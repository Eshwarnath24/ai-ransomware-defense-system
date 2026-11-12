"""
src/stage_10_enforcer/enforcer.py
====================================
Stage 10 — Enforcer Orchestrator

Coordinates ACL revocation, write-ahead journaling, process termination,
and selective rollback for the Stage 10 pipeline.  Exposes two resolution
branches for Stage 11's SOC dashboard buttons:

    resolve(pid, MALICIOUS)       → SIGKILL → rollback → keep ACLs
    resolve(pid, FALSE_POSITIVE)  → restore ACLs → trust 100 → SIGCONT

Data Flow:
    Stage 7   prewarm_journal=True  →  arm(pid)
    Harness   before_write hooks    →  JournalVault.snapshot()
    Stage 9   ContainmentRecord     →  enforce(record)
    Stage 11  dashboard buttons     →  resolve(pid, verdict)

Safety:
    - dry_run=True by default: no real kill, no real ACL changes.
    - rollback_dry_run: separate flag for file writes (may be False
      in harness sandbox while dry_run=True for kill/ACL).
    - allowed_roots: restrict writes/deletes to sandbox boundaries.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from src.stage_10_enforcer.acl_manager import ACLManager, ACLRecord
from src.stage_10_enforcer.journal_rollback import (
    JournalEntry,
    JournalVault,
    RollbackEngine,
    RollbackReport,
)
from src.stage_10_enforcer.process_terminator import ProcessTerminator, TerminateResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#   Enums
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    """Analyst resolution verdict for a contained process."""
    MALICIOUS = "MALICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class EnforcementState(str, Enum):
    """State machine for per-PID enforcement tracking."""
    PENDING_RESOLUTION = "PENDING_RESOLUTION"
    RESOLVED_MALICIOUS = "RESOLVED_MALICIOUS"
    RESOLVED_FALSE_POSITIVE = "RESOLVED_FALSE_POSITIVE"


# ---------------------------------------------------------------------------
#   Records
# ---------------------------------------------------------------------------

@dataclass
class EnforcementRecord:
    """Tracks enforcement state for a single PID."""

    pid: int
    state: EnforcementState
    acl_paths: List[str] = field(default_factory=list)
    acl_records: List[ACLRecord] = field(default_factory=list)
    containment_record: Optional[Any] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class ResolutionResult:
    """Result of resolving a pending enforcement."""

    pid: int
    verdict: Optional[Verdict] = None
    success: bool = False
    steps: List[str] = field(default_factory=list)
    terminate_result: Optional[TerminateResult] = None
    rollback_report: Optional[RollbackReport] = None
    acl_restored: int = 0
    trust_reset: Optional[dict] = None
    release_record: Optional[Any] = None
    error: str = ""
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
#   Config
# ---------------------------------------------------------------------------

@dataclass
class Stage10Config:
    """Configuration for Stage 10 with sensible defaults."""

    vault_dir: str = ""
    block_size: int = 65536
    max_vault_bytes: int = 536870912      # 512 MB
    max_file_bytes: int = 268435456       # 256 MB
    always_on_journal: bool = True
    dry_run: bool = True

    def __post_init__(self):
        if not self.vault_dir:
            import tempfile
            self.vault_dir = os.path.join(tempfile.gettempdir(), ".journal_vault")

    @classmethod
    def from_yaml(cls, path: str) -> "Stage10Config":
        """
        Load config from a YAML file's ``stage_10`` key.
        Falls back to defaults with a warning if PyYAML is unavailable
        or the key is missing.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "[Stage10Config] PyYAML not installed; using defaults"
            )
            return cls()

        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            s10 = data.get("stage_10", {})
            if not s10:
                logger.info("[Stage10Config] No stage_10 key in %s; using defaults", path)
                return cls()
            return cls(
                vault_dir=s10.get("vault_dir", ""),
                block_size=s10.get("block_size", 65536),
                max_vault_bytes=s10.get("max_vault_bytes", 536870912),
                max_file_bytes=s10.get("max_file_bytes", 268435456),
                always_on_journal=s10.get("always_on_journal", True),
                dry_run=s10.get("dry_run", True),
            )
        except Exception as exc:
            logger.warning("[Stage10Config] Failed to load %s: %s; using defaults", path, exc)
            return cls()


# ---------------------------------------------------------------------------
#   Enforcer
# ---------------------------------------------------------------------------

class Enforcer:
    """
    Stage 10 orchestrator: journaling, ACL enforcement, and resolution.

    Parameters
    ----------
    containment_engine : ContainmentEngine
        Stage 9 engine (for ``release()`` on false positives).
    trust_evolution : TrustEvolution, optional
        Stage 7 engine (for ``confirm_false_positive()``).
    vault : JournalVault, optional
        Pre-constructed vault; one is created if not provided.
    acl : ACLManager, optional
        Pre-constructed ACL manager; one is created if not provided.
    terminator : ProcessTerminator, optional
        Pre-constructed terminator; one is created if not provided.
    dry_run : bool
        Governs process kill and ACL operations (default True).
    always_on : bool
        If True, ``before_write`` snapshots regardless of arming.
    allowed_roots : sequence of str, optional
        Restrict rollback writes and deletes to these directories.
    rollback_dry_run : bool, optional
        Separate dry-run for file rollback writes. Defaults to *dry_run*
        if not provided. Setting False while dry_run=True allows real
        file restores in a sandbox while keeping kill/ACL simulated.
    """

    def __init__(
        self,
        containment_engine: Any,
        trust_evolution: Any = None,
        vault: Optional[JournalVault] = None,
        acl: Optional[ACLManager] = None,
        terminator: Optional[ProcessTerminator] = None,
        dry_run: bool = True,
        always_on: bool = False,
        allowed_roots: Optional[Sequence[str]] = None,
        rollback_dry_run: Optional[bool] = None,
    ) -> None:
        self.containment_engine = containment_engine
        self.trust_evolution = trust_evolution
        self.dry_run = dry_run
        self.always_on = always_on
        self.allowed_roots = allowed_roots

        self._rollback_dry_run = rollback_dry_run if rollback_dry_run is not None else dry_run

        self.vault = vault or JournalVault()
        self.acl = acl or ACLManager(dry_run=dry_run)
        self.terminator = terminator or ProcessTerminator(dry_run=dry_run)

        # PID tracking
        self._armed_pids: set = set()
        self._records: Dict[int, EnforcementRecord] = {}
        self._lock = threading.Lock()

        # Counters
        self.unjournaled_writes: int = 0
        self.total_enforcements: int = 0
        self.total_resolutions: int = 0

    # ------------------------------------------------------------------
    #   Journaling API
    # ------------------------------------------------------------------

    def arm(self, pid: int) -> None:
        """Mark a PID for write-ahead journaling. Idempotent."""
        with self._lock:
            self._armed_pids.add(pid)
        logger.info("[Enforcer] Armed PID=%d for journaling", pid)

    def disarm(self, pid: int) -> None:
        """Remove a PID from the armed set."""
        with self._lock:
            self._armed_pids.discard(pid)

    def on_trust_update(self, stage7_result: dict) -> None:
        """
        React to a Stage 7 trust update. Arms the PID when
        ``prewarm_journal`` is True (VERIFY or CRITICAL_RISK).
        """
        if stage7_result.get("prewarm_journal"):
            pid = stage7_result.get("pid", -1)
            if pid > 0:
                self.arm(pid)

    def before_write(self, path: str, pid: int) -> Optional[JournalEntry]:
        """
        Snapshot *path* before it is overwritten by *pid*.

        Returns a ``JournalEntry`` if captured, None otherwise.
        Snapshots only if the PID is armed or ``always_on=True``.
        """
        with self._lock:
            is_armed = pid in self._armed_pids

        if not is_armed and not self.always_on:
            self.unjournaled_writes += 1
            return None

        return self.vault.snapshot(path, pid)

    def note_rename(self, pid: int, old: str, new: str) -> None:
        """Forward a rename event to the vault."""
        self.vault.note_rename(pid, old, new)

    def note_created(self, pid: int, path: str) -> None:
        """Forward a file-created event to the vault."""
        self.vault.note_created(pid, path)

    # ------------------------------------------------------------------
    #   enforce
    # ------------------------------------------------------------------

    def enforce(self, record: Any) -> EnforcementRecord:
        """
        Apply ACL revocations on the file paths from a Stage 9
        ``ContainmentRecord``.

        No-op (returns a blank/existing record) if:
          - ``record.action != "CONTAIN"``
          - ``record.freeze_result`` is missing or unsuccessful
          - The PID is already under enforcement (idempotent)
        """
        pid = record.pid

        # Idempotent check
        with self._lock:
            if pid in self._records:
                logger.info("[Enforcer] PID=%d already enforced", pid)
                return self._records[pid]

        # Guard: only enforce successful containment
        action = getattr(record, "action", "")
        if action != "CONTAIN":
            logger.debug("[Enforcer] Skipping non-CONTAIN record for PID=%d", pid)
            return EnforcementRecord(
                pid=pid,
                state=EnforcementState.PENDING_RESOLUTION,
            )

        freeze_result = getattr(record, "freeze_result", None)
        if freeze_result is None or not getattr(freeze_result, "success", False):
            logger.debug("[Enforcer] Skipping enforcement: freeze unsuccessful for PID=%d", pid)
            return EnforcementRecord(
                pid=pid,
                state=EnforcementState.PENDING_RESOLUTION,
            )

        # Derive file paths from cut_edges
        file_paths = self._extract_file_paths(record)

        # ACL revoke
        acl_records = self.acl.revoke(pid, file_paths)

        # Register with terminator
        self.terminator.register(pid)

        enforcement = EnforcementRecord(
            pid=pid,
            state=EnforcementState.PENDING_RESOLUTION,
            acl_paths=file_paths,
            acl_records=acl_records,
            containment_record=record,
            created_at=time.time(),
        )

        with self._lock:
            self._records[pid] = enforcement
            self.total_enforcements += 1

        logger.info(
            "[Enforcer] ENFORCED PID=%d: %d file paths, %d ACLs revoked",
            pid, len(file_paths), len(acl_records),
        )
        return enforcement

    def _extract_file_paths(self, record: Any) -> List[str]:
        """Extract and normalize file paths from a ContainmentRecord."""
        paths: set = set()

        # Try cut_edges first
        cut_edges = getattr(record, "cut_edges", []) or []
        for edge in cut_edges:
            if len(edge) >= 2:
                target = edge[1]  # (source, target)
                if isinstance(target, str) and target.startswith("file:"):
                    raw_path = target[5:]  # strip "file:" prefix
                    try:
                        paths.add(os.path.realpath(raw_path))
                    except (OSError, ValueError):
                        paths.add(raw_path)

        # Fall back to isolated_files if cut_edges yielded nothing
        if not paths:
            isolated = getattr(record, "isolated_files", []) or []
            for node in isolated:
                if isinstance(node, str):
                    raw = node[5:] if node.startswith("file:") else node
                    try:
                        paths.add(os.path.realpath(raw))
                    except (OSError, ValueError):
                        paths.add(raw)

        return sorted(paths)

    # ------------------------------------------------------------------
    #   resolve
    # ------------------------------------------------------------------

    def resolve(self, pid: int, verdict: Verdict) -> ResolutionResult:
        """
        Resolve a pending enforcement for *pid*.

        MALICIOUS:
            1. SIGKILL the process.
            2. Rollback files from the vault.
            3. Keep ACL revocations active (quarantine).

        FALSE_POSITIVE:
            1. Restore ACL permissions.
            2. Reset trust to 100 (Stage 7).
            3. Release the process (SIGCONT via Stage 9).
            4. Purge the vault and disarm.
        """
        t_start = time.perf_counter()

        # Validate verdict type
        if not isinstance(verdict, Verdict):
            try:
                verdict = Verdict(verdict)
            except (ValueError, KeyError):
                return ResolutionResult(
                    pid=pid, success=False,
                    error=f"Unknown verdict: {verdict}",
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                )

        # Check enforcement exists
        with self._lock:
            record = self._records.get(pid)

        if record is None:
            return ResolutionResult(
                pid=pid, verdict=verdict, success=False,
                error="No enforcement record for this PID (resolve before enforce?)",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )

        # Check not already resolved
        if record.state != EnforcementState.PENDING_RESOLUTION:
            return ResolutionResult(
                pid=pid, verdict=verdict, success=False,
                error=f"Already resolved as {record.state.value}",
                duration_ms=(time.perf_counter() - t_start) * 1000.0,
            )

        if verdict == Verdict.MALICIOUS:
            result = self._resolve_malicious(pid, record)
        else:
            result = self._resolve_false_positive(pid, record)

        result.duration_ms = (time.perf_counter() - t_start) * 1000.0
        result.verdict = verdict

        with self._lock:
            self.total_resolutions += 1

        return result

    def _resolve_malicious(
        self, pid: int, record: EnforcementRecord,
    ) -> ResolutionResult:
        """MALICIOUS: kill → rollback → keep ACLs."""
        result = ResolutionResult(pid=pid)
        result.steps = []

        # 1. Terminate
        term_result = self.terminator.terminate(pid, reason="MALICIOUS_confirmed")
        result.terminate_result = term_result
        result.steps.append(
            f"terminate: success={term_result.success}"
            + (f" error={term_result.error}" if term_result.error else "")
        )
        # A failed kill must NOT skip the rollback

        # 2. Rollback
        rollback_engine = RollbackEngine(
            vault=self.vault,
            acl=self.acl,
            dry_run=self._rollback_dry_run,
            allowed_roots=self.allowed_roots,
        )
        rollback_report = rollback_engine.rollback(pid)
        result.rollback_report = rollback_report
        result.steps.append(
            f"rollback: {rollback_report.restored}/{rollback_report.total} restored, "
            f"zero_loss={rollback_report.zero_loss}"
        )

        # 3. Keep ACL revocations active (per architecture doc)
        result.steps.append("acl: revocations kept active (quarantine)")

        # Update state
        with self._lock:
            record.state = EnforcementState.RESOLVED_MALICIOUS

        result.success = True
        logger.info("[Enforcer] RESOLVED PID=%d as MALICIOUS", pid)
        return result

    def _resolve_false_positive(
        self, pid: int, record: EnforcementRecord,
    ) -> ResolutionResult:
        """FALSE_POSITIVE: restore ACLs → trust 100 → release → purge."""
        result = ResolutionResult(pid=pid)
        result.steps = []

        # 1. Restore ACL permissions
        restored_records = self.acl.restore_all(pid)
        result.acl_restored = len(restored_records)
        result.steps.append(f"acl_restore: {len(restored_records)} paths restored")

        # 2. Reset trust to 100
        if self.trust_evolution is not None:
            try:
                trust_result = self.trust_evolution.confirm_false_positive(pid)
                result.trust_reset = trust_result
                result.steps.append(
                    f"trust_reset: trust={trust_result.get('trust', '?')}, "
                    f"tier={trust_result.get('risk_tier', '?')}"
                )
            except Exception as exc:
                result.steps.append(f"trust_reset: failed ({exc})")
        else:
            result.steps.append("trust_reset: skipped (no trust_evolution)")

        # 3. Release (SIGCONT) via Stage 9
        try:
            release_record = self.containment_engine.release(
                pid, reason="false_positive_confirmed"
            )
            result.release_record = release_record
            result.steps.append(
                f"release: success={release_record.success}"
            )
        except Exception as exc:
            result.steps.append(f"release: failed ({exc})")

        # 4. Purge vault and disarm (no rollback for FP)
        self.vault.purge(pid)
        self.disarm(pid)
        result.steps.append("vault: purged, pid disarmed")

        # Update state
        with self._lock:
            record.state = EnforcementState.RESOLVED_FALSE_POSITIVE

        result.success = True
        logger.info("[Enforcer] RESOLVED PID=%d as FALSE_POSITIVE", pid)
        return result

    # ------------------------------------------------------------------
    #   Queries
    # ------------------------------------------------------------------

    def get_pending(self) -> List[int]:
        """Return PIDs that are enforced but not yet resolved."""
        with self._lock:
            return [
                pid for pid, r in self._records.items()
                if r.state == EnforcementState.PENDING_RESOLUTION
            ]

    def get_history(self, pid: Optional[int] = None) -> list:
        """Return enforcement records, optionally for a single PID."""
        with self._lock:
            if pid is not None:
                r = self._records.get(pid)
                return [r] if r else []
            return list(self._records.values())

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics."""
        with self._lock:
            pending = sum(
                1 for r in self._records.values()
                if r.state == EnforcementState.PENDING_RESOLUTION
            )
            malicious = sum(
                1 for r in self._records.values()
                if r.state == EnforcementState.RESOLVED_MALICIOUS
            )
            fp = sum(
                1 for r in self._records.values()
                if r.state == EnforcementState.RESOLVED_FALSE_POSITIVE
            )
            armed = len(self._armed_pids)

        return {
            "total_enforcements": self.total_enforcements,
            "total_resolutions": self.total_resolutions,
            "pending": pending,
            "resolved_malicious": malicious,
            "resolved_false_positive": fp,
            "armed_pids": armed,
            "unjournaled_writes": self.unjournaled_writes,
            "dry_run": self.dry_run,
            "rollback_dry_run": self._rollback_dry_run,
            "always_on": self.always_on,
            "vault": self.vault.stats(),
            "acl": self.acl.get_stats(),
        }

    def __repr__(self) -> str:
        return (
            f"Enforcer(enforcements={self.total_enforcements}, "
            f"resolutions={self.total_resolutions}, "
            f"dry_run={self.dry_run}, always_on={self.always_on})"
        )

