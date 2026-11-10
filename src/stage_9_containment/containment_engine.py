"""
src/stage_9_containment/containment_engine.py
================================================
Stage 9 — Freeze-Graph Min-Cut Containment Engine (Orchestrator)

Main entry point for Stage 9. Receives the ``should_contain`` signal
from Stage 7's ``TrustEvolution.evolve()`` result and executes the
full containment sequence:

    1. Snapshot the DBRG (or accept one as argument).
    2. Compute the Edmonds-Karp minimum cut via ``GraphCutEngine``.
    3. Freeze (suspend) the malicious process via ``ProcessFreezer``.
    4. Record the containment event in an append-only log.

Data Flow:
    Stage 7 (TrustEvolution.evolve() → should_contain=True)
        → ContainmentEngine.contain(pid, dbrg_graph, trust_state)
            → { ContainmentRecord }
                → feeds Stage 10 (Journaling & Rollback)

False-Positive Recovery:
    Stage 10 or an analyst may call ``release()`` to resume the process
    and reset its containment state. The released PID's trust can then
    be restored by Stage 7's ``confirm_false_positive()``.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import networkx as nx

from src.stage_9_containment.graph_cut import GraphCutEngine, MinCutResult
from src.stage_9_containment.process_freezer import (
    ContainmentState,
    FreezeResult,
    ProcessFreezer,
)

logger = logging.getLogger(__name__)


@dataclass
class ContainmentRecord:
    """
    Full record of a single containment or release event.

    Attributes
    ----------
    pid : int
        Process ID that was contained or released.
    action : str
        ``"CONTAIN"`` or ``"RELEASE"``.
    timestamp : float
        Wall-clock time when the action completed.
    cut_value : float
        Total cost of the min-cut (0.0 for release events).
    cut_edges : list
        List of (source, target) tuples for the severed edges.
    isolated_files : list
        List of file-node IDs isolated from the process.
    freeze_result : Optional[FreezeResult]
        Result from the ProcessFreezer operation.
    trust_at_containment : Optional[float]
        Trust score at the moment of containment (from Stage 7).
    risk_tier_at_containment : Optional[str]
        Risk tier at the moment of containment.
    latency_ms : float
        Total wall-clock time for the entire containment sequence
        (graph cut + freeze), in milliseconds.
    success : bool
        Whether the overall operation succeeded.
    """

    pid: int
    action: str
    timestamp: float
    cut_value: float = 0.0
    cut_edges: list = field(default_factory=list)
    isolated_files: list = field(default_factory=list)
    freeze_result: Optional[FreezeResult] = None
    trust_at_containment: Optional[float] = None
    risk_tier_at_containment: Optional[str] = None
    latency_ms: float = 0.0
    success: bool = True


class ContainmentEngine:
    """
    Stage 9 orchestrator: computes optimal graph cuts, freezes
    malicious processes, and maintains the containment audit log.

    Parameters
    ----------
    dry_run : bool
        Passed through to ``ProcessFreezer``. If True (default), process
        suspension is simulated. Set to False for real enforcement.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.graph_cutter = GraphCutEngine()
        self.freezer = ProcessFreezer(dry_run=dry_run)
        self._containment_log: List[ContainmentRecord] = []
        self._lock = threading.Lock()

        # Counters
        self.total_containments: int = 0
        self.total_releases: int = 0

    def contain(
        self,
        pid: int,
        dbrg_graph: nx.DiGraph,
        trust_state: Optional[Dict[str, Any]] = None,
    ) -> ContainmentRecord:
        """
        Execute the full containment sequence for a malicious process.

        Steps
        -----
        1. Resolve the process node ID in the DBRG (``"pid:<PID>"``).
        2. Compute the minimum s-t cut to isolate it from file targets.
        3. Freeze (suspend) the process.
        4. Record the event and return the ``ContainmentRecord``.

        Parameters
        ----------
        pid : int
            Process ID to contain.
        dbrg_graph : nx.DiGraph
            Snapshot of the Stage 3 DBRG graph.
        trust_state : dict, optional
            Stage 7 trust state dict (must contain ``"trust"`` and
            ``"risk_tier"`` keys if provided).

        Returns
        -------
        ContainmentRecord
            Full record of the containment action.
        """
        t_start = time.perf_counter()

        source_node = f"pid:{pid}"
        trust_score = None
        risk_tier = None
        if trust_state:
            trust_score = trust_state.get("trust")
            risk_tier = trust_state.get("risk_tier")

        # ── 1. Check if already frozen ───────────────────────────────
        if self.freezer.get_state(pid) == ContainmentState.FROZEN:
            latency = (time.perf_counter() - t_start) * 1000.0
            logger.warning(
                "[Containment] PID=%d already FROZEN; skipping re-contain.",
                pid,
            )
            record = ContainmentRecord(
                pid=pid,
                action="CONTAIN",
                timestamp=time.time(),
                trust_at_containment=trust_score,
                risk_tier_at_containment=risk_tier,
                latency_ms=latency,
                success=False,
            )
            with self._lock:
                self._containment_log.append(record)
            return record

        # ── 2. Compute min-cut ───────────────────────────────────────
        cut_result: MinCutResult = self.graph_cutter.compute_min_cut(
            graph=dbrg_graph,
            source_pid=source_node,
        )

        # ── 3. Freeze the process ────────────────────────────────────
        reason = (
            f"CRITICAL_RISK trust={trust_score:.1f}"
            if trust_score is not None
            else "containment_triggered"
        )
        freeze_result = self.freezer.freeze(pid=pid, reason=reason)

        # ── 4. Build and store the record ────────────────────────────
        latency = (time.perf_counter() - t_start) * 1000.0

        record = ContainmentRecord(
            pid=pid,
            action="CONTAIN",
            timestamp=time.time(),
            cut_value=cut_result.cut_value,
            cut_edges=list(cut_result.cut_edges),
            isolated_files=list(cut_result.isolated_files),
            freeze_result=freeze_result,
            trust_at_containment=trust_score,
            risk_tier_at_containment=risk_tier,
            latency_ms=latency,
            success=freeze_result.success,
        )

        with self._lock:
            self._containment_log.append(record)
            self.total_containments += 1

        logger.info(
            "[Containment] CONTAINED PID=%d  cut_value=%.4f  "
            "cut_edges=%d  isolated_files=%d  latency=%.3fms  "
            "trust=%.2f  tier=%s",
            pid,
            cut_result.cut_value,
            len(cut_result.cut_edges),
            len(cut_result.isolated_files),
            latency,
            trust_score if trust_score is not None else -1,
            risk_tier or "UNKNOWN",
        )

        return record

    def release(
        self, pid: int, reason: str = "false_positive"
    ) -> ContainmentRecord:
        """
        Release a previously contained process (false-positive recovery).

        Parameters
        ----------
        pid : int
            Process ID to release.
        reason : str
            Reason for release (e.g. ``"false_positive_confirmed"``).

        Returns
        -------
        ContainmentRecord
            Record of the release action.
        """
        t_start = time.perf_counter()

        freeze_result = self.freezer.release(pid=pid, reason=reason)
        latency = (time.perf_counter() - t_start) * 1000.0

        record = ContainmentRecord(
            pid=pid,
            action="RELEASE",
            timestamp=time.time(),
            freeze_result=freeze_result,
            latency_ms=latency,
            success=freeze_result.success,
        )

        with self._lock:
            self._containment_log.append(record)
            if freeze_result.success:
                self.total_releases += 1

        logger.info(
            "[Containment] RELEASED PID=%d  success=%s  reason=%s  "
            "latency=%.3fms",
            pid,
            freeze_result.success,
            reason,
            latency,
        )

        return record

    def get_containment_history(
        self, pid: Optional[int] = None
    ) -> List[ContainmentRecord]:
        """
        Return the containment audit log.

        Parameters
        ----------
        pid : int, optional
            If provided, filter records to this PID only.

        Returns
        -------
        list of ContainmentRecord
        """
        with self._lock:
            if pid is not None:
                return [r for r in self._containment_log if r.pid == pid]
            return list(self._containment_log)

    def get_stats(self) -> Dict[str, Any]:
        """
        Return aggregate containment statistics.

        Returns
        -------
        dict
            Counts and metadata about containment activity.
        """
        with self._lock:
            frozen_pids = self.freezer.get_frozen_pids()
            return {
                "total_containments": self.total_containments,
                "total_releases": self.total_releases,
                "currently_frozen": len(frozen_pids),
                "frozen_pids": frozen_pids,
                "total_log_entries": len(self._containment_log),
                "total_cuts_computed": self.graph_cutter.total_cuts_computed,
                "dry_run": self.freezer.dry_run,
            }

    def __repr__(self) -> str:
        return (
            f"ContainmentEngine("
            f"containments={self.total_containments}, "
            f"releases={self.total_releases}, "
            f"frozen={len(self.freezer.get_frozen_pids())}, "
            f"dry_run={self.freezer.dry_run})"
        )

