"""
src/stage_8_harness/attack_engine.py
=======================================
Simulated ransomware attack engine for Stage 8.

Executes a multi-phase attack against the sandboxed victim files:
  Phase 1 — Enumerate target files from the sandbox
  Phase 2 — Overwrite each file with high-entropy random bytes
  Phase 3 — Rename files with the profile's ransomware extension
  Phase 4 — (Optional) Drop ransom notes in each affected directory

Safety:
  Every write, rename, and note-drop operation calls
  SandboxManager.verify_path_safety() BEFORE execution.
  Violations raise SandboxEscapeError and abort the attack.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from src.stage_8_harness.sandbox_manager import SandboxManager, SandboxEscapeError
from src.stage_8_harness.attack_profiles import AttackProfile
from src.stage_8_harness.benchmark_logger import BenchmarkLogger

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Summary of a completed attack run."""
    profile_name: str
    total_files: int
    encrypted_count: int
    renamed_count: int
    ransom_notes_dropped: int
    elapsed_ms: float
    files_encrypted: List[str] = field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None


class AttackEngine:
    """
    Executes a simulated ransomware attack inside a sandbox.

    Parameters
    ----------
    sandbox : SandboxManager
        The sandbox environment to attack.
    profile : AttackProfile
        Attack speed and behavior parameters.
    logger_ : BenchmarkLogger, optional
        Benchmark logger for recording attack events.
    abort_on_detection : bool
        If True, stop the attack when the benchmark logger records a detection.
    on_file_encrypted : callable, optional
        Callback invoked after each file is encrypted and renamed:
        ``on_file_encrypted(original_path, renamed_path, data, index)``.
        Allows the runner to feed events into the pipeline without
        duplicating the attack loop.
    """

    def __init__(
        self,
        sandbox: SandboxManager,
        profile: AttackProfile,
        logger_: Optional[BenchmarkLogger] = None,
        abort_on_detection: bool = False,
        on_file_encrypted: Optional[Callable] = None,
    ) -> None:
        self.sandbox = sandbox
        self.profile = profile
        self.bench = logger_ or BenchmarkLogger(profile.name)
        self.abort_on_detection = abort_on_detection
        self.on_file_encrypted = on_file_encrypted
        self._aborted = False
        self._abort_reason: Optional[str] = None

    def execute(self) -> AttackResult:
        """
        Run the full attack sequence.

        Returns
        -------
        AttackResult
            Summary of what was encrypted, renamed, and how long it took.
        """
        if not self.sandbox.is_setup:
            raise RuntimeError(
                "Sandbox is not set up. Call sandbox.setup() before executing an attack."
            )

        target_files = self.sandbox.get_target_files()
        total_files = len(target_files)

        logger.info(
            "Starting %s attack on %d files (interval=%dms, batch=%d)",
            self.profile.name, total_files,
            self.profile.interval_ms, self.profile.batch_size,
        )

        encrypted_files: List[str] = []
        renamed_count = 0
        notes_dropped = 0
        affected_dirs: set = set()

        t_start = time.perf_counter()
        # Preserve any pre-set abort (e.g. from signal_abort() called before execute)
        if not self._aborted:
            self._aborted = False
            self._abort_reason = None

        # ── Phase 1+2+3: Encrypt and rename in batches ───────────────
        batch: List[Path] = []
        for i, file_path in enumerate(target_files):
            batch.append(file_path)

            if len(batch) >= self.profile.batch_size or i == total_files - 1:
                for fp in batch:
                    if self._check_abort():
                        break

                    # SAFETY CHECK before every write
                    try:
                        safe_path = self.sandbox.verify_path_safety(fp)
                    except SandboxEscapeError as e:
                        logger.error("Safety violation during encrypt: %s", e)
                        self._aborted = True
                        self._abort_reason = str(e)
                        break

                    # Encrypt: overwrite with high-entropy random bytes
                    try:
                        original_size = safe_path.stat().st_size if safe_path.exists() else 4096
                        write_size = max(original_size, 1024)  # minimum 1KB
                        encrypted_data = os.urandom(write_size)
                        safe_path.write_bytes(encrypted_data)
                        self.bench.record_attack_event(str(safe_path))
                        affected_dirs.add(safe_path.parent)
                    except OSError as e:
                        logger.warning("Failed to encrypt %s: %s", safe_path, e)
                        continue

                    # Rename with ransomware extension
                    new_name = safe_path.with_suffix(
                        safe_path.suffix + self.profile.rename_ext
                    )
                    safe_new = new_name  # default for callback
                    try:
                        safe_new = self.sandbox.verify_path_safety(new_name)
                        safe_path.rename(safe_new)
                        renamed_count += 1
                        encrypted_files.append(str(safe_new))
                    except SandboxEscapeError as e:
                        logger.error("Safety violation during rename: %s", e)
                        self._aborted = True
                        self._abort_reason = str(e)
                        encrypted_files.append(str(safe_path))
                        break
                    except OSError as e:
                        logger.warning("Failed to rename %s: %s", safe_path, e)
                        encrypted_files.append(str(safe_path))

                    # Invoke per-file callback (e.g., pipeline evaluation)
                    if self.on_file_encrypted is not None:
                        try:
                            file_idx = len(encrypted_files) - 1
                            self.on_file_encrypted(safe_path, safe_new, encrypted_data, file_idx)
                        except Exception as e:
                            logger.debug("on_file_encrypted callback error: %s", e)

                if self._aborted:
                    break

                batch.clear()

                # Inter-batch delay
                if self.profile.interval_ms > 0 and i < total_files - 1:
                    time.sleep(self.profile.interval_ms / 1000.0)

        # ── Phase 4: Drop ransom notes ───────────────────────────────
        if self.profile.drop_ransom_note and not self._aborted:
            for dir_path in affected_dirs:
                note_path = dir_path / self.profile.note_filename
                try:
                    safe_note = self.sandbox.verify_path_safety(note_path)
                    safe_note.write_text(self.profile.note_content, encoding="utf-8")
                    notes_dropped += 1
                except SandboxEscapeError as e:
                    logger.error("Safety violation during ransom note: %s", e)
                    break
                except OSError as e:
                    logger.warning("Failed to write ransom note at %s: %s", note_path, e)

        t_end = time.perf_counter()
        elapsed_ms = (t_end - t_start) * 1000.0

        result = AttackResult(
            profile_name=self.profile.name,
            total_files=total_files,
            encrypted_count=len(encrypted_files),
            renamed_count=renamed_count,
            ransom_notes_dropped=notes_dropped,
            elapsed_ms=elapsed_ms,
            files_encrypted=encrypted_files,
            aborted=self._aborted,
            abort_reason=self._abort_reason,
        )

        logger.info(
            "Attack complete: %d/%d encrypted, %d renamed, %d notes in %.1fms%s",
            result.encrypted_count, total_files, renamed_count,
            notes_dropped, elapsed_ms,
            " (ABORTED)" if self._aborted else "",
        )

        return result

    def _check_abort(self) -> bool:
        """Check if the attack should be aborted due to detection."""
        if self._aborted:
            return True
        if self.abort_on_detection and self.bench.first_detection_time is not None:
            self._aborted = True
            self._abort_reason = "Detection triggered — aborting attack"
            logger.info("Attack aborted: pipeline detected the attack")
            return True
        return False

    def signal_abort(self, reason: str = "External abort signal") -> None:
        """Allow external code (e.g., the pipeline monitor) to stop the attack."""
        self._aborted = True
        self._abort_reason = reason

    def __repr__(self) -> str:
        return (
            f"AttackEngine(profile='{self.profile.name}', "
            f"sandbox='{self.sandbox.sandbox_dir}')"
        )
