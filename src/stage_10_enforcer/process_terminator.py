"""
src/stage_10_enforcer/process_terminator.py
=============================================
Stage 10 — Process Terminator (SIGKILL)

Issues SIGKILL (POSIX) or psutil.Process.kill() (Windows) to confirmed
malicious processes.  Defaults to dry_run=True — no real signal is sent
unless explicitly overridden.

Safety guards:
  - Refuses pid <= 1 (init / System Idle).
  - Refuses to kill the current process or its parent.
  - PID-reuse detection via create_time comparison when register() was
    called first.

Data Flow:
    Enforcer.resolve(pid, MALICIOUS)
        → ProcessTerminator.terminate(pid, reason)
            → TerminateResult
"""

import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


@dataclass
class TerminateResult:
    """Result of a process termination attempt."""

    pid: int
    success: bool
    dry_run: bool
    reason: str
    error: str = ""
    latency_ms: float = 0.0


class ProcessTerminator:
    """
    Sends SIGKILL to confirmed-malicious processes.

    Parameters
    ----------
    dry_run : bool
        If True (default), the kill is simulated — no real signal.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        # pid -> create_time (for PID-reuse detection)
        self._registered: Dict[int, Optional[float]] = {}
        self.total_kills: int = 0
        self.total_refused: int = 0

    def register(self, pid: int) -> None:
        """
        Record the process's create_time for later PID-reuse detection.

        Should be called when a PID enters enforcement, before any
        resolution attempt.
        """
        ctime: Optional[float] = None
        if psutil is not None:
            try:
                ctime = psutil.Process(pid).create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._registered[pid] = ctime

    def terminate(self, pid: int, reason: str = "") -> TerminateResult:
        """
        Terminate *pid* with SIGKILL (POSIX) or psutil.Process.kill()
        (Windows).

        Returns a ``TerminateResult`` — never raises.
        """
        t_start = time.perf_counter()

        # ── Safety guards ──────────────────────────────────────────
        if pid <= 1:
            self.total_refused += 1
            return TerminateResult(
                pid=pid, success=False, dry_run=self.dry_run,
                reason=reason, error=f"Refused: pid={pid} is a protected system process",
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
            )

        if pid == os.getpid():
            self.total_refused += 1
            return TerminateResult(
                pid=pid, success=False, dry_run=self.dry_run,
                reason=reason, error="Refused: cannot kill own process",
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
            )

        if pid == os.getppid():
            self.total_refused += 1
            return TerminateResult(
                pid=pid, success=False, dry_run=self.dry_run,
                reason=reason, error="Refused: cannot kill parent process",
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
            )

        # PID-reuse detection
        if pid in self._registered and self._registered[pid] is not None:
            if psutil is not None:
                try:
                    current_ctime = psutil.Process(pid).create_time()
                    if abs(current_ctime - self._registered[pid]) > 0.1:
                        self.total_refused += 1
                        return TerminateResult(
                            pid=pid, success=False, dry_run=self.dry_run,
                            reason=reason,
                            error="Refused: PID reuse detected (create_time mismatch)",
                            latency_ms=(time.perf_counter() - t_start) * 1000.0,
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process already gone — not an error, just report
                    latency = (time.perf_counter() - t_start) * 1000.0
                    return TerminateResult(
                        pid=pid, success=False, dry_run=self.dry_run,
                        reason=reason, error="already terminated",
                        latency_ms=latency,
                    )

        # ── Dry run ────────────────────────────────────────────────
        if self.dry_run:
            self.total_kills += 1
            latency = (time.perf_counter() - t_start) * 1000.0
            logger.info(
                "[Terminator] DRY RUN SIGKILL pid=%d reason=%s (%.3fms)",
                pid, reason, latency,
            )
            return TerminateResult(
                pid=pid, success=True, dry_run=True,
                reason=reason, latency_ms=latency,
            )

        # ── Real kill ──────────────────────────────────────────────
        try:
            if sys.platform == "win32":
                if psutil is not None:
                    psutil.Process(pid).kill()
                else:
                    os.kill(pid, signal.SIGTERM)
            else:
                os.kill(pid, signal.SIGKILL)

            self.total_kills += 1
            latency = (time.perf_counter() - t_start) * 1000.0
            logger.info(
                "[Terminator] SIGKILL pid=%d reason=%s (%.3fms)",
                pid, reason, latency,
            )
            return TerminateResult(
                pid=pid, success=True, dry_run=False,
                reason=reason, latency_ms=latency,
            )
        except ProcessLookupError:
            latency = (time.perf_counter() - t_start) * 1000.0
            return TerminateResult(
                pid=pid, success=False, dry_run=False,
                reason=reason, error="already terminated",
                latency_ms=latency,
            )
        except PermissionError as exc:
            latency = (time.perf_counter() - t_start) * 1000.0
            return TerminateResult(
                pid=pid, success=False, dry_run=False,
                reason=reason, error=f"PermissionError: {exc}",
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.perf_counter() - t_start) * 1000.0
            if psutil is not None and isinstance(exc, psutil.NoSuchProcess):
                return TerminateResult(
                    pid=pid, success=False, dry_run=False,
                    reason=reason, error="already terminated",
                    latency_ms=latency,
                )
            return TerminateResult(
                pid=pid, success=False, dry_run=False,
                reason=reason, error=str(exc),
                latency_ms=latency,
            )

    def __repr__(self) -> str:
        return (
            f"ProcessTerminator(kills={self.total_kills}, "
            f"refused={self.total_refused}, dry_run={self.dry_run})"
        )

