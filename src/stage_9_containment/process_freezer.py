"""
src/stage_9_containment/process_freezer.py
=============================================
Stage 9 — Process Suspension Manager

Simulates kernel-level process suspension via ``NtSuspendProcess``
(Windows) or ``SIGSTOP`` (Linux).  By default operates in **dry-run
mode** for safety — all state transitions are tracked and latency is
measured, but no actual OS calls are made.

Containment State Machine (per PID):
    ACTIVE ──[freeze()]──► FROZEN ──[release()]──► RELEASED
                              │                        │
                              └── (already frozen) ────┘
                                   double-freeze → error

Safety:
    Real enforcement (``dry_run=False``) is gated behind an explicit
    opt-in.  Even in real mode, only ``SIGSTOP``/``SIGCONT`` are used
    (never ``SIGKILL``), preserving the process for Stage 10 rollback
    analysis.
"""

import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ContainmentAction(str, Enum):
    """Actions that can be applied to a process."""

    FREEZE = "FREEZE"
    RELEASE = "RELEASE"
    REVOKE_ACCESS = "REVOKE_ACCESS"


class ContainmentState(str, Enum):
    """Per-PID containment lifecycle states."""

    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    RELEASED = "RELEASED"


@dataclass
class FreezeResult:
    """
    Result of a freeze or release operation.

    Attributes
    ----------
    pid : int
        Target process ID.
    action : str
        The action taken (FREEZE or RELEASE).
    success : bool
        Whether the operation succeeded.
    timestamp : float
        Wall-clock time when the action completed.
    reason : str
        Human-readable reason for the action.
    dry_run : bool
        Whether this was a simulated (non-enforced) action.
    latency_ms : float
        Time taken to execute the action, in milliseconds.
    error : str
        Error message if ``success`` is False, empty otherwise.
    """

    pid: int
    action: str
    success: bool
    timestamp: float
    reason: str
    dry_run: bool
    latency_ms: float
    error: str = ""


class ProcessFreezer:
    """
    Simulates (or enforces) kernel-level process suspension.

    Parameters
    ----------
    dry_run : bool
        If True (default), operations are simulated — state transitions
        and latency are tracked, but no OS signals are sent.  Set to
        False for real enforcement (requires appropriate privileges).
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        self._states: Dict[int, ContainmentState] = {}
        self._lock = threading.Lock()
        self.total_freezes: int = 0
        self.total_releases: int = 0
        self.total_actions: int = 0

    def freeze(self, pid: int, reason: str = "") -> FreezeResult:
        """
        Suspend a process.

        In dry-run mode, only the internal state is updated.
        In real mode, sends ``SIGSTOP`` (Unix) or logs a simulated
        ``NtSuspendProcess`` (Windows, as actual API requires ctypes
        and debug privileges).

        Parameters
        ----------
        pid : int
            Process ID to suspend.
        reason : str
            Human-readable reason (e.g. "CRITICAL_RISK trust=0.0").

        Returns
        -------
        FreezeResult
            Describes whether the operation succeeded.
        """
        t_start = time.perf_counter()

        with self._lock:
            current_state = self._states.get(pid, ContainmentState.ACTIVE)

            if current_state == ContainmentState.FROZEN:
                latency = (time.perf_counter() - t_start) * 1000.0
                self.total_actions += 1
                logger.warning(
                    "[Freezer] PID=%d already FROZEN; cannot double-freeze.",
                    pid,
                )
                return FreezeResult(
                    pid=pid,
                    action=ContainmentAction.FREEZE.value,
                    success=False,
                    timestamp=time.time(),
                    reason=reason,
                    dry_run=self.dry_run,
                    latency_ms=latency,
                    error="Process already frozen",
                )

            # Attempt actual suspension if not dry-run
            error_msg = ""
            success = True
            if not self.dry_run:
                success, error_msg = self._os_freeze(pid)

            if success:
                self._states[pid] = ContainmentState.FROZEN
                self.total_freezes += 1

            self.total_actions += 1

        latency = (time.perf_counter() - t_start) * 1000.0

        logger.info(
            "[Freezer] FREEZE PID=%d  dry_run=%s  success=%s  "
            "latency=%.3fms  reason=%s",
            pid,
            self.dry_run,
            success,
            latency,
            reason,
        )

        return FreezeResult(
            pid=pid,
            action=ContainmentAction.FREEZE.value,
            success=success,
            timestamp=time.time(),
            reason=reason,
            dry_run=self.dry_run,
            latency_ms=latency,
            error=error_msg,
        )

    def release(self, pid: int, reason: str = "") -> FreezeResult:
        """
        Resume a previously frozen process.

        Parameters
        ----------
        pid : int
            Process ID to resume.
        reason : str
            Reason for release (e.g. "false_positive_confirmed").

        Returns
        -------
        FreezeResult
            Describes whether the operation succeeded.
        """
        t_start = time.perf_counter()

        with self._lock:
            current_state = self._states.get(pid, ContainmentState.ACTIVE)

            if current_state != ContainmentState.FROZEN:
                latency = (time.perf_counter() - t_start) * 1000.0
                self.total_actions += 1
                logger.warning(
                    "[Freezer] PID=%d is %s, not FROZEN; cannot release.",
                    pid,
                    current_state.value,
                )
                return FreezeResult(
                    pid=pid,
                    action=ContainmentAction.RELEASE.value,
                    success=False,
                    timestamp=time.time(),
                    reason=reason,
                    dry_run=self.dry_run,
                    latency_ms=latency,
                    error=f"Process is {current_state.value}, not FROZEN",
                )

            error_msg = ""
            success = True
            if not self.dry_run:
                success, error_msg = self._os_release(pid)

            if success:
                self._states[pid] = ContainmentState.RELEASED
                self.total_releases += 1

            self.total_actions += 1

        latency = (time.perf_counter() - t_start) * 1000.0

        logger.info(
            "[Freezer] RELEASE PID=%d  dry_run=%s  success=%s  "
            "latency=%.3fms  reason=%s",
            pid,
            self.dry_run,
            success,
            latency,
            reason,
        )

        return FreezeResult(
            pid=pid,
            action=ContainmentAction.RELEASE.value,
            success=success,
            timestamp=time.time(),
            reason=reason,
            dry_run=self.dry_run,
            latency_ms=latency,
            error=error_msg,
        )

    def get_state(self, pid: int) -> ContainmentState:
        """
        Return the current containment state for a PID.

        Returns ``ACTIVE`` for PIDs that have never been observed.
        """
        with self._lock:
            return self._states.get(pid, ContainmentState.ACTIVE)

    def get_frozen_pids(self) -> List[int]:
        """Return a list of all PIDs currently in the FROZEN state."""
        with self._lock:
            return [
                pid
                for pid, state in self._states.items()
                if state == ContainmentState.FROZEN
            ]

    def get_all_states(self) -> Dict[int, str]:
        """Return a snapshot of all tracked PID states."""
        with self._lock:
            return {pid: state.value for pid, state in self._states.items()}

    # ── OS-level helpers (only used when dry_run=False) ───────────────

    @staticmethod
    def _os_freeze(pid: int) -> tuple:
        """Send SIGSTOP (Unix) or simulate NtSuspendProcess (Windows)."""
        if sys.platform == "win32":
            # On Windows, NtSuspendProcess requires ctypes + SeDebugPrivilege.
            # For safety, we log instead of calling the real API.
            logger.warning(
                "[Freezer] Real NtSuspendProcess for PID=%d is not "
                "implemented; treating as simulated.",
                pid,
            )
            return True, ""
        else:
            try:
                os.kill(pid, signal.SIGSTOP)
                return True, ""
            except ProcessLookupError:
                return False, f"PID {pid} does not exist"
            except PermissionError:
                return False, f"Permission denied for PID {pid}"
            except Exception as exc:
                return False, str(exc)

    @staticmethod
    def _os_release(pid: int) -> tuple:
        """Send SIGCONT (Unix) or simulate NtResumeProcess (Windows)."""
        if sys.platform == "win32":
            logger.warning(
                "[Freezer] Real NtResumeProcess for PID=%d is not "
                "implemented; treating as simulated.",
                pid,
            )
            return True, ""
        else:
            try:
                os.kill(pid, signal.SIGCONT)
                return True, ""
            except ProcessLookupError:
                return False, f"PID {pid} does not exist"
            except PermissionError:
                return False, f"Permission denied for PID {pid}"
            except Exception as exc:
                return False, str(exc)

    def __repr__(self) -> str:
        with self._lock:
            frozen_count = sum(
                1
                for s in self._states.values()
                if s == ContainmentState.FROZEN
            )
        return (
            f"ProcessFreezer(dry_run={self.dry_run}, "
            f"frozen={frozen_count}, "
            f"actions={self.total_actions})"
        )

