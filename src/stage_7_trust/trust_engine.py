"""
src/stage_7_trust/trust_engine.py
=====================================
Stage 7 - Momentum Trust Decay Engine

Every process starts with full trust (100) and loses trust on each
event in proportion to how confident Stage 6 is that the event is
malicious (IntentDrift), accelerated by how fast that confidence is
rising (drift_rate). A threat that is getting worse quickly is
penalized harder than one of equal severity that has plateaued.

Mathematical Foundation (architecture specification, Stage 7):

    Trust(t) = max(0, Trust(t-1) - gamma * IntentDrift(t) * (1 + drift_rate) * 100)

Where:
    gamma       = decay multiplier in [0.1, 1.0], tuned by the Stage 12
                  ablation sweep (default 0.5 here, pending that sweep)
    IntentDrift = Stage 6's sigmoidally-accelerated intent score [0, 1]
    drift_rate  = Stage 6's d(IntentDrift)/dt, can be negative

Trust state is tracked per process (PID) and never goes below 0 or
above 100. A process can be forgiven back to full trust (e.g. after
Stage 10 confirms a false positive) via reset_trust().
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_GAMMA: float = 0.5
INITIAL_TRUST: float = 100.0
MIN_TRUST: float = 0.0
MAX_TRUST: float = 100.0


class TrustDecayEngine:
    """
    Momentum-based trust decay engine with per-PID state.

    Parameters
    ----------
    gamma : float
        Decay multiplier in [0.1, 1.0]. Higher values decay trust faster
        for the same IntentDrift/drift_rate. Default 0.5.
    """

    def __init__(self, gamma: float = DEFAULT_GAMMA) -> None:
        if not (0.0 < gamma <= 1.0):
            raise ValueError(f"gamma must be in (0, 1.0], got {gamma}")
        self.gamma = gamma

        # pid -> (trust, last_timestamp)
        self._trust: Dict[int, Tuple[float, float]] = {}
        self._lock = threading.Lock()

        self.total_updates: int = 0

    def update_trust(
        self,
        pid: int,
        intent_drift: float,
        drift_rate: float = 0.0,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Apply one event's worth of trust decay for a process.

        Parameters
        ----------
        pid : int
            Process ID being tracked.
        intent_drift : float
            Stage 6 IntentDrift for this event, expected in [0, 1].
        drift_rate : float
            Stage 6 drift_rate (d(IntentDrift)/dt) for this event.
        timestamp : float, optional
            Event time in seconds. Defaults to time.time().

        Returns
        -------
        dict
            {
                "pid": int,
                "trust": float,          # new Trust(t), in [0, 100]
                "previous_trust": float, # Trust(t-1)
                "delta_trust": float,    # amount subtracted this event
                "timestamp": float,
            }
        """
        if timestamp is None:
            timestamp = time.time()

        intent_drift = max(0.0, min(1.0, float(intent_drift)))
        # drift_rate is a signed velocity; only its effect on the momentum
        # multiplier matters here, so we don't clamp it, but we do prevent
        # a very large negative rate from flipping the multiplier negative
        # (which would turn a penalty into a reward).
        momentum = max(0.0, 1.0 + float(drift_rate))

        with self._lock:
            previous_trust, _ = self._trust.get(pid, (INITIAL_TRUST, timestamp))

            delta_trust = self.gamma * intent_drift * momentum * 100.0
            new_trust = max(MIN_TRUST, min(MAX_TRUST, previous_trust - delta_trust))

            self._trust[pid] = (new_trust, timestamp)
            self.total_updates += 1

        logger.debug(
            "[Stage7-Trust] PID=%d  drift=%.4f  rate=%+.4f  "
            "Trust: %.2f -> %.2f (-%.2f)",
            pid, intent_drift, drift_rate, previous_trust, new_trust, delta_trust,
        )

        return {
            "pid": pid,
            "trust": new_trust,
            "previous_trust": previous_trust,
            "delta_trust": delta_trust,
            "timestamp": timestamp,
        }

    def get_trust(self, pid: int) -> float:
        """Return a process's current trust, or 100.0 if never observed."""
        with self._lock:
            trust, _ = self._trust.get(pid, (INITIAL_TRUST, 0.0))
            return trust

    def reset_trust(self, pid: int, trust: float = INITIAL_TRUST) -> None:
        """
        Restore a process's trust (default: back to full 100).

        Used when Stage 10 confirms a containment event was a false
        positive and the process is resumed via SIGCONT.
        """
        with self._lock:
            self._trust[pid] = (max(MIN_TRUST, min(MAX_TRUST, trust)), time.time())

    def forget_pid(self, pid: int) -> None:
        """Drop all tracked state for a PID (e.g. on process exit)."""
        with self._lock:
            self._trust.pop(pid, None)

    def evict_stale_pids(
        self, max_age_seconds: float, current_time: Optional[float] = None
    ) -> List[int]:
        """Evict trust state for PIDs inactive beyond max_age_seconds, returning the list of evicted PIDs."""
        if current_time is None:
            current_time = time.time()
        cutoff = current_time - max_age_seconds
        with self._lock:
            stale = [pid for pid, (_, ts) in self._trust.items() if ts < cutoff]
            for pid in stale:
                del self._trust[pid]
            return stale

    def prune_stale_pids(
        self, max_age_seconds: float, current_time: Optional[float] = None
    ) -> int:
        """Evict trust state for PIDs inactive beyond max_age_seconds."""
        return len(self.evict_stale_pids(max_age_seconds, current_time))

    def get_tracked_pids(self):
        with self._lock:
            return list(self._trust.keys())

    def __repr__(self) -> str:
        with self._lock:
            n = len(self._trust)
        return f"TrustDecayEngine(gamma={self.gamma}, tracked_pids={n}, updates={self.total_updates})"
