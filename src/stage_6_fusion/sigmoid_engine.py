"""
src/stage_6_fusion/sigmoid_engine.py
=======================================
Stage 6 — Sigmoidal Acceleration Engine with Per-PID Drift Tracking

Transforms composite threat scores through a logistic sigmoid function
to create a non-linear "Intent Drift" signal that suppresses single-
feature spikes while rapidly accelerating multi-signal convergence.

Mathematical Foundation (from architecture specification — Stage 6):

    IntentDrift(t) = 1 / (1 + exp(-beta * (S_composite - theta)))

    Where:
        beta  = 10.0   (steepness — how sharply the sigmoid rises)
        theta = 0.50   (threshold center — scores below this are suppressed)

    Acceleration Rate (numerical derivative):
        d(Drift)/dt = [IntentDrift(t) - IntentDrift(t - dt)] / dt

Behaviour:
    - S_composite << theta  →  IntentDrift ≈ 0.0   (fully suppressed)
    - S_composite ≈  theta  →  IntentDrift ≈ 0.5   (transition zone)
    - S_composite >> theta  →  IntentDrift ≈ 1.0   (full acceleration)

Per-PID State:
    The engine tracks the most recent IntentDrift and timestamp for each
    process ID to compute the temporal derivative d(Drift)/dt, which
    measures how rapidly a process is accelerating toward malicious intent.
"""

import logging
import math
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Architecture-specified default parameters
DEFAULT_BETA: float = 15.0
DEFAULT_THETA: float = 0.50


class SigmoidEngine:
    """
    Logistic sigmoidal acceleration engine with per-PID drift history.

    Parameters
    ----------
    beta : float
        Steepness parameter for the logistic curve (default 10.0).
        Higher values create a sharper transition around theta.
    theta : float
        Center threshold for the sigmoid (default 0.50).
        Composite scores below theta are heavily suppressed.

    Attributes
    ----------
    beta : float
        Active steepness parameter.
    theta : float
        Active center threshold.
    total_computed : int
        Number of drift computations performed.
    """

    def __init__(
        self,
        beta: float = DEFAULT_BETA,
        theta: float = DEFAULT_THETA,
    ) -> None:
        if beta <= 0:
            raise ValueError(f"beta must be positive, got {beta}")
        if not (0.0 <= theta <= 1.0):
            raise ValueError(f"theta must be in [0, 1], got {theta}")

        self.beta: float = beta
        self.theta: float = theta

        # Per-PID drift history: pid -> (prev_drift, prev_timestamp)
        self._history: Dict[int, Tuple[float, float]] = {}
        self._lock = threading.Lock()

        # Statistics
        self.total_computed: int = 0

    def compute_intent_drift(
        self,
        s_composite: float,
        pid: int,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Compute IntentDrift and drift rate for a process.

        Parameters
        ----------
        s_composite : float
            Priority-weighted composite score from CompositeScorer [0, 1].
        pid : int
            Process ID for per-PID drift history tracking.
        timestamp : float, optional
            Event timestamp in seconds (defaults to time.time()).

        Returns
        -------
        dict
            {
                "IntentDrift": float,     # Sigmoidal acceleration [0, 1]
                "drift_rate": float,      # d(IntentDrift)/dt (acceleration)
                "S_composite": float,     # Input composite (passthrough)
                "pid": int,               # Process ID
                "timestamp": float,       # Event timestamp
                "is_first_observation": bool,
            }
        """
        if timestamp is None:
            timestamp = time.time()

        # Clamp composite to [0, 1]
        s_composite = max(0.0, min(1.0, s_composite))

        # Apply logistic sigmoidal acceleration
        intent_drift = self._sigmoid(s_composite)

        # Compute drift rate from per-PID history
        drift_rate = 0.0
        is_first = True

        with self._lock:
            if pid in self._history:
                prev_drift, prev_ts = self._history[pid]
                dt = timestamp - prev_ts
                if dt > 1e-9:  # Avoid division by near-zero
                    drift_rate = (intent_drift - prev_drift) / dt
                is_first = False

            # Update history
            self._history[pid] = (intent_drift, timestamp)
            self.total_computed += 1

        logger.debug(
            "[Stage6-Sigmoid] PID=%d  S_comp=%.4f  IntentDrift=%.4f  "
            "drift_rate=%.6f  first=%s",
            pid, s_composite, intent_drift, drift_rate, is_first,
        )

        return {
            "IntentDrift": intent_drift,
            "drift_rate": drift_rate,
            "S_composite": s_composite,
            "pid": pid,
            "timestamp": timestamp,
            "is_first_observation": is_first,
        }

    def _sigmoid(self, s_composite: float) -> float:
        """
        Apply the logistic sigmoid function.

        IntentDrift = 1 / (1 + exp(-beta * (S_composite - theta)))
        """
        exponent = -self.beta * (s_composite - self.theta)
        # Guard against overflow/underflow in exp()
        if exponent > 100:
            return 0.0
        if exponent < -100:
            return 1.0
        return 1.0 / (1.0 + math.exp(exponent))

    def get_pid_drift(self, pid: int) -> Optional[Tuple[float, float]]:
        """
        Return the last recorded (IntentDrift, timestamp) for a PID.

        Returns None if the PID has no history.
        """
        with self._lock:
            return self._history.get(pid)

    def get_tracked_pids(self):
        """Return a list of all PIDs with drift history."""
        with self._lock:
            return list(self._history.keys())

    def reset_pid(self, pid: int) -> None:
        """Clear drift history for a specific PID."""
        with self._lock:
            self._history.pop(pid, None)

    def reset_all(self) -> None:
        """Clear all per-PID drift history."""
        with self._lock:
            self._history.clear()

    def prune_stale_pids(
        self,
        max_age_seconds: float,
        current_time: Optional[float] = None,
    ) -> int:
        """
        Prune PID histories that haven't recorded activity within max_age_seconds.
        Prevents unbounded memory accumulation in long-running 24/7 EDR deployments.

        Parameters
        ----------
        max_age_seconds : float
            Maximum age in seconds since last recorded event.
        current_time : float, optional
            Current reference time (defaults to time.time()).

        Returns
        -------
        int
            Number of stale PIDs evicted.
        """
        if current_time is None:
            current_time = time.time()
        cutoff = current_time - max_age_seconds
        evicted = 0
        with self._lock:
            stale_pids = [
                pid for pid, (_, last_ts) in self._history.items()
                if last_ts < cutoff
            ]
            for pid in stale_pids:
                del self._history[pid]
                evicted += 1
        return evicted

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        with self._lock:
            return {
                "beta": self.beta,
                "theta": self.theta,
                "pids_tracked": len(self._history),
                "total_computed": self.total_computed,
            }

    def __repr__(self) -> str:
        with self._lock:
            n_pids = len(self._history)
        return (
            f"SigmoidEngine(beta={self.beta}, theta={self.theta}, "
            f"pids_tracked={n_pids}, total={self.total_computed})"
        )
