"""
src/stage_6_fusion/threat_fusion.py
=====================================
Stage 6 — Main Threat Fusion Orchestrator

This is the primary entry point for Stage 6, consumed by Stage 7
(Dynamic Adaptive Trust Evolution) and the live pipeline monitor.
It coordinates the CompositeScorer and SigmoidEngine to transform
Stage 4 feature vectors and Stage 5 anomaly results into a unified
intent drift signal.

Data Flow:
    Stage 4 (FeatureVector) + Stage 5 (AnomalyResult)
        -> ThreatFusion.fuse(feature_vector, anomaly_result)
            -> {
                 S_composite, IntentDrift, drift_rate,
                 threat_tier, anomaly_score, signals, ...
               }
                -> feeds Stage 7 (Trust State Engine)

Threat Tier Classification (based on IntentDrift):
    BENIGN   : IntentDrift < 0.10  — No threat intent detected
    ELEVATED : 0.10 <= drift < 0.40 — Mild signal, log and monitor
    HIGH     : 0.40 <= drift < 0.75 — Strong signal, prepare containment
    CRITICAL : drift >= 0.75       — Multi-signal convergence, trigger trust decay

Architecture Constraint:
    S_composite is computed from the 5 raw sub-signals (S_entropy, S_dist,
    S_dev, S_rel, 1-S_stab), NOT from Stage 5's fused anomaly_score.
    Stage 5's anomaly_score is a parallel signal passed through for
    downstream consumption only.
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from src.stage_6_fusion.composite_scorer import CompositeScorer
from src.stage_6_fusion.sigmoid_engine import SigmoidEngine

logger = logging.getLogger(__name__)

# Architecture-specified threat tier thresholds (based on IntentDrift)
DEFAULT_TIER_THRESHOLDS: Dict[str, float] = {
    "BENIGN": 0.10,
    "ELEVATED": 0.40,
    "HIGH": 0.75,
}


class ThreatFusion:
    """
    Main Stage 6 orchestrator combining composite scoring and sigmoidal
    acceleration into a unified threat fusion engine.

    Parameters
    ----------
    beta : float
        Sigmoid steepness parameter (default 10.0).
    theta : float
        Sigmoid center threshold (default 0.50).
    composite_weights : dict, optional
        Custom priority weights for the composite scorer.
    tier_thresholds : dict, optional
        Custom threat tier thresholds (keys: BENIGN, ELEVATED, HIGH).

    Attributes
    ----------
    composite : CompositeScorer
        The priority-weighted signal fusion engine.
    sigmoid : SigmoidEngine
        The logistic sigmoidal acceleration engine.
    total_fused : int
        Total events processed through the fusion engine.
    total_critical : int
        Total events classified as CRITICAL tier.
    """

    def __init__(
        self,
        beta: float = 15.0,
        theta: float = 0.50,
        composite_weights: Optional[Dict[str, float]] = None,
        tier_thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self.composite = CompositeScorer(weights=composite_weights)
        self.sigmoid = SigmoidEngine(beta=beta, theta=theta)
        self.tier_thresholds = (
            tier_thresholds.copy()
            if tier_thresholds is not None
            else DEFAULT_TIER_THRESHOLDS.copy()
        )

        # Thread-safe statistics
        self._lock = threading.Lock()
        self.total_fused: int = 0
        self.total_critical: int = 0
        self.total_benign: int = 0
        self.total_elevated: int = 0
        self.total_high: int = 0

    def fuse(
        self,
        feature_vector: Dict[str, Any],
        anomaly_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fuse Stage 4 features + Stage 5 anomaly into an intent drift signal.

        Parameters
        ----------
        feature_vector : dict
            Stage 4 output with keys: S_entropy, S_dist, S_dev, S_stab,
            and optionally S_rel, pid, timestamp, file_path, operation.
        anomaly_result : dict, optional
            Stage 5 output with keys: anomaly_score, risk_tier, confidence.
            If None, anomaly_score defaults to 0.0.

        Returns
        -------
        dict
            Complete fusion result with keys:
                S_composite    : float  — Priority-weighted composite [0, 1]
                IntentDrift    : float  — Sigmoidal acceleration [0, 1]
                drift_rate     : float  — d(IntentDrift)/dt
                threat_tier    : str    — "BENIGN"/"ELEVATED"/"HIGH"/"CRITICAL"
                signals        : dict   — Individual clamped signal values
                anomaly_score  : float  — Stage 5 score (passthrough)
                risk_tier_s5   : str    — Stage 5 risk tier (passthrough)
                pid            : int    — Process ID
                file_path      : str    — Target file path
                timestamp      : float  — Event timestamp
                is_first_observation : bool — First event for this PID
        """
        if anomaly_result is None:
            anomaly_result = {}

        # Extract event context
        pid = feature_vector.get("pid", -1)
        if not isinstance(pid, int):
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                pid = -1

        timestamp = feature_vector.get("timestamp", time.time() * 1000)
        if not isinstance(timestamp, (int, float)):
            try:
                timestamp = float(timestamp)
            except (ValueError, TypeError):
                timestamp = time.time() * 1000

        # Convert to seconds if in milliseconds
        t_sec = timestamp / 1000.0 if timestamp > 1e12 else timestamp

        # Step 1: Compute priority composite score
        composite_result = self.composite.compute(feature_vector)
        s_composite = composite_result["S_composite"]

        # Step 2: Apply sigmoidal acceleration with per-PID drift tracking
        drift_result = self.sigmoid.compute_intent_drift(
            s_composite=s_composite,
            pid=pid,
            timestamp=t_sec,
        )
        intent_drift = drift_result["IntentDrift"]
        drift_rate = drift_result["drift_rate"]

        # Step 3: Assign threat tier based on IntentDrift
        threat_tier = self._assign_threat_tier(intent_drift)

        # Update statistics
        with self._lock:
            self.total_fused += 1
            if threat_tier == "CRITICAL":
                self.total_critical += 1
            elif threat_tier == "HIGH":
                self.total_high += 1
            elif threat_tier == "ELEVATED":
                self.total_elevated += 1
            else:
                self.total_benign += 1

        file_path = feature_vector.get("file_path", "")
        operation = feature_vector.get("operation", "")

        logger.debug(
            "[Stage6-Fusion] PID=%d  S_comp=%.4f  Drift=%.4f  "
            "d(Drift)/dt=%.6f  tier=%s  file=%s",
            pid, s_composite, intent_drift, drift_rate,
            threat_tier, file_path,
        )

        return {
            # Primary Stage 6 outputs
            "S_composite": s_composite,
            "IntentDrift": intent_drift,
            "drift_rate": drift_rate,
            "threat_tier": threat_tier,

            # Decomposed signal values
            "signals": composite_result["signals"],
            "weights": composite_result["weights"],

            # Stage 5 passthrough
            "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
            "risk_tier_s5": anomaly_result.get("risk_tier", "UNKNOWN"),
            "confidence_s5": anomaly_result.get("confidence", 0.0),

            # Event context passthrough
            "pid": pid,
            "file_path": file_path,
            "operation": operation,
            "timestamp": timestamp,
            "is_first_observation": drift_result["is_first_observation"],
        }

    def fuse_batch(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Fuse a batch of (feature_vector, anomaly_result) pairs.

        Parameters
        ----------
        events : list of dict
            Each dict must have "feature_vector" and optionally "anomaly_result".

        Returns
        -------
        list of dict
            Fusion results for each event.
        """
        results = []
        for event in events:
            fv = event.get("feature_vector", event)
            ar = event.get("anomaly_result", None)
            results.append(self.fuse(fv, ar))
        return results

    def _assign_threat_tier(self, intent_drift: float) -> str:
        """
        Map IntentDrift to a threat tier string.

        Tier Mapping:
            IntentDrift < 0.10   → BENIGN
            0.10 ≤ drift < 0.40  → ELEVATED
            0.40 ≤ drift < 0.75  → HIGH
            drift ≥ 0.75         → CRITICAL
        """
        if intent_drift < self.tier_thresholds.get("BENIGN", 0.10):
            return "BENIGN"
        elif intent_drift < self.tier_thresholds.get("ELEVATED", 0.40):
            return "ELEVATED"
        elif intent_drift < self.tier_thresholds.get("HIGH", 0.75):
            return "HIGH"
        else:
            return "CRITICAL"

    def reset_pid(self, pid: int) -> None:
        """Clear all per-PID state (drift history) for a process."""
        self.sigmoid.reset_pid(pid)

    def reset_all(self) -> None:
        """Clear all per-PID state and statistics."""
        self.sigmoid.reset_all()
        with self._lock:
            self.total_fused = 0
            self.total_critical = 0
            self.total_benign = 0
            self.total_elevated = 0
            self.total_high = 0

    def prune_stale_pids(
        self,
        max_age_seconds: float,
        current_time: Optional[float] = None,
    ) -> int:
        """
        Prune PID histories older than max_age_seconds from the sigmoid engine.
        Prevents unbounded memory growth in long-running 24/7 EDR deployments.
        """
        return self.sigmoid.prune_stale_pids(max_age_seconds, current_time)

    def get_stats(self) -> Dict[str, Any]:
        """Return fusion engine statistics."""
        with self._lock:
            return {
                "total_fused": self.total_fused,
                "total_benign": self.total_benign,
                "total_elevated": self.total_elevated,
                "total_high": self.total_high,
                "total_critical": self.total_critical,
                "critical_rate": (
                    self.total_critical / max(1, self.total_fused)
                ),
                "sigmoid_beta": self.sigmoid.beta,
                "sigmoid_theta": self.sigmoid.theta,
                "pids_tracked": len(self.sigmoid.get_tracked_pids()),
                "composite_weight_sum": self.composite.get_weight_sum(),
            }

    def __repr__(self) -> str:
        return (
            f"ThreatFusion(beta={self.sigmoid.beta}, theta={self.sigmoid.theta}, "
            f"fused={self.total_fused}, critical={self.total_critical})"
        )
