"""
src/stage_7_trust/trust_evolution.py
========================================
Stage 7 - Dynamic Adaptive Trust Evolution Orchestrator

Main entry point for Stage 7. Takes Stage 6's fuse() result directly,
runs it through the Trust Decay Engine and the Risk State Machine, and
returns a single combined verdict per event.

Data Flow:
    Stage 6 (ThreatFusion.fuse() result)
        -> TrustEvolution.evolve(stage6_result)
            -> { trust, risk_tier, escalated, should_contain, ... }
                -> feeds Stage 9 (kernel containment) when should_contain
                   is True, and Stage 4 (sampling rate) via sampling_multiplier
"""

import logging
import time
from typing import Any, Dict, Optional

from src.stage_7_trust.trust_engine import TrustDecayEngine, DEFAULT_GAMMA
from src.stage_7_trust.risk_state_machine import RiskStateMachine

logger = logging.getLogger(__name__)


class TrustEvolution:
    """
    Stage 7 orchestrator: turns a Stage 6 fusion result into a Trust
    score, a risk tier, and the concrete actions that tier implies for
    downstream stages.

    Parameters
    ----------
    gamma : float
        Trust decay multiplier, passed through to TrustDecayEngine.
    tier_thresholds : dict, optional
        Custom Trust thresholds for the four risk tiers.
    """

    def __init__(
        self,
        gamma: float = DEFAULT_GAMMA,
        tier_thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self.trust_engine = TrustDecayEngine(gamma=gamma)
        self.risk_machine = RiskStateMachine(thresholds=tier_thresholds)
        self.total_evolved: int = 0
        self.total_containment_triggers: int = 0

    def evolve(self, stage6_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply one Stage 6 event to this process's trust and risk state.

        Parameters
        ----------
        stage6_result : dict
            The dict returned by `ThreatFusion.fuse()`. Must contain at
            least "pid" and "IntentDrift"; "drift_rate" and "timestamp"
            are used if present.

        Returns
        -------
        dict
            {
                "pid": int,
                "trust": float,
                "delta_trust": float,
                "risk_tier": str,
                "previous_risk_tier": str or None,
                "tier_changed": bool,
                "escalated": bool,
                "deescalated": bool,
                "sampling_multiplier": int,
                "prewarm_journal": bool,
                "should_contain": bool,
                "threat_tier_s6": str,     # Stage 6's own tier, passthrough
                "intent_drift": float,     # passthrough
                "timestamp": float,
            }
        """
        pid = stage6_result.get("pid", -1)
        intent_drift = stage6_result.get("IntentDrift", 0.0)
        drift_rate = stage6_result.get("drift_rate", 0.0)
        timestamp = stage6_result.get("timestamp", time.time())
        # Stage 6 may hand us millisecond timestamps; trust engine wants seconds.
        t_sec = timestamp / 1000.0 if timestamp and timestamp > 1e12 else timestamp

        trust_result = self.trust_engine.update_trust(
            pid=pid,
            intent_drift=intent_drift,
            drift_rate=drift_rate,
            timestamp=t_sec,
        )
        tier_result = self.risk_machine.transition(pid, trust_result["trust"])

        tier = tier_result["tier"]
        should_contain = self.risk_machine.should_contain(tier)

        self.total_evolved += 1
        # Count a containment trigger once per *newly entered* CRITICAL_RISK
        # episode: either this is the first event we've ever seen for this
        # PID and it already lands in CRITICAL_RISK (e.g. the process was
        # mid-attack before telemetry started), or it escalated into
        # CRITICAL_RISK from a less severe tier. Either way, a repeat event
        # that is still sitting in CRITICAL_RISK must not re-count.
        newly_critical = should_contain and tier_result["previous_tier"] != "CRITICAL_RISK"
        if newly_critical:
            self.total_containment_triggers += 1

        logger.debug(
            "[Stage7-Evolution] PID=%d  Trust=%.2f  tier=%s%s",
            pid, trust_result["trust"], tier,
            " (ESCALATED)" if tier_result["escalated"] else "",
        )

        return {
            "pid": pid,
            "trust": trust_result["trust"],
            "delta_trust": trust_result["delta_trust"],
            "risk_tier": tier,
            "previous_risk_tier": tier_result["previous_tier"],
            "tier_changed": tier_result["tier_changed"],
            "escalated": tier_result["escalated"],
            "deescalated": tier_result["deescalated"],
            "sampling_multiplier": self.risk_machine.sampling_multiplier(tier),
            "prewarm_journal": self.risk_machine.should_prewarm_journal(tier),
            "should_contain": should_contain,
            "threat_tier_s6": stage6_result.get("threat_tier", "UNKNOWN"),
            "intent_drift": intent_drift,
            "timestamp": timestamp,
        }

    def confirm_false_positive(self, pid: int) -> Dict[str, Any]:
        """
        Stage 10 resolution branch: the analyst (or automated check)
        confirmed this process's containment was a false alarm. Resets
        trust to 100 and the process back to SAFE, mirroring the
        SIGCONT + ACL-restore resolution on the containment side.
        """
        self.trust_engine.reset_trust(pid, trust=100.0)
        tier_result = self.risk_machine.transition(pid, 100.0)
        return {"pid": pid, "trust": 100.0, "risk_tier": tier_result["tier"]}

    def forget_pid(self, pid: int) -> None:
        """Drop all Stage 7 state for a process (e.g. on process exit)."""
        self.trust_engine.forget_pid(pid)
        self.risk_machine.forget_pid(pid)

    def prune_stale_pids(
        self, max_age_seconds: float, current_time: Optional[float] = None
    ) -> int:
        """Evict state for processes inactive beyond max_age_seconds."""
        return self.trust_engine.prune_stale_pids(max_age_seconds, current_time)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_evolved": self.total_evolved,
            "total_containment_triggers": self.total_containment_triggers,
            "gamma": self.trust_engine.gamma,
            "pids_tracked": len(self.trust_engine.get_tracked_pids()),
        }

    def __repr__(self) -> str:
        return (
            f"TrustEvolution(gamma={self.trust_engine.gamma}, "
            f"evolved={self.total_evolved}, "
            f"containment_triggers={self.total_containment_triggers})"
        )
