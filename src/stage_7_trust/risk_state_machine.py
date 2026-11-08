"""
src/stage_7_trust/risk_state_machine.py
===========================================
Stage 7 - Risk State Machine

Maps a process's current Trust score onto one of four risk tiers and
tracks tier transitions per process, so the pipeline can react to a
process *entering* a tier (not just sitting in one).

Risk Tiers (architecture specification, Stage 7):
    SAFE          : Trust >= 60   - normal operation
    MONITOR       : 35 <= Trust < 60  - double the 4KB sampling frequency
    VERIFY        : 20 <= Trust < 35  - pre-warm the write-ahead journal
    CRITICAL_RISK : Trust < 20    - trigger Stage 9 kernel containment

Tiers are ordered SAFE > MONITOR > VERIFY > CRITICAL_RISK so that
"escalating" and "de-escalating" transitions can be told apart.
"""

import threading
from typing import Dict, Optional, Tuple

# Tier names in order from least to most severe.
TIER_ORDER = ("SAFE", "MONITOR", "VERIFY", "CRITICAL_RISK")

# Lower bound (inclusive) of Trust for each tier.
DEFAULT_THRESHOLDS: Dict[str, float] = {
    "SAFE": 60.0,
    "MONITOR": 35.0,
    "VERIFY": 20.0,
    "CRITICAL_RISK": 0.0,
}


def _severity(tier: str) -> int:
    """Higher number = more severe. Used to detect escalation vs de-escalation."""
    return TIER_ORDER.index(tier)


class RiskStateMachine:
    """
    Converts Trust scores into risk tiers and tracks per-process transitions.

    Parameters
    ----------
    thresholds : dict, optional
        Lower bound of Trust for each tier. Must cover all four tier
        names in DEFAULT_THRESHOLDS. Defaults to the architecture
        specification's values (60 / 35 / 20 / 0).
    """

    def __init__(self, thresholds: Optional[Dict[str, float]] = None) -> None:
        self.thresholds = dict(thresholds) if thresholds else dict(DEFAULT_THRESHOLDS)
        # pid -> current tier
        self._tier: Dict[int, str] = {}
        self._lock = threading.Lock()

    def assign_tier(self, trust: float) -> str:
        """Pure function: Trust value -> tier name. Does not touch per-PID state."""
        if trust >= self.thresholds["SAFE"]:
            return "SAFE"
        elif trust >= self.thresholds["MONITOR"]:
            return "MONITOR"
        elif trust >= self.thresholds["VERIFY"]:
            return "VERIFY"
        else:
            return "CRITICAL_RISK"

    def transition(self, pid: int, trust: float) -> Dict[str, object]:
        """
        Assign a tier for this Trust value and record the transition for `pid`.

        Returns
        -------
        dict
            {
                "pid": int,
                "tier": str,              # new tier
                "previous_tier": str,     # tier before this update (None on first observation)
                "tier_changed": bool,
                "escalated": bool,        # tier_changed and more severe than before
                "deescalated": bool,      # tier_changed and less severe than before
            }
        """
        new_tier = self.assign_tier(trust)

        with self._lock:
            previous_tier = self._tier.get(pid)
            self._tier[pid] = new_tier

        tier_changed = previous_tier is not None and previous_tier != new_tier
        escalated = tier_changed and _severity(new_tier) > _severity(previous_tier)
        deescalated = tier_changed and _severity(new_tier) < _severity(previous_tier)

        return {
            "pid": pid,
            "tier": new_tier,
            "previous_tier": previous_tier,
            "tier_changed": tier_changed,
            "escalated": escalated,
            "deescalated": deescalated,
        }

    def get_tier(self, pid: int) -> Optional[str]:
        """Return a process's last-known tier, or None if never observed."""
        with self._lock:
            return self._tier.get(pid)

    def forget_pid(self, pid: int) -> None:
        with self._lock:
            self._tier.pop(pid, None)

    @staticmethod
    def sampling_multiplier(tier: str) -> int:
        """
        How much faster Stage 4 should sample 4KB write buffers while a
        process sits in this tier. MONITOR doubles it; everything else
        uses the normal rate (VERIFY/CRITICAL_RISK are about to be
        contained outright, not sampled harder).
        """
        return 2 if tier == "MONITOR" else 1

    @staticmethod
    def should_prewarm_journal(tier: str) -> bool:
        """Whether Stage 10's write-ahead journal buffers should be warmed now."""
        return tier in ("VERIFY", "CRITICAL_RISK")

    @staticmethod
    def should_contain(tier: str) -> bool:
        """Whether Stage 9 kernel containment should be triggered now."""
        return tier == "CRITICAL_RISK"

    def __repr__(self) -> str:
        with self._lock:
            n = len(self._tier)
        return f"RiskStateMachine(tracked_pids={n})"
