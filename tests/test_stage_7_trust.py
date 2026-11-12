"""
tests/test_stage_7_trust.py
================================
Stage 7 — Automated Test Suite for Dynamic Adaptive Trust Evolution &
Risk State Engine (TrustDecayEngine + RiskStateMachine + TrustEvolution).

Test Categories:
    1. TrustDecayEngine      (10 tests) — decay math, momentum, clamping, state
    2. RiskStateMachine      (10 tests) — tier assignment, transitions, actions
    3. TrustEvolution        (10 tests) — end-to-end per-event orchestration
    4. Integration            (3 tests) — compatibility with real Stage 6 output

Total: 33 tests
"""

import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_7_trust.trust_engine import TrustDecayEngine, DEFAULT_GAMMA
from src.stage_7_trust.risk_state_machine import (
    RiskStateMachine,
    DEFAULT_THRESHOLDS,
    TIER_ORDER,
)
from src.stage_7_trust.trust_evolution import TrustEvolution
from src.stage_6_fusion import ThreatFusion


# ─────────────────────────────────────────────────────────────────────────
# 1. TrustDecayEngine
# ─────────────────────────────────────────────────────────────────────────

class TestTrustDecayEngine:

    def test_new_pid_starts_at_full_trust(self):
        engine = TrustDecayEngine()
        assert engine.get_trust(999) == 100.0

    def test_zero_intent_drift_causes_no_decay(self):
        engine = TrustDecayEngine(gamma=0.5)
        result = engine.update_trust(pid=1, intent_drift=0.0, drift_rate=0.0)
        assert result["trust"] == pytest.approx(100.0)
        assert result["delta_trust"] == pytest.approx(0.0)

    def test_known_decay_value(self):
        engine = TrustDecayEngine(gamma=0.5)
        # delta = gamma * drift * (1 + rate) * 100 = 0.5 * 0.6 * 1.3 * 100 = 39.0
        result = engine.update_trust(pid=1, intent_drift=0.6, drift_rate=0.3)
        assert result["delta_trust"] == pytest.approx(39.0)
        assert result["trust"] == pytest.approx(61.0)

    def test_trust_never_goes_below_zero(self):
        engine = TrustDecayEngine(gamma=1.0)
        engine.update_trust(pid=1, intent_drift=1.0, drift_rate=5.0)
        assert engine.get_trust(1) == 0.0

    def test_trust_never_exceeds_hundred(self):
        engine = TrustDecayEngine()
        # A very negative drift_rate must not push trust above 100 via the
        # momentum term; negative momentum is clamped to zero penalty, not
        # a reward.
        result = engine.update_trust(pid=1, intent_drift=0.5, drift_rate=-5.0)
        assert result["trust"] <= 100.0
        assert result["delta_trust"] >= 0.0

    def test_negative_drift_rate_clamped_not_rewarding(self):
        engine = TrustDecayEngine(gamma=0.5)
        result = engine.update_trust(pid=1, intent_drift=0.4, drift_rate=-2.0)
        # momentum = max(0, 1 + (-2.0)) = 0 -> delta_trust = 0, not negative
        assert result["delta_trust"] == pytest.approx(0.0)

    def test_sequential_decay_is_cumulative(self):
        engine = TrustDecayEngine(gamma=0.3)
        r1 = engine.update_trust(pid=1, intent_drift=0.5, drift_rate=0.0)
        r2 = engine.update_trust(pid=1, intent_drift=0.5, drift_rate=0.0)
        assert r2["previous_trust"] == pytest.approx(r1["trust"])
        assert r2["trust"] < r1["trust"]

    def test_reset_trust_restores_to_full_by_default(self):
        engine = TrustDecayEngine(gamma=1.0)
        engine.update_trust(pid=1, intent_drift=1.0, drift_rate=0.0)
        assert engine.get_trust(1) < 100.0
        engine.reset_trust(1)
        assert engine.get_trust(1) == 100.0

    def test_forget_pid_clears_state(self):
        engine = TrustDecayEngine()
        engine.update_trust(pid=1, intent_drift=0.5, drift_rate=0.0)
        engine.forget_pid(1)
        assert engine.get_trust(1) == 100.0  # back to the "never seen" default

    def test_invalid_gamma_raises(self):
        with pytest.raises(ValueError):
            TrustDecayEngine(gamma=0.0)
        with pytest.raises(ValueError):
            TrustDecayEngine(gamma=1.5)

    def test_prune_stale_pids(self):
        engine = TrustDecayEngine()
        engine.update_trust(pid=1001, intent_drift=0.5, timestamp=100.0)
        engine.update_trust(pid=1002, intent_drift=0.5, timestamp=150.0)
        evicted = engine.prune_stale_pids(max_age_seconds=30.0, current_time=160.0)
        assert evicted == 1
        assert 1001 not in engine._trust
        assert 1002 in engine._trust
        assert engine.get_trust(1001) == 100.0
        assert engine.get_trust(1002) < 100.0


# ─────────────────────────────────────────────────────────────────────────
# 2. RiskStateMachine
# ─────────────────────────────────────────────────────────────────────────

class TestRiskStateMachine:

    def test_safe_tier_boundary(self):
        rsm = RiskStateMachine()
        assert rsm.assign_tier(100.0) == "SAFE"
        assert rsm.assign_tier(60.0) == "SAFE"

    def test_monitor_tier_boundary(self):
        rsm = RiskStateMachine()
        assert rsm.assign_tier(59.99) == "MONITOR"
        assert rsm.assign_tier(35.0) == "MONITOR"

    def test_verify_tier_boundary(self):
        rsm = RiskStateMachine()
        assert rsm.assign_tier(34.99) == "VERIFY"
        assert rsm.assign_tier(20.0) == "VERIFY"

    def test_critical_risk_tier_boundary(self):
        rsm = RiskStateMachine()
        assert rsm.assign_tier(19.99) == "CRITICAL_RISK"
        assert rsm.assign_tier(0.0) == "CRITICAL_RISK"

    def test_first_observation_has_no_previous_tier(self):
        rsm = RiskStateMachine()
        result = rsm.transition(pid=1, trust=100.0)
        assert result["previous_tier"] is None
        assert result["tier_changed"] is False

    def test_escalation_detected(self):
        rsm = RiskStateMachine()
        rsm.transition(pid=1, trust=90.0)  # SAFE
        result = rsm.transition(pid=1, trust=40.0)  # MONITOR
        assert result["escalated"] is True
        assert result["deescalated"] is False

    def test_deescalation_detected(self):
        rsm = RiskStateMachine()
        rsm.transition(pid=1, trust=10.0)  # CRITICAL_RISK
        result = rsm.transition(pid=1, trust=100.0)  # SAFE (e.g. after reset)
        assert result["deescalated"] is True
        assert result["escalated"] is False

    def test_sampling_multiplier_doubles_only_in_monitor(self):
        assert RiskStateMachine.sampling_multiplier("SAFE") == 1
        assert RiskStateMachine.sampling_multiplier("MONITOR") == 2
        assert RiskStateMachine.sampling_multiplier("VERIFY") == 1

    def test_journal_prewarm_in_verify_and_critical_only(self):
        assert RiskStateMachine.should_prewarm_journal("SAFE") is False
        assert RiskStateMachine.should_prewarm_journal("MONITOR") is False
        assert RiskStateMachine.should_prewarm_journal("VERIFY") is True
        assert RiskStateMachine.should_prewarm_journal("CRITICAL_RISK") is True

    def test_containment_only_in_critical_risk(self):
        assert RiskStateMachine.should_contain("VERIFY") is False
        assert RiskStateMachine.should_contain("CRITICAL_RISK") is True

    def test_forget_pids_multiple(self):
        rsm = RiskStateMachine()
        rsm.transition(pid=1, trust=50.0)
        rsm.transition(pid=2, trust=10.0)
        rsm.transition(pid=3, trust=80.0)
        removed = rsm.forget_pids([1, 2, 999])
        assert removed == 2
        assert rsm.get_tier(1) is None
        assert rsm.get_tier(2) is None
        assert rsm.get_tier(3) == "SAFE"


# ─────────────────────────────────────────────────────────────────────────
# 3. TrustEvolution
# ─────────────────────────────────────────────────────────────────────────

class TestTrustEvolution:

    def test_benign_sequence_stays_safe(self):
        te = TrustEvolution(gamma=0.3)
        for _ in range(5):
            result = te.evolve({"pid": 1, "IntentDrift": 0.05, "drift_rate": 0.0})
        assert result["risk_tier"] == "SAFE"
        assert result["should_contain"] is False

    def test_long_benign_workload_with_elevated_blip_stays_safe(self):
        """50 benign events (<0.10) with occasional mild 0.11 blips must never erode trust into containment."""
        te = TrustEvolution(gamma=0.5)
        result = None
        for i in range(50):
            drift = 0.11 if i in (4, 18, 32) else 0.06
            rate = 0.3 if i in (4, 18, 32) else 0.0
            result = te.evolve({"pid": 30528, "IntentDrift": drift, "drift_rate": rate})
        assert result["trust"] >= 90.0
        assert result["risk_tier"] == "SAFE"
        assert result["should_contain"] is False

    def test_sustained_high_drift_eventually_triggers_containment(self):
        te = TrustEvolution(gamma=0.8)
        result = None
        for _ in range(10):
            result = te.evolve({"pid": 1, "IntentDrift": 0.9, "drift_rate": 0.2})
            if result["should_contain"]:
                break
        assert result["should_contain"] is True
        assert result["risk_tier"] == "CRITICAL_RISK"

    def test_confirm_false_positive_restores_trust(self):
        te = TrustEvolution(gamma=1.0)
        te.evolve({"pid": 1, "IntentDrift": 1.0, "drift_rate": 1.0})
        assert te.trust_engine.get_trust(1) < 100.0
        result = te.confirm_false_positive(1)
        assert result["trust"] == 100.0
        assert result["risk_tier"] == "SAFE"

    def test_millisecond_timestamp_is_normalized(self):
        te = TrustEvolution()
        ms_timestamp = time.time() * 1000.0
        result = te.evolve({"pid": 1, "IntentDrift": 0.1, "timestamp": ms_timestamp})
        assert result["timestamp"] == ms_timestamp  # passthrough unchanged

    def test_missing_drift_rate_defaults_to_zero(self):
        te = TrustEvolution()
        result = te.evolve({"pid": 1, "IntentDrift": 0.2})
        assert result["trust"] < 100.0  # still decays from IntentDrift alone

    def test_threat_tier_s6_passthrough(self):
        te = TrustEvolution()
        result = te.evolve({"pid": 1, "IntentDrift": 0.9, "threat_tier": "CRITICAL"})
        assert result["threat_tier_s6"] == "CRITICAL"

    def test_stats_track_evolution_count(self):
        te = TrustEvolution()
        te.evolve({"pid": 1, "IntentDrift": 0.1})
        te.evolve({"pid": 2, "IntentDrift": 0.1})
        stats = te.get_stats()
        assert stats["total_evolved"] == 2
        assert stats["pids_tracked"] == 2

    def test_containment_trigger_counted_once_on_escalation(self):
        te = TrustEvolution(gamma=1.0)
        te.evolve({"pid": 1, "IntentDrift": 1.0, "drift_rate": 1.0})  # -> CRITICAL_RISK
        te.evolve({"pid": 1, "IntentDrift": 1.0, "drift_rate": 1.0})  # still CRITICAL_RISK
        assert te.get_stats()["total_containment_triggers"] == 1

    def test_forget_pid_resets_to_defaults(self):
        te = TrustEvolution(gamma=1.0)
        te.evolve({"pid": 1, "IntentDrift": 1.0, "drift_rate": 1.0})
        te.forget_pid(1)
        assert te.trust_engine.get_trust(1) == 100.0
        assert te.risk_machine.get_tier(1) is None

    def test_independent_pids_do_not_share_state(self):
        te = TrustEvolution(gamma=1.0)
        te.evolve({"pid": 1, "IntentDrift": 1.0, "drift_rate": 1.0})
        result2 = te.evolve({"pid": 2, "IntentDrift": 0.0, "drift_rate": 0.0})
        assert result2["trust"] == 100.0
        assert result2["risk_tier"] == "SAFE"

    def test_prune_stale_pids_cleans_both_trust_and_risk_state(self):
        te = TrustEvolution(gamma=1.0)
        te.evolve({"pid": 1001, "IntentDrift": 0.8, "drift_rate": 0.0, "timestamp": 1000.0})
        te.evolve({"pid": 1002, "IntentDrift": 0.8, "drift_rate": 0.0, "timestamp": 1050.0})
        assert te.risk_machine.get_tier(1001) is not None
        assert te.risk_machine.get_tier(1002) is not None

        evicted = te.prune_stale_pids(max_age_seconds=30.0, current_time=1060.0)
        assert evicted == 1

        # PID 1001 was stale: must be purged from BOTH trust engine AND risk machine
        assert te.trust_engine.get_trust(1001) == 100.0
        assert te.risk_machine.get_tier(1001) is None

        # PID 1002 was recent: must remain active in both
        assert te.trust_engine.get_trust(1002) < 100.0
        assert te.risk_machine.get_tier(1002) is not None


# ─────────────────────────────────────────────────────────────────────────
# 4. Integration — real Stage 6 output
# ─────────────────────────────────────────────────────────────────────────

class TestStage6ToStage7Integration:

    def test_accepts_real_threatfusion_output(self):
        """Stage 6's actual ThreatFusion.fuse() output should flow into
        Stage 7 without any adaptation layer."""
        fusion = ThreatFusion()
        te = TrustEvolution(gamma=0.5)

        feature_vector = {
            "S_entropy": 0.9, "S_dist": 0.8, "S_dev": 0.7,
            "S_rel": 0.6, "S_stab": 0.2,
            "pid": 777, "timestamp": time.time() * 1000.0,
        }
        s6_result = fusion.fuse(feature_vector)
        s7_result = te.evolve(s6_result)

        assert s7_result["pid"] == 777
        assert 0.0 <= s7_result["trust"] <= 100.0
        assert s7_result["risk_tier"] in ("SAFE", "MONITOR", "VERIFY", "CRITICAL_RISK")

    def test_benign_feature_vector_keeps_trust_high_through_both_stages(self):
        fusion = ThreatFusion()
        te = TrustEvolution(gamma=0.5)

        benign_vector = {
            "S_entropy": 0.2, "S_dist": 0.1, "S_dev": 0.05,
            "S_rel": 0.1, "S_stab": 0.9,
            "pid": 42, "timestamp": time.time() * 1000.0,
        }
        for _ in range(5):
            s6_result = fusion.fuse(benign_vector)
            s7_result = te.evolve(s6_result)

        assert s7_result["risk_tier"] == "SAFE"

    def test_ransomware_like_vector_drives_containment_through_both_stages(self):
        fusion = ThreatFusion()
        te = TrustEvolution(gamma=0.8)

        ransomware_vector = {
            "S_entropy": 0.97, "S_dist": 0.95, "S_dev": 0.9,
            "S_rel": 0.9, "S_stab": 0.05,
            "pid": 6666, "timestamp": time.time() * 1000.0,
        }
        s7_result = None
        for _ in range(10):
            s6_result = fusion.fuse(ransomware_vector)
            s7_result = te.evolve(s6_result)
            if s7_result["should_contain"]:
                break

        assert s7_result["should_contain"] is True
