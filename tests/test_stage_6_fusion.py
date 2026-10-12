"""
tests/test_stage_6_fusion.py
================================
Stage 6 — Comprehensive Automated Test Suite for Multi-Signal
Corroboration & Sigmoidal Acceleration Engine

Test Categories:
    Category 1:  CompositeScorer — Basic Operations         (20 tests)
    Category 2:  CompositeScorer — Signal Isolation          (12 tests)
    Category 3:  CompositeScorer — Edge Cases & Invalid      (14 tests)
    Category 4:  SigmoidEngine — Core Sigmoid Math           (16 tests)
    Category 5:  SigmoidEngine — Per-PID Drift Tracking      (14 tests)
    Category 6:  SigmoidEngine — Edge Cases & Invalid        (12 tests)
    Category 7:  ThreatFusion — Core Fusion Pipeline         (16 tests)
    Category 8:  ThreatFusion — Threat Tier Classification   (12 tests)
    Category 9:  ThreatFusion — Batch & Stateful Behaviour   (10 tests)
    Category 10: ThreatFusion — Thread Safety & Concurrency  ( 6 tests)
    Category 11: Integration — Stage 4 → 5 → 6 Pipeline     (14 tests)
    Category 12: Verification Criteria & Arch Compliance     (16 tests)
    Category 13: Statistics, Reset & Lifecycle               ( 8 tests)

    Total: 170 tests
"""

import math
import os
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any

# pyrefly: ignore [missing-import]
import pytest

# Ensure project root on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_6_fusion.composite_scorer import (
    CompositeScorer,
    DEFAULT_WEIGHTS,
    _clamp,
    _safe_float,
)
from src.stage_6_fusion.sigmoid_engine import (
    SigmoidEngine,
    DEFAULT_BETA,
    DEFAULT_THETA,
)
from src.stage_6_fusion.threat_fusion import (
    ThreatFusion,
    DEFAULT_TIER_THRESHOLDS,
)
from src.stage_6_fusion import (
    COMPOSITE_WEIGHTS,
    THREAT_TIERS,
)


# ─── Helper Factories ───────────────────────────────────────────────────────

def _benign_vector(**overrides) -> Dict[str, Any]:
    """Generate a typical benign file operation feature vector."""
    fv = {
        "S_entropy": 0.15, "S_ETD": 0.10, "S_dist": 0.04,
        "S_dev": 0.02, "S_stab": 0.85, "S_rel": 0.05,
        "lambda_norm": 0.02, "branching_n": 0.625,
        "pid": 1000, "file_path": "C:\\Users\\test\\doc.txt",
        "operation": "FILE_MODIFY", "timestamp": 1700000000000.0,
    }
    fv.update(overrides)
    return fv


def _ransomware_vector(**overrides) -> Dict[str, Any]:
    """Generate a typical ransomware attack feature vector."""
    fv = {
        "S_entropy": 0.95, "S_ETD": 0.90, "S_dist": 0.85,
        "S_dev": 0.90, "S_stab": 0.10, "S_rel": 0.80,
        "lambda_norm": 0.95, "branching_n": 1.8,
        "is_superheated": True,
        "pid": 9999, "file_path": "C:\\Users\\test\\secret.docx.locked",
        "operation": "FILE_MODIFY", "timestamp": 1700000001000.0,
    }
    fv.update(overrides)
    return fv


def _archiver_vector(**overrides) -> Dict[str, Any]:
    """Generate a 7-Zip style high-entropy-only feature vector."""
    fv = {
        "S_entropy": 0.92, "S_ETD": 0.30, "S_dist": 0.02,
        "S_dev": 0.03, "S_stab": 0.90, "S_rel": 0.05,
        "lambda_norm": 0.05, "branching_n": 0.625,
        "pid": 2000, "file_path": "C:\\Users\\test\\archive.7z",
        "operation": "FILE_CREATE", "timestamp": 1700000002000.0,
    }
    fv.update(overrides)
    return fv


def _moderate_vector(**overrides) -> Dict[str, Any]:
    """Generate a borderline/moderate activity feature vector."""
    fv = {
        "S_entropy": 0.50, "S_ETD": 0.50, "S_dist": 0.50,
        "S_dev": 0.50, "S_stab": 0.50, "S_rel": 0.50,
        "lambda_norm": 0.50, "branching_n": 0.625,
        "pid": 3000, "file_path": "C:\\Users\\test\\mid.bin",
        "operation": "FILE_MODIFY", "timestamp": 1700000003000.0,
    }
    fv.update(overrides)
    return fv


# ═══════════════════════════════════════════════════════════════════════════
# Category 1: CompositeScorer — Basic Operations (20 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestCompositeBasic:

    def test_default_weights_match_architecture(self):
        """Verify default weights match architecture specification."""
        assert DEFAULT_WEIGHTS["S_entropy"] == 0.35
        assert DEFAULT_WEIGHTS["S_dist"] == 0.30
        assert DEFAULT_WEIGHTS["S_dev"] == 0.20
        assert DEFAULT_WEIGHTS["S_rel"] == 0.10
        assert DEFAULT_WEIGHTS["S_stab"] == 0.05

    def test_weights_sum_to_one(self):
        """Architecture constraint: all weights must sum to 1.0."""
        scorer = CompositeScorer()
        assert abs(scorer.get_weight_sum() - 1.0) < 1e-10

    def test_benign_composite_low(self):
        """Benign activity should produce a low composite score."""
        scorer = CompositeScorer()
        result = scorer.compute(_benign_vector())
        assert result["S_composite"] < 0.20

    def test_ransomware_composite_high(self):
        """Ransomware activity should produce a high composite score."""
        scorer = CompositeScorer()
        result = scorer.compute(_ransomware_vector())
        assert result["S_composite"] > 0.70

    def test_composite_output_keys(self):
        """Verify all expected keys are present in output."""
        scorer = CompositeScorer()
        result = scorer.compute(_benign_vector())
        assert "S_composite" in result
        assert "signals" in result
        assert "weights" in result

    def test_signals_decomposition_keys(self):
        """Verify individual signal decomposition keys."""
        scorer = CompositeScorer()
        result = scorer.compute(_benign_vector())
        signals = result["signals"]
        assert "S_entropy" in signals
        assert "S_dist" in signals
        assert "S_dev" in signals
        assert "S_rel" in signals
        assert "S_stab_inv" in signals

    def test_stab_inversion(self):
        """S_stab must be inverted: S_stab_inv = 1 - S_stab."""
        scorer = CompositeScorer()
        fv = _benign_vector(S_stab=0.85)
        result = scorer.compute(fv)
        assert abs(result["signals"]["S_stab_inv"] - 0.15) < 1e-10

    def test_stab_inversion_low_stability(self):
        """Low stability (unstable) → high S_stab_inv."""
        scorer = CompositeScorer()
        fv = _ransomware_vector(S_stab=0.10)
        result = scorer.compute(fv)
        assert abs(result["signals"]["S_stab_inv"] - 0.90) < 1e-10

    def test_composite_range_zero_to_one(self):
        """S_composite must always be in [0, 1]."""
        scorer = CompositeScorer()
        for vec_fn in [_benign_vector, _ransomware_vector, _archiver_vector, _moderate_vector]:
            result = scorer.compute(vec_fn())
            assert 0.0 <= result["S_composite"] <= 1.0

    def test_total_scored_counter(self):
        """Verify the total_scored counter increments."""
        scorer = CompositeScorer()
        assert scorer.total_scored == 0
        scorer.compute(_benign_vector())
        assert scorer.total_scored == 1
        scorer.compute(_ransomware_vector())
        assert scorer.total_scored == 2

    def test_custom_weights(self):
        """Verify custom weights are applied correctly."""
        custom = {"S_entropy": 1.0, "S_dist": 0.0, "S_dev": 0.0, "S_rel": 0.0, "S_stab": 0.0}
        scorer = CompositeScorer(weights=custom)
        fv = {"S_entropy": 0.5, "S_dist": 0.9, "S_dev": 0.9, "S_stab": 0.1}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.5) < 1e-10

    def test_manual_formula_verification(self):
        """Manually verify the weighted sum formula."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.80, "S_dist": 0.60, "S_dev": 0.40,
              "S_rel": 0.20, "S_stab": 0.50}
        result = scorer.compute(fv)
        expected = (0.35 * 0.80 + 0.30 * 0.60 + 0.20 * 0.40
                    + 0.10 * 0.20 + 0.05 * 0.50)
        assert abs(result["S_composite"] - expected) < 1e-10

    def test_weights_returned_in_output(self):
        """Returned weights should match active weights."""
        scorer = CompositeScorer()
        result = scorer.compute(_benign_vector())
        assert result["weights"] == DEFAULT_WEIGHTS

    def test_repr_string(self):
        """Verify repr includes class name."""
        scorer = CompositeScorer()
        assert "CompositeScorer" in repr(scorer)

    def test_scorer_is_stateless_per_event(self):
        """Each compute() call is independent (no state leaks between events)."""
        scorer = CompositeScorer()
        r1 = scorer.compute(_ransomware_vector())
        r2 = scorer.compute(_benign_vector())
        r3 = scorer.compute(_ransomware_vector())
        assert abs(r1["S_composite"] - r3["S_composite"]) < 1e-10

    def test_zero_input_yields_zero_composite(self):
        """All-zero signals → composite is zero (or near zero from stab inversion)."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert result["S_composite"] < 0.001

    def test_max_input_yields_max_composite(self):
        """All-max signals → composite is 1.0."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 1.0, "S_dist": 1.0, "S_dev": 1.0,
              "S_rel": 1.0, "S_stab": 0.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 1.0) < 1e-10

    def test_archiver_composite_moderate(self):
        """7-Zip archiver (entropy-only) should be moderate, not maximum."""
        scorer = CompositeScorer()
        result = scorer.compute(_archiver_vector())
        assert 0.20 < result["S_composite"] < 0.55

    def test_multiple_sequential_benign(self):
        """Multiple benign events should all produce low composites."""
        scorer = CompositeScorer()
        for i in range(20):
            result = scorer.compute(_benign_vector(pid=1000 + i))
            assert result["S_composite"] < 0.25

    def test_benign_lower_than_ransomware(self):
        """Benign composite must be strictly less than ransomware composite."""
        scorer = CompositeScorer()
        rb = scorer.compute(_benign_vector())
        rr = scorer.compute(_ransomware_vector())
        assert rb["S_composite"] < rr["S_composite"]


# ═══════════════════════════════════════════════════════════════════════════
# Category 2: CompositeScorer — Signal Isolation (12 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestCompositeSignalIsolation:

    def test_entropy_only_high(self):
        """Only S_entropy high → limited composite from single signal."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 1.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.35) < 1e-10

    def test_dist_only_high(self):
        """Only S_dist high → exactly 0.30."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.0, "S_dist": 1.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.30) < 1e-10

    def test_dev_only_high(self):
        """Only S_dev high → exactly 0.20."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 1.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.20) < 1e-10

    def test_rel_only_high(self):
        """Only S_rel high → exactly 0.10."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 1.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.10) < 1e-10

    def test_stab_inv_only_high(self):
        """Only S_stab low (inverted high) → exactly 0.05."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 0.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.05) < 1e-10

    def test_entropy_plus_dist_only(self):
        """S_entropy + S_dist only → exactly 0.65."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 1.0, "S_dist": 1.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.65) < 1e-10

    def test_half_entropy_isolation(self):
        """S_entropy=0.5, others zero → 0.175."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.5, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0}
        result = scorer.compute(fv)
        assert abs(result["S_composite"] - 0.175) < 1e-10

    def test_entropy_dominates_over_stab(self):
        """Entropy weight (0.35) should dominate over stability (0.05)."""
        scorer = CompositeScorer()
        fv1 = {"S_entropy": 0.5, "S_dist": 0.0, "S_dev": 0.0,
               "S_rel": 0.0, "S_stab": 1.0}
        fv2 = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
               "S_rel": 0.0, "S_stab": 0.0}
        r1 = scorer.compute(fv1)
        r2 = scorer.compute(fv2)
        assert r1["S_composite"] > r2["S_composite"]

    def test_weight_proportionality(self):
        """Higher-weighted signals should contribute more per unit."""
        scorer = CompositeScorer()
        fv_entropy = {"S_entropy": 0.5, "S_dist": 0.0, "S_dev": 0.0,
                      "S_rel": 0.0, "S_stab": 1.0}
        fv_dev = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.5,
                  "S_rel": 0.0, "S_stab": 1.0}
        re = scorer.compute(fv_entropy)
        rd = scorer.compute(fv_dev)
        assert re["S_composite"] > rd["S_composite"]

    def test_linearity_of_fusion(self):
        """Double all inputs → double the composite (within [0,1] bounds)."""
        scorer = CompositeScorer()
        fv1 = {"S_entropy": 0.2, "S_dist": 0.2, "S_dev": 0.2,
               "S_rel": 0.2, "S_stab": 0.8}
        fv2 = {"S_entropy": 0.4, "S_dist": 0.4, "S_dev": 0.4,
               "S_rel": 0.4, "S_stab": 0.6}
        r1 = scorer.compute(fv1)
        r2 = scorer.compute(fv2)
        assert abs(r2["S_composite"] - 2 * r1["S_composite"]) < 1e-10

    def test_all_signals_half(self):
        """All signals at 0.5, S_stab at 0.5 → composite should be 0.50."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.5, "S_dist": 0.5, "S_dev": 0.5,
              "S_rel": 0.5, "S_stab": 0.5}
        result = scorer.compute(fv)
        expected = 0.35 * 0.5 + 0.30 * 0.5 + 0.20 * 0.5 + 0.10 * 0.5 + 0.05 * 0.5
        assert abs(result["S_composite"] - expected) < 1e-10

    def test_only_two_signals_present(self):
        """When only partial signals are available, result is partial."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.80, "S_dev": 0.60}
        result = scorer.compute(fv)
        # S_dist=0.0 default, S_rel=0.0 default, S_stab=0.5 default → inv=0.5
        expected = 0.35 * 0.80 + 0.30 * 0.0 + 0.20 * 0.60 + 0.10 * 0.0 + 0.05 * 0.5
        assert abs(result["S_composite"] - expected) < 1e-10


# ═══════════════════════════════════════════════════════════════════════════
# Category 3: CompositeScorer — Edge Cases & Invalid Input (14 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestCompositeEdgeCases:

    def test_empty_feature_vector(self):
        """Empty dict uses all defaults → should not crash."""
        scorer = CompositeScorer()
        result = scorer.compute({})
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_none_values(self):
        """None values should be handled gracefully."""
        scorer = CompositeScorer()
        fv = {"S_entropy": None, "S_dist": None, "S_dev": None,
              "S_rel": None, "S_stab": None}
        result = scorer.compute(fv)
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_string_values(self):
        """String values should be safely converted or defaulted."""
        scorer = CompositeScorer()
        fv = {"S_entropy": "0.5", "S_dist": "invalid", "S_dev": "0.3"}
        result = scorer.compute(fv)
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_negative_values_clamped(self):
        """Negative values should be clamped to 0.0."""
        scorer = CompositeScorer()
        fv = {"S_entropy": -0.5, "S_dist": -1.0, "S_dev": -2.0,
              "S_rel": -0.1, "S_stab": -0.5}
        result = scorer.compute(fv)
        assert result["S_composite"] >= 0.0
        assert result["signals"]["S_entropy"] == 0.0

    def test_over_one_values_clamped(self):
        """Values > 1.0 should be clamped to 1.0."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 2.5, "S_dist": 1.5, "S_dev": 3.0,
              "S_rel": 1.1, "S_stab": -0.5}
        result = scorer.compute(fv)
        assert result["S_composite"] <= 1.0
        assert result["signals"]["S_entropy"] == 1.0

    def test_nan_values(self):
        """NaN values should default gracefully."""
        scorer = CompositeScorer()
        fv = {"S_entropy": float("nan"), "S_dist": float("nan")}
        result = scorer.compute(fv)
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_inf_values(self):
        """Infinity values should default gracefully."""
        scorer = CompositeScorer()
        fv = {"S_entropy": float("inf"), "S_dist": float("-inf")}
        result = scorer.compute(fv)
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_clamp_helper_basic(self):
        """Test the _clamp helper function."""
        assert _clamp(0.5) == 0.5
        assert _clamp(-1.0) == 0.0
        assert _clamp(2.0) == 1.0
        assert _clamp(0.0) == 0.0
        assert _clamp(1.0) == 1.0

    def test_safe_float_helper(self):
        """Test the _safe_float helper."""
        assert _safe_float(None) == 0.0
        assert _safe_float("abc") == 0.0
        assert _safe_float("3.14") == 3.14
        assert _safe_float(42) == 42.0
        assert _safe_float(float("nan")) == 0.0

    def test_s_rel_absent_defaults_zero(self):
        """Missing S_rel should default to 0.0 (lineage not active)."""
        scorer = CompositeScorer()
        fv = {"S_entropy": 0.5, "S_dist": 0.3, "S_dev": 0.2, "S_stab": 0.7}
        result = scorer.compute(fv)
        assert result["signals"]["S_rel"] == 0.0

    def test_large_weight_sum_different_from_one(self):
        """Custom weights not summing to 1.0 should still work."""
        custom = {"S_entropy": 0.5, "S_dist": 0.5, "S_dev": 0.5,
                  "S_rel": 0.5, "S_stab": 0.5}
        scorer = CompositeScorer(weights=custom)
        fv = {"S_entropy": 1.0, "S_dist": 1.0, "S_dev": 1.0,
              "S_rel": 1.0, "S_stab": 0.0}
        result = scorer.compute(fv)
        # composite = 0.5*1 + 0.5*1 + 0.5*1 + 0.5*1 + 0.5*1 = 2.5 → clamped to 1.0
        assert result["S_composite"] == 1.0

    def test_zero_weight_for_entropy(self):
        """Zero weight on entropy means it has no influence."""
        custom = DEFAULT_WEIGHTS.copy()
        custom["S_entropy"] = 0.0
        scorer = CompositeScorer(weights=custom)
        fv1 = {"S_entropy": 0.0, "S_dist": 0.5, "S_dev": 0.5,
               "S_rel": 0.5, "S_stab": 0.5}
        fv2 = {"S_entropy": 1.0, "S_dist": 0.5, "S_dev": 0.5,
               "S_rel": 0.5, "S_stab": 0.5}
        r1 = scorer.compute(fv1)
        r2 = scorer.compute(fv2)
        assert abs(r1["S_composite"] - r2["S_composite"]) < 1e-10

    def test_boolean_values_handled(self):
        """Boolean values should be safely converted."""
        scorer = CompositeScorer()
        fv = {"S_entropy": True, "S_dist": False}
        result = scorer.compute(fv)
        assert 0.0 <= result["S_composite"] <= 1.0

    def test_extra_keys_ignored(self):
        """Extra keys in feature_vector should not cause errors."""
        scorer = CompositeScorer()
        fv = _benign_vector(extra_key="hello", another=42, nested={"a": 1})
        result = scorer.compute(fv)
        assert "S_composite" in result


# ═══════════════════════════════════════════════════════════════════════════
# Category 4: SigmoidEngine — Core Sigmoid Math (16 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestSigmoidMath:

    def test_default_parameters(self):
        """Verify default beta and theta match architecture."""
        assert DEFAULT_BETA == 15.0
        assert DEFAULT_THETA == 0.50

    def test_sigmoid_at_theta(self):
        """sigmoid(theta) should equal exactly 0.5."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        result = engine.compute_intent_drift(0.50, pid=1, timestamp=100.0)
        assert abs(result["IntentDrift"] - 0.5) < 1e-10

    def test_sigmoid_below_theta_suppressed(self):
        """Scores well below theta should produce drift near 0."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        result = engine.compute_intent_drift(0.10, pid=1, timestamp=100.0)
        assert result["IntentDrift"] < 0.02

    def test_sigmoid_above_theta_accelerated(self):
        """Scores well above theta should produce drift near 1."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        result = engine.compute_intent_drift(0.90, pid=1, timestamp=100.0)
        assert result["IntentDrift"] > 0.98

    def test_sigmoid_zero_input(self):
        """S_composite=0.0 → IntentDrift near 0."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        result = engine.compute_intent_drift(0.0, pid=1, timestamp=100.0)
        assert result["IntentDrift"] < 0.01

    def test_sigmoid_one_input(self):
        """S_composite=1.0 → IntentDrift near 1."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        result = engine.compute_intent_drift(1.0, pid=1, timestamp=100.0)
        assert result["IntentDrift"] > 0.99

    def test_sigmoid_monotonic(self):
        """Sigmoid should be monotonically increasing."""
        engine = SigmoidEngine()
        values = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        drifts = []
        for i, v in enumerate(values):
            r = engine.compute_intent_drift(v, pid=i + 100, timestamp=100.0)
            drifts.append(r["IntentDrift"])
        for i in range(len(drifts) - 1):
            assert drifts[i] <= drifts[i + 1]

    def test_higher_beta_steeper_transition(self):
        """Higher beta → sharper transition around theta."""
        engine_low = SigmoidEngine(beta=5.0, theta=0.50)
        engine_high = SigmoidEngine(beta=20.0, theta=0.50)
        # Above theta: higher beta → closer to 1.0
        r_low = engine_low.compute_intent_drift(0.6, pid=1, timestamp=100.0)
        r_high = engine_high.compute_intent_drift(0.6, pid=2, timestamp=100.0)
        assert r_high["IntentDrift"] > r_low["IntentDrift"]

    def test_lower_beta_gentler_transition(self):
        """Lower beta → more gradual transition."""
        engine = SigmoidEngine(beta=1.0, theta=0.50)
        r = engine.compute_intent_drift(0.6, pid=1, timestamp=100.0)
        assert 0.4 < r["IntentDrift"] < 0.7

    def test_theta_shift_changes_center(self):
        """Shifting theta should shift where the midpoint is."""
        engine = SigmoidEngine(beta=10.0, theta=0.30)
        r = engine.compute_intent_drift(0.30, pid=1, timestamp=100.0)
        assert abs(r["IntentDrift"] - 0.5) < 1e-10

    def test_sigmoid_symmetry_around_theta(self):
        """sigmoid(theta + d) + sigmoid(theta - d) ≈ 1.0."""
        engine = SigmoidEngine(beta=10.0, theta=0.50)
        r_above = engine.compute_intent_drift(0.65, pid=1, timestamp=100.0)
        r_below = engine.compute_intent_drift(0.35, pid=2, timestamp=100.0)
        assert abs(r_above["IntentDrift"] + r_below["IntentDrift"] - 1.0) < 1e-10

    def test_output_always_between_zero_and_one(self):
        """IntentDrift must always be in [0, 1]."""
        engine = SigmoidEngine()
        for v in [-1.0, 0.0, 0.25, 0.50, 0.75, 1.0, 2.0]:
            r = engine.compute_intent_drift(max(0, min(1, v)), pid=99, timestamp=100.0)
            assert 0.0 <= r["IntentDrift"] <= 1.0

    def test_negative_composite_clamped(self):
        """Negative S_composite clamped to 0 before sigmoid."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(-0.5, pid=1, timestamp=100.0)
        assert r["IntentDrift"] >= 0.0
        assert r["S_composite"] == 0.0

    def test_over_one_composite_clamped(self):
        """S_composite > 1 clamped to 1.0."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(1.5, pid=1, timestamp=100.0)
        assert r["S_composite"] == 1.0

    def test_very_large_beta_approaches_step_function(self):
        """Very large beta → near step function."""
        engine = SigmoidEngine(beta=100.0, theta=0.50)
        r_low = engine.compute_intent_drift(0.49, pid=1, timestamp=100.0)
        r_high = engine.compute_intent_drift(0.51, pid=2, timestamp=100.0)
        assert r_low["IntentDrift"] < 0.30
        assert r_high["IntentDrift"] > 0.70

    def test_very_small_beta_approaches_flat(self):
        """Very small beta → nearly flat around 0.5 everywhere."""
        engine = SigmoidEngine(beta=0.01, theta=0.50)
        r = engine.compute_intent_drift(0.90, pid=1, timestamp=100.0)
        assert 0.49 < r["IntentDrift"] < 0.51


# ═══════════════════════════════════════════════════════════════════════════
# Category 5: SigmoidEngine — Per-PID Drift Tracking (14 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestSigmoidDriftTracking:

    def test_first_observation_drift_rate_zero(self):
        """First event for a PID should have drift_rate = 0."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        assert r["drift_rate"] == 0.0
        assert r["is_first_observation"] is True

    def test_second_observation_has_drift_rate(self):
        """Second event should compute a non-zero drift_rate."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.3, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.7, pid=1, timestamp=101.0)
        assert r["drift_rate"] != 0.0
        assert r["is_first_observation"] is False

    def test_increasing_composite_positive_drift_rate(self):
        """Increasing S_composite over time → positive drift_rate."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.20, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.80, pid=1, timestamp=101.0)
        assert r["drift_rate"] > 0.0

    def test_decreasing_composite_negative_drift_rate(self):
        """Decreasing S_composite over time → negative drift_rate."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.80, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.20, pid=1, timestamp=101.0)
        assert r["drift_rate"] < 0.0

    def test_same_composite_zero_drift_rate(self):
        """Same S_composite → drift_rate ≈ 0."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.50, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.50, pid=1, timestamp=101.0)
        assert abs(r["drift_rate"]) < 1e-10

    def test_different_pids_independent(self):
        """Different PIDs should have independent drift histories."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.30, pid=1, timestamp=100.0)
        engine.compute_intent_drift(0.80, pid=2, timestamp=100.0)
        r1 = engine.compute_intent_drift(0.70, pid=1, timestamp=101.0)
        r2 = engine.compute_intent_drift(0.30, pid=2, timestamp=101.0)
        assert r1["drift_rate"] > 0
        assert r2["drift_rate"] < 0

    def test_reset_pid_clears_history(self):
        """reset_pid should clear drift history so next is first observation."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        engine.reset_pid(1)
        r = engine.compute_intent_drift(0.5, pid=1, timestamp=101.0)
        assert r["is_first_observation"] is True

    def test_get_pid_drift(self):
        """get_pid_drift should return last recorded values."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        pd = engine.get_pid_drift(1)
        assert pd is not None
        assert abs(pd[0] - 0.5) < 1e-10
        assert abs(pd[1] - 100.0) < 1e-10

    def test_get_pid_drift_nonexistent(self):
        """get_pid_drift for unknown PID returns None."""
        engine = SigmoidEngine()
        assert engine.get_pid_drift(99999) is None

    def test_get_tracked_pids(self):
        """get_tracked_pids returns all PIDs with history."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=100, timestamp=100.0)
        engine.compute_intent_drift(0.5, pid=200, timestamp=100.0)
        pids = engine.get_tracked_pids()
        assert 100 in pids
        assert 200 in pids
        assert len(pids) == 2

    def test_reset_all_clears_everything(self):
        """reset_all should remove all PID histories."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        engine.compute_intent_drift(0.5, pid=2, timestamp=100.0)
        engine.reset_all()
        assert len(engine.get_tracked_pids()) == 0

    def test_drift_rate_proportional_to_time_delta(self):
        """Larger dt should produce smaller drift_rate for same change."""
        engine1 = SigmoidEngine()
        engine1.compute_intent_drift(0.2, pid=1, timestamp=100.0)
        r_fast = engine1.compute_intent_drift(0.8, pid=1, timestamp=101.0)

        engine2 = SigmoidEngine()
        engine2.compute_intent_drift(0.2, pid=1, timestamp=100.0)
        r_slow = engine2.compute_intent_drift(0.8, pid=1, timestamp=110.0)

        assert abs(r_fast["drift_rate"]) > abs(r_slow["drift_rate"])

    def test_rapid_acceleration_high_drift_rate(self):
        """Rapid jump in S_composite with small dt → large drift_rate."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.10, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.90, pid=1, timestamp=100.01)
        assert r["drift_rate"] > 10.0  # Large positive rate

    def test_total_computed_counter(self):
        """Verify total_computed counter increments correctly."""
        engine = SigmoidEngine()
        assert engine.total_computed == 0
        engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        engine.compute_intent_drift(0.5, pid=2, timestamp=100.0)
        assert engine.total_computed == 2


# ═══════════════════════════════════════════════════════════════════════════
# Category 6: SigmoidEngine — Edge Cases & Invalid (12 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestSigmoidEdgeCases:

    def test_invalid_beta_raises(self):
        """beta <= 0 should raise ValueError."""
        with pytest.raises(ValueError):
            SigmoidEngine(beta=0.0)
        with pytest.raises(ValueError):
            SigmoidEngine(beta=-1.0)

    def test_invalid_theta_raises(self):
        """theta outside [0, 1] should raise ValueError."""
        with pytest.raises(ValueError):
            SigmoidEngine(theta=-0.1)
        with pytest.raises(ValueError):
            SigmoidEngine(theta=1.1)

    def test_theta_at_zero(self):
        """theta=0 → any positive S_composite → high drift."""
        engine = SigmoidEngine(beta=10.0, theta=0.0)
        r = engine.compute_intent_drift(0.10, pid=1, timestamp=100.0)
        assert r["IntentDrift"] > 0.7

    def test_theta_at_one(self):
        """theta=1.0 → almost everything suppressed."""
        engine = SigmoidEngine(beta=10.0, theta=1.0)
        r = engine.compute_intent_drift(0.90, pid=1, timestamp=100.0)
        assert r["IntentDrift"] < 0.30

    def test_timestamp_default_uses_system_time(self):
        """If timestamp is None, should use time.time()."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(0.5, pid=1)
        assert r["timestamp"] > 0

    def test_same_timestamp_no_division_error(self):
        """Two events at same timestamp should not cause division by zero."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.3, pid=1, timestamp=100.0)
        r = engine.compute_intent_drift(0.7, pid=1, timestamp=100.0)
        # dt = 0, drift_rate should be 0 (guarded)
        assert r["drift_rate"] == 0.0

    def test_negative_pid(self):
        """Negative PID (-1) should work without errors."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(0.5, pid=-1, timestamp=100.0)
        assert "IntentDrift" in r

    def test_zero_pid(self):
        """PID=0 should work without errors."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(0.5, pid=0, timestamp=100.0)
        assert "IntentDrift" in r

    def test_very_large_pid(self):
        """Very large PID should work."""
        engine = SigmoidEngine()
        r = engine.compute_intent_drift(0.5, pid=999999999, timestamp=100.0)
        assert "IntentDrift" in r

    def test_overflow_protection_high_exponent(self):
        """Very high beta with low S_composite should not overflow."""
        engine = SigmoidEngine(beta=500.0, theta=0.5)
        r = engine.compute_intent_drift(0.0, pid=1, timestamp=100.0)
        assert r["IntentDrift"] == 0.0

    def test_overflow_protection_low_exponent(self):
        """Very high beta with high S_composite should not overflow."""
        engine = SigmoidEngine(beta=500.0, theta=0.5)
        r = engine.compute_intent_drift(1.0, pid=1, timestamp=100.0)
        assert r["IntentDrift"] == 1.0

    def test_repr_string(self):
        """Verify repr includes useful info."""
        engine = SigmoidEngine()
        s = repr(engine)
        assert "SigmoidEngine" in s
        assert "beta=" in s


# ═══════════════════════════════════════════════════════════════════════════
# Category 7: ThreatFusion — Core Fusion Pipeline (16 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestThreatFusionCore:

    def test_benign_produces_benign_tier(self):
        """Benign feature vector → BENIGN tier."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector())
        assert result["threat_tier"] == "BENIGN"

    def test_ransomware_produces_critical_tier(self):
        """Ransomware feature vector → CRITICAL tier."""
        fusion = ThreatFusion()
        result = fusion.fuse(_ransomware_vector())
        assert result["threat_tier"] == "CRITICAL"

    def test_archiver_suppressed(self):
        """7-Zip (entropy-only high) → should NOT be CRITICAL."""
        fusion = ThreatFusion()
        result = fusion.fuse(_archiver_vector())
        assert result["threat_tier"] in ("BENIGN", "ELEVATED")

    def test_output_has_all_required_keys(self):
        """Verify all architecture-specified output keys are present."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(), {"anomaly_score": 0.3, "risk_tier": "WATCH"})
        required_keys = [
            "S_composite", "IntentDrift", "drift_rate", "threat_tier",
            "signals", "anomaly_score", "risk_tier_s5", "pid",
            "file_path", "timestamp",
        ]
        for k in required_keys:
            assert k in result, f"Missing key: {k}"

    def test_anomaly_score_passthrough(self):
        """Stage 5 anomaly_score should be passed through unchanged."""
        fusion = ThreatFusion()
        ar = {"anomaly_score": 0.789, "risk_tier": "SUSPECT"}
        result = fusion.fuse(_benign_vector(), ar)
        assert result["anomaly_score"] == 0.789
        assert result["risk_tier_s5"] == "SUSPECT"

    def test_none_anomaly_result(self):
        """None anomaly_result should default gracefully."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(), None)
        assert result["anomaly_score"] == 0.0

    def test_pid_passthrough(self):
        """PID should be passed through to output."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(pid=12345))
        assert result["pid"] == 12345

    def test_file_path_passthrough(self):
        """file_path should be passed through to output."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(file_path="/test/file.txt"))
        assert result["file_path"] == "/test/file.txt"

    def test_timestamp_passthrough(self):
        """timestamp should be passed through to output."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(timestamp=1234567890000.0))
        assert result["timestamp"] == 1234567890000.0

    def test_s_composite_range(self):
        """S_composite must be in [0, 1]."""
        fusion = ThreatFusion()
        for fn in [_benign_vector, _ransomware_vector, _archiver_vector]:
            result = fusion.fuse(fn())
            assert 0.0 <= result["S_composite"] <= 1.0

    def test_intent_drift_range(self):
        """IntentDrift must be in [0, 1]."""
        fusion = ThreatFusion()
        for fn in [_benign_vector, _ransomware_vector, _archiver_vector]:
            result = fusion.fuse(fn())
            assert 0.0 <= result["IntentDrift"] <= 1.0

    def test_signals_dict_present(self):
        """signals dict should contain all 5 sub-signals."""
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector())
        assert "S_entropy" in result["signals"]
        assert "S_stab_inv" in result["signals"]

    def test_first_observation_flag(self):
        """First event for a PID should flag is_first_observation."""
        fusion = ThreatFusion()
        r = fusion.fuse(_benign_vector(pid=7777))
        assert r["is_first_observation"] is True

    def test_second_observation_not_first(self):
        """Second event for same PID → not first observation."""
        fusion = ThreatFusion()
        fusion.fuse(_benign_vector(pid=7777, timestamp=1700000000000.0))
        r = fusion.fuse(_benign_vector(pid=7777, timestamp=1700000001000.0))
        assert r["is_first_observation"] is False

    def test_custom_beta_theta(self):
        """Custom beta/theta should be honoured."""
        fusion = ThreatFusion(beta=5.0, theta=0.30)
        assert fusion.sigmoid.beta == 5.0
        assert fusion.sigmoid.theta == 0.30

    def test_custom_composite_weights(self):
        """Custom composite weights should be honoured."""
        custom = {"S_entropy": 0.50, "S_dist": 0.50, "S_dev": 0.0,
                  "S_rel": 0.0, "S_stab": 0.0}
        fusion = ThreatFusion(composite_weights=custom)
        assert fusion.composite.weights["S_entropy"] == 0.50


# ═══════════════════════════════════════════════════════════════════════════
# Category 8: ThreatFusion — Threat Tier Classification (12 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestThreatTiers:

    def test_tier_benign_threshold(self):
        """IntentDrift < 0.10 → BENIGN."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.05) == "BENIGN"

    def test_tier_benign_boundary(self):
        """IntentDrift exactly 0.0 → BENIGN."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.0) == "BENIGN"

    def test_tier_elevated_lower(self):
        """IntentDrift = 0.10 → ELEVATED (boundary inclusive)."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.10) == "ELEVATED"

    def test_tier_elevated_middle(self):
        """IntentDrift = 0.25 → ELEVATED."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.25) == "ELEVATED"

    def test_tier_high_lower(self):
        """IntentDrift = 0.40 → HIGH (boundary inclusive)."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.40) == "HIGH"

    def test_tier_high_middle(self):
        """IntentDrift = 0.60 → HIGH."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.60) == "HIGH"

    def test_tier_critical_lower(self):
        """IntentDrift = 0.75 → CRITICAL (boundary inclusive)."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.75) == "CRITICAL"

    def test_tier_critical_high(self):
        """IntentDrift = 0.99 → CRITICAL."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(0.99) == "CRITICAL"

    def test_tier_critical_max(self):
        """IntentDrift = 1.0 → CRITICAL."""
        fusion = ThreatFusion()
        assert fusion._assign_threat_tier(1.0) == "CRITICAL"

    def test_custom_thresholds(self):
        """Custom thresholds should be respected."""
        fusion = ThreatFusion(tier_thresholds={"BENIGN": 0.20, "ELEVATED": 0.60, "HIGH": 0.90})
        assert fusion._assign_threat_tier(0.15) == "BENIGN"
        assert fusion._assign_threat_tier(0.40) == "ELEVATED"
        assert fusion._assign_threat_tier(0.80) == "HIGH"
        assert fusion._assign_threat_tier(0.95) == "CRITICAL"

    def test_default_tier_thresholds_match_architecture(self):
        """Verify default tier thresholds match architecture spec."""
        assert DEFAULT_TIER_THRESHOLDS["BENIGN"] == 0.10
        assert DEFAULT_TIER_THRESHOLDS["ELEVATED"] == 0.40
        assert DEFAULT_TIER_THRESHOLDS["HIGH"] == 0.75

    def test_package_level_threat_tiers(self):
        """Package-level THREAT_TIERS should be consistent."""
        assert THREAT_TIERS["BENIGN"] == 0.10
        assert THREAT_TIERS["ELEVATED"] == 0.40
        assert THREAT_TIERS["HIGH"] == 0.75
        assert THREAT_TIERS["CRITICAL"] == 1.0


# ═══════════════════════════════════════════════════════════════════════════
# Category 9: ThreatFusion — Batch & Stateful Behaviour (10 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestThreatFusionStateful:

    def test_batch_processing(self):
        """fuse_batch should process multiple events."""
        fusion = ThreatFusion()
        events = [
            {"feature_vector": _benign_vector(pid=1, timestamp=1700000000000.0)},
            {"feature_vector": _ransomware_vector(pid=2, timestamp=1700000001000.0)},
        ]
        results = fusion.fuse_batch(events)
        assert len(results) == 2
        assert results[0]["threat_tier"] == "BENIGN"
        assert results[1]["threat_tier"] == "CRITICAL"

    def test_batch_with_anomaly_results(self):
        """fuse_batch with anomaly_result dicts."""
        fusion = ThreatFusion()
        events = [
            {"feature_vector": _benign_vector(), "anomaly_result": {"anomaly_score": 0.1}},
            {"feature_vector": _ransomware_vector(), "anomaly_result": {"anomaly_score": 0.9}},
        ]
        results = fusion.fuse_batch(events)
        assert results[0]["anomaly_score"] == 0.1
        assert results[1]["anomaly_score"] == 0.9

    def test_escalation_sequence(self):
        """Gradually increasing signals should escalate through tiers."""
        fusion = ThreatFusion()
        tiers_seen = set()
        for i in range(20):
            s_ent = i * 0.05
            fv = _benign_vector(
                S_entropy=s_ent, S_dist=s_ent * 0.8,
                S_dev=s_ent * 0.6, S_stab=max(0, 1.0 - s_ent),
                pid=5000, timestamp=1700000000000.0 + i * 1000.0,
            )
            r = fusion.fuse(fv)
            tiers_seen.add(r["threat_tier"])
        assert "BENIGN" in tiers_seen
        assert "CRITICAL" in tiers_seen

    def test_pid_state_accumulates(self):
        """Repeated events for same PID should track drift history."""
        fusion = ThreatFusion()
        fusion.fuse(_benign_vector(pid=8000, timestamp=1700000000000.0))
        r = fusion.fuse(_ransomware_vector(pid=8000, timestamp=1700000001000.0))
        assert r["drift_rate"] > 0.0

    def test_reset_pid(self):
        """reset_pid should clear PID state."""
        fusion = ThreatFusion()
        fusion.fuse(_benign_vector(pid=8001, timestamp=1700000000000.0))
        fusion.reset_pid(8001)
        r = fusion.fuse(_benign_vector(pid=8001, timestamp=1700000001000.0))
        assert r["is_first_observation"] is True

    def test_reset_all(self):
        """reset_all should clear all state and counters."""
        fusion = ThreatFusion()
        fusion.fuse(_benign_vector(pid=1))
        fusion.fuse(_ransomware_vector(pid=2))
        fusion.reset_all()
        stats = fusion.get_stats()
        assert stats["total_fused"] == 0
        assert stats["pids_tracked"] == 0

    def test_monotonic_drift_escalation_for_same_pid(self):
        """Steadily increasing composite → monotonically increasing drift."""
        fusion = ThreatFusion()
        prev_drift = -1.0
        for i in range(10):
            s = 0.1 * (i + 1)
            fv = _benign_vector(
                S_entropy=s, S_dist=s, S_dev=s, S_stab=1.0 - s,
                pid=6000, timestamp=1700000000000.0 + i * 1000.0,
            )
            r = fusion.fuse(fv)
            assert r["IntentDrift"] >= prev_drift - 1e-10
            prev_drift = r["IntentDrift"]

    def test_deescalation_sequence(self):
        """Decreasing signals after escalation should lower tier."""
        fusion = ThreatFusion()
        # First: ransomware-level
        r_high = fusion.fuse(_ransomware_vector(pid=7000, timestamp=1700000000000.0))
        # Then: benign-level
        r_low = fusion.fuse(_benign_vector(pid=7000, timestamp=1700000001000.0))
        assert r_low["IntentDrift"] < r_high["IntentDrift"]

    def test_empty_batch(self):
        """Empty batch should return empty list."""
        fusion = ThreatFusion()
        results = fusion.fuse_batch([])
        assert results == []

    def test_batch_preserves_order(self):
        """Results should be in same order as inputs."""
        fusion = ThreatFusion()
        events = [
            {"feature_vector": _benign_vector(pid=100 + i, timestamp=1700000000000.0 + i * 1000.0)}
            for i in range(5)
        ]
        results = fusion.fuse_batch(events)
        for i, r in enumerate(results):
            assert r["pid"] == 100 + i


# ═══════════════════════════════════════════════════════════════════════════
# Category 10: ThreatFusion — Thread Safety & Concurrency (6 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestThreatFusionConcurrency:

    def test_concurrent_scoring_no_errors(self):
        """Multiple threads scoring simultaneously should not raise."""
        fusion = ThreatFusion()
        errors = []

        def worker(thread_id):
            try:
                for i in range(50):
                    fv = _benign_vector(pid=thread_id * 1000 + i,
                                        timestamp=1700000000000.0 + i * 1000.0)
                    fusion.fuse(fv)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert fusion.total_fused >= 200

    def test_concurrent_mixed_benign_ransomware(self):
        """Concurrent benign + ransomware scoring should not crash."""
        fusion = ThreatFusion()
        errors = []

        def benign_worker():
            try:
                for i in range(50):
                    fusion.fuse(_benign_vector(pid=1000 + i, timestamp=1700000000000.0 + i * 1000.0))
            except Exception as e:
                errors.append(e)

        def ransomware_worker():
            try:
                for i in range(50):
                    fusion.fuse(_ransomware_vector(pid=9000 + i, timestamp=1700000000000.0 + i * 1000.0))
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=benign_worker)
        t2 = threading.Thread(target=ransomware_worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0

    def test_concurrent_same_pid(self):
        """Concurrent events for same PID should not corrupt state."""
        fusion = ThreatFusion()
        errors = []

        def worker(offset):
            try:
                for i in range(50):
                    fv = _moderate_vector(pid=5555, timestamp=1700000000000.0 + offset + i * 100.0)
                    fusion.fuse(fv)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t * 50000,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    def test_concurrent_reset_and_fuse(self):
        """Resetting while fusing should not crash."""
        fusion = ThreatFusion()
        errors = []

        def fuse_worker():
            try:
                for i in range(50):
                    fusion.fuse(_benign_vector(pid=i, timestamp=1700000000000.0 + i * 1000.0))
            except Exception as e:
                errors.append(e)

        def reset_worker():
            try:
                for i in range(50):
                    fusion.reset_pid(i)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=fuse_worker)
        t2 = threading.Thread(target=reset_worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert len(errors) == 0

    def test_stats_consistent_after_concurrent(self):
        """Stats total should reflect all processed events."""
        fusion = ThreatFusion()

        def worker(thread_id):
            for i in range(25):
                fusion.fuse(_benign_vector(pid=thread_id * 100 + i,
                                           timestamp=1700000000000.0 + i * 1000.0))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = fusion.get_stats()
        assert stats["total_fused"] == 100

    def test_concurrent_batch(self):
        """Concurrent fuse_batch should not crash."""
        fusion = ThreatFusion()
        errors = []

        def worker(thread_id):
            try:
                events = [
                    {"feature_vector": _benign_vector(pid=thread_id * 100 + i,
                                                      timestamp=1700000000000.0 + i * 1000.0)}
                    for i in range(25)
                ]
                fusion.fuse_batch(events)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Category 11: Integration — Stage 4 → 5 → 6 Pipeline (14 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegration:

    def test_stage4_vector_compatible_with_stage6(self):
        """Stage 4 feature vector format should be directly usable by Stage 6."""
        # Simulate a Stage 4 output dict
        stage4_output = {
            "S_entropy": 0.30, "S_ETD": 0.20, "S_dist": 0.10,
            "S_dev": 0.05, "S_stab": 0.80, "lambda_norm": 0.03,
            "branching_n": 0.625, "is_superheated": False,
            "entropy_raw": 2.4, "delta_H": 0.5,
            "pid": 1234, "file_path": "C:\\test.txt",
            "operation": "FILE_MODIFY", "timestamp": 1700000000000.0,
        }
        fusion = ThreatFusion()
        result = fusion.fuse(stage4_output)
        assert result["threat_tier"] in ("BENIGN", "ELEVATED", "HIGH", "CRITICAL")

    def test_stage5_result_compatible_with_stage6(self):
        """Stage 5 anomaly result format should be usable by Stage 6."""
        stage5_result = {
            "anomaly_score": 0.35, "isolation_score": 0.40,
            "svm_score": 0.30, "confidence": 0.70,
            "risk_tier": "WATCH", "is_anomaly": True,
            "scoring_mode": "ml", "dimension_matched": True,
        }
        fusion = ThreatFusion()
        result = fusion.fuse(_benign_vector(), stage5_result)
        assert result["anomaly_score"] == 0.35
        assert result["risk_tier_s5"] == "WATCH"

    def test_full_pipeline_benign_scenario(self):
        """Full S4→S5→S6 pipeline: benign → BENIGN."""
        stage4_fv = {
            "S_entropy": 0.15, "S_ETD": 0.10, "S_dist": 0.03,
            "S_dev": 0.02, "S_stab": 0.90, "lambda_norm": 0.01,
            "branching_n": 0.625,
            "pid": 1000, "timestamp": 1700000000000.0,
        }
        stage5_ar = {"anomaly_score": 0.10, "risk_tier": "SAFE"}
        fusion = ThreatFusion()
        result = fusion.fuse(stage4_fv, stage5_ar)
        assert result["threat_tier"] == "BENIGN"
        assert result["IntentDrift"] < 0.10

    def test_full_pipeline_ransomware_scenario(self):
        """Full S4→S5→S6 pipeline: ransomware → CRITICAL."""
        stage4_fv = {
            "S_entropy": 0.97, "S_ETD": 0.85, "S_dist": 0.90,
            "S_dev": 0.88, "S_stab": 0.05, "lambda_norm": 0.95,
            "branching_n": 1.5, "S_rel": 0.85,
            "pid": 9999, "timestamp": 1700000001000.0,
        }
        stage5_ar = {"anomaly_score": 0.90, "risk_tier": "CRITICAL"}
        fusion = ThreatFusion()
        result = fusion.fuse(stage4_fv, stage5_ar)
        assert result["threat_tier"] == "CRITICAL"
        assert result["IntentDrift"] > 0.90

    def test_full_pipeline_archiver_scenario(self):
        """Full S4→S5→S6 pipeline: 7-Zip → NOT CRITICAL."""
        stage4_fv = {
            "S_entropy": 0.95, "S_ETD": 0.25, "S_dist": 0.02,
            "S_dev": 0.01, "S_stab": 0.92, "lambda_norm": 0.03,
            "branching_n": 0.625,
            "pid": 2000, "timestamp": 1700000002000.0,
        }
        stage5_ar = {"anomaly_score": 0.45, "risk_tier": "WATCH"}
        fusion = ThreatFusion()
        result = fusion.fuse(stage4_fv, stage5_ar)
        assert result["threat_tier"] in ("BENIGN", "ELEVATED")

    def test_live_pipeline_import_chain(self):
        """Verify import chain works: Stage3 → Stage4 → Stage5 → Stage6."""
        from src.stage_3_dbrg.dbrg_manager import DBRGManager
        from src.stage_4_features.feature_extractor import FeatureExtractor
        from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer

        dbrg = DBRGManager()
        extractor = FeatureExtractor(dbrg_manager=dbrg)
        scorer = AnomalyScorer(model_dir="nonexistent_test_dir")
        fusion = ThreatFusion()

        ecar = {
            "actorID": "pid:1234", "objectID": "file:C:\\test.txt",
            "pid": 1234, "operation": "FILE_MODIFY",
            "timestamp": 1700000000000.0, "entropy": 3.0,
        }
        dbrg.process_event(ecar)
        fv = extractor.extract_features(ecar)
        assert fv is not None
        anomaly = scorer.score(fv)
        result = fusion.fuse(fv, anomaly)
        assert "IntentDrift" in result

    def test_s_composite_independent_of_anomaly_score(self):
        """S_composite should NOT use Stage 5 anomaly_score (arch constraint)."""
        fusion = ThreatFusion()
        fv = _moderate_vector()
        r1 = fusion.fuse(fv, {"anomaly_score": 0.10})
        fusion.reset_all()
        r2 = fusion.fuse(fv, {"anomaly_score": 0.90})
        assert abs(r1["S_composite"] - r2["S_composite"]) < 1e-10

    def test_timestamps_in_milliseconds(self):
        """Pipeline handles timestamps in ms (> 1e12)."""
        fusion = ThreatFusion()
        fv = _benign_vector(timestamp=1700000000123.0)
        result = fusion.fuse(fv)
        assert result["timestamp"] == 1700000000123.0

    def test_timestamps_in_seconds(self):
        """Pipeline handles timestamps in seconds (< 1e12)."""
        fusion = ThreatFusion()
        fv = _benign_vector(timestamp=1700000000.123)
        result = fusion.fuse(fv)
        assert result["timestamp"] == 1700000000.123

    def test_string_pid_handled(self):
        """String PID should be converted to int."""
        fusion = ThreatFusion()
        fv = _benign_vector(pid="1234")
        result = fusion.fuse(fv)
        assert result["pid"] == 1234

    def test_invalid_pid_defaults(self):
        """Non-convertible PID should default to -1."""
        fusion = ThreatFusion()
        fv = _benign_vector(pid="not_a_number")
        result = fusion.fuse(fv)
        assert result["pid"] == -1

    def test_missing_pid_defaults(self):
        """Missing PID should default to -1."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.3, "S_dist": 0.1}
        result = fusion.fuse(fv)
        assert result["pid"] == -1

    def test_missing_timestamp_gets_default(self):
        """Missing timestamp should get a reasonable default."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.3, "S_dist": 0.1, "pid": 100}
        result = fusion.fuse(fv)
        assert result["timestamp"] > 0

    def test_batch_with_direct_feature_vectors(self):
        """fuse_batch should accept bare feature vectors without wrapping."""
        fusion = ThreatFusion()
        events = [
            _benign_vector(pid=100 + i, timestamp=1700000000000.0 + i * 1000.0)
            for i in range(5)
        ]
        results = fusion.fuse_batch(events)
        assert len(results) == 5


# ═══════════════════════════════════════════════════════════════════════════
# Category 12: Verification Criteria & Architecture Compliance (16 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestVerificationCriteria:
    """
    Tests directly from the architecture specification's verification criteria:
    "Single high feature produces IntentDrift < 0.10 while multi-signal attacks
     produce IntentDrift > 0.90."
    """

    def test_arch_criterion_single_entropy_suppressed(self):
        """ARCH VERIFICATION: Pure high entropy → IntentDrift < 0.10."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 1.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] < 0.10, (
            f"ARCH VIOLATION: Single entropy spike → IntentDrift={result['IntentDrift']:.4f} "
            f"(must be < 0.10)")

    def test_arch_criterion_single_dist_suppressed(self):
        """ARCH VERIFICATION: Pure high S_dist → IntentDrift < 0.10."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.0, "S_dist": 1.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] < 0.10

    def test_arch_criterion_single_dev_suppressed(self):
        """ARCH VERIFICATION: Pure high S_dev → IntentDrift < 0.10."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 1.0,
              "S_rel": 0.0, "S_stab": 1.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] < 0.10

    def test_arch_criterion_single_rel_suppressed(self):
        """ARCH VERIFICATION: Pure high S_rel → IntentDrift < 0.10."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 1.0, "S_stab": 1.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] < 0.10

    def test_arch_criterion_single_stab_suppressed(self):
        """ARCH VERIFICATION: Pure low stability → IntentDrift < 0.10."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.0, "S_dist": 0.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 0.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] < 0.10

    def test_arch_criterion_multi_signal_convergence(self):
        """ARCH VERIFICATION: All signals high → IntentDrift > 0.90."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.95, "S_dist": 0.90, "S_dev": 0.85,
              "S_rel": 0.80, "S_stab": 0.05,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["IntentDrift"] > 0.90, (
            f"ARCH VIOLATION: Multi-signal convergence → IntentDrift={result['IntentDrift']:.4f} "
            f"(must be > 0.90)")

    def test_arch_7zip_not_false_positive(self):
        """ARCH: 7-Zip compression (entropy only) → NOT CRITICAL."""
        fusion = ThreatFusion()
        fv = _archiver_vector()
        result = fusion.fuse(fv)
        assert result["threat_tier"] != "CRITICAL", (
            f"ARCH VIOLATION: 7-Zip triggered CRITICAL (IntentDrift={result['IntentDrift']:.4f})")

    def test_arch_notepad_benign(self):
        """ARCH: Notepad editing → BENIGN."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.10, "S_dist": 0.02, "S_dev": 0.01,
              "S_stab": 0.95, "S_rel": 0.05,
              "pid": 1500, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["threat_tier"] == "BENIGN"

    def test_arch_compiler_not_critical(self):
        """ARCH: Compiler (moderate entropy/d_out) → NOT CRITICAL."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.60, "S_dist": 0.20, "S_dev": 0.15,
              "S_stab": 0.70, "S_rel": 0.10,
              "pid": 1600, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        assert result["threat_tier"] != "CRITICAL"

    def test_arch_ransomware_detection_confidence(self):
        """ARCH: Ransomware-like multi-signal → high IntentDrift with CRITICAL tier."""
        fusion = ThreatFusion()
        result = fusion.fuse(_ransomware_vector())
        assert result["IntentDrift"] > 0.90
        assert result["threat_tier"] == "CRITICAL"

    def test_arch_formula_s_composite(self):
        """ARCH: Verify S_composite formula exactly matches specification."""
        fusion = ThreatFusion()
        fv = {"S_entropy": 0.8, "S_dist": 0.6, "S_dev": 0.4,
              "S_rel": 0.2, "S_stab": 0.3,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        expected = 0.35 * 0.8 + 0.30 * 0.6 + 0.20 * 0.4 + 0.10 * 0.2 + 0.05 * (1 - 0.3)
        assert abs(result["S_composite"] - expected) < 1e-10

    def test_arch_formula_sigmoid(self):
        """ARCH: Verify sigmoid formula exactly matches specification."""
        fusion = ThreatFusion()
        s_comp = 0.65
        expected_drift = 1.0 / (1.0 + math.exp(-fusion.sigmoid.beta * (s_comp - 0.50)))
        # Build feature vector that produces s_comp ≈ 0.65
        fv = {"S_entropy": 1.0, "S_dist": 1.0, "S_dev": 0.0,
              "S_rel": 0.0, "S_stab": 1.0,
              "pid": 1, "timestamp": 1700000000000.0}
        result = fusion.fuse(fv)
        # s_comp should be 0.35 + 0.30 = 0.65
        assert abs(result["S_composite"] - 0.65) < 1e-10
        assert abs(result["IntentDrift"] - expected_drift) < 1e-10

    def test_arch_weights_sum_exactly_one(self):
        """ARCH: Composite weights must sum to exactly 1.0."""
        total = sum(COMPOSITE_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-10

    def test_arch_beta_default_ten(self):
        """ARCH: Default beta must match DEFAULT_BETA."""
        engine = SigmoidEngine()
        assert engine.beta == DEFAULT_BETA

    def test_arch_theta_default_half(self):
        """ARCH: Default theta must be 0.50 per specification."""
        engine = SigmoidEngine()
        assert engine.theta == 0.50

    def test_arch_stage6_version(self):
        """ARCH: Stage 6 version should be defined."""
        from src.stage_6_fusion import __version__, __stage__
        assert __version__ == "1.0.0"
        assert "Stage 6" in __stage__


# ═══════════════════════════════════════════════════════════════════════════
# Category 13: Statistics, Reset & Lifecycle (8 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestStatisticsAndLifecycle:

    def test_initial_stats(self):
        """Initial stats should all be zero."""
        fusion = ThreatFusion()
        stats = fusion.get_stats()
        assert stats["total_fused"] == 0
        assert stats["total_benign"] == 0
        assert stats["total_critical"] == 0
        assert stats["critical_rate"] == 0.0

    def test_stats_after_benign(self):
        """Stats should count benign events."""
        fusion = ThreatFusion()
        fusion.fuse(_benign_vector())
        stats = fusion.get_stats()
        assert stats["total_fused"] == 1
        assert stats["total_benign"] == 1

    def test_stats_after_critical(self):
        """Stats should count critical events."""
        fusion = ThreatFusion()
        fusion.fuse(_ransomware_vector())
        stats = fusion.get_stats()
        assert stats["total_critical"] == 1

    def test_critical_rate_calculation(self):
        """Critical rate = total_critical / total_fused."""
        fusion = ThreatFusion()
        fusion.fuse(_ransomware_vector(pid=1, timestamp=1700000000000.0))
        fusion.fuse(_benign_vector(pid=2, timestamp=1700000001000.0))
        stats = fusion.get_stats()
        assert stats["critical_rate"] == 0.5

    def test_stats_contains_sigmoid_params(self):
        """Stats should report sigmoid parameters."""
        fusion = ThreatFusion(beta=15.0, theta=0.60)
        stats = fusion.get_stats()
        assert stats["sigmoid_beta"] == 15.0
        assert stats["sigmoid_theta"] == 0.60

    def test_stats_contains_weight_sum(self):
        """Stats should report composite weight sum."""
        fusion = ThreatFusion()
        stats = fusion.get_stats()
        assert abs(stats["composite_weight_sum"] - 1.0) < 1e-10

    def test_repr_string(self):
        """ThreatFusion repr should contain useful info."""
        fusion = ThreatFusion()
        s = repr(fusion)
        assert "ThreatFusion" in s
        assert "beta=" in s

    def test_sigmoid_get_stats(self):
        """SigmoidEngine.get_stats should return useful info."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=1, timestamp=100.0)
        stats = engine.get_stats()
        assert stats["beta"] == DEFAULT_BETA
        assert stats["total_computed"] == 1
        assert stats["pids_tracked"] == 1

    def test_prune_stale_pids_sigmoid(self):
        """Pruning stale PIDs should evict inactive processes and retain active ones."""
        engine = SigmoidEngine()
        engine.compute_intent_drift(0.5, pid=100, timestamp=100.0)  # old
        engine.compute_intent_drift(0.5, pid=200, timestamp=150.0)  # active
        evicted = engine.prune_stale_pids(max_age_seconds=30.0, current_time=160.0)
        assert evicted == 1
        pids = engine.get_tracked_pids()
        assert 100 not in pids
        assert 200 in pids

    def test_prune_stale_pids_fusion(self):
        """ThreatFusion.prune_stale_pids should delegate cleanly to sigmoid engine."""
        fusion = ThreatFusion()
        fusion.fuse({"S_entropy": 0.5, "pid": 10, "timestamp": 1000.0})
        fusion.fuse({"S_entropy": 0.5, "pid": 20, "timestamp": 1050.0})
        evicted = fusion.prune_stale_pids(max_age_seconds=20.0, current_time=1060.0)
        assert evicted == 1
        assert fusion.get_stats()["pids_tracked"] == 1
