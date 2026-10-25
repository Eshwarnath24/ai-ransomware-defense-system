"""
src/stage_6_fusion/__init__.py
==================================
Stage 6 — Multi-Signal Corroboration & Sigmoidal Acceleration Engine

This package fuses independent threat sub-signals from Stage 4 (Feature
Extraction) and Stage 5 (Anomaly Scoring) using priority weighting and
transforms the result through a non-linear sigmoid to suppress single-
feature false positives while rapidly accelerating multi-signal threats.

Architecture:
    1. CompositeScorer   — Priority-weighted causality fusion of 5 sub-signals
    2. SigmoidEngine     — Logistic sigmoidal acceleration with per-PID drift tracking
    3. ThreatFusion      — Main orchestrator consumed by Stage 7 (Trust State Engine)

Pipeline:
    Stage 4 FeatureVector + Stage 5 AnomalyResult
        -> ThreatFusion.fuse(feature_vector, anomaly_result)
            -> { S_composite, IntentDrift, drift_rate, threat_tier }
                -> feeds Stage 7 (Dynamic Adaptive Trust Evolution)

Mathematical Foundation:
    Composite Score:
        S_composite = (0.35 * S_entropy) + (0.30 * S_dist) + (0.20 * S_dev)
                    + (0.10 * S_rel) + (0.05 * (1 - S_stab))

    Sigmoidal Acceleration:
        IntentDrift(t) = 1 / (1 + exp(-beta * (S_composite - theta)))

    Acceleration Rate:
        d(Drift)/dt = [IntentDrift(t) - IntentDrift(t-dt)] / dt

Verification Criterion:
    Single high feature (e.g., pure compression) → IntentDrift < 0.10
    Multi-signal convergence (ransomware) → IntentDrift > 0.90

Exports
-------
ThreatFusion     — Main orchestrator class (consumed by Stage 7).
CompositeScorer  — Priority-weighted signal fusion engine.
SigmoidEngine    — Logistic sigmoidal acceleration with drift tracking.
COMPOSITE_WEIGHTS — Default signal priority weights dict.
THREAT_TIERS     — Tier threshold mapping.
"""

__version__ = "1.0.0"
__stage__ = "Stage 6: Multi-Signal Corroboration & Sigmoidal Acceleration"

from src.stage_6_fusion.composite_scorer import CompositeScorer
from src.stage_6_fusion.sigmoid_engine import SigmoidEngine
from src.stage_6_fusion.threat_fusion import ThreatFusion

# Default composite signal weights from architecture specification
COMPOSITE_WEIGHTS = {
    "S_entropy": 0.35,
    "S_dist": 0.30,
    "S_dev": 0.20,
    "S_rel": 0.10,
    "S_stab": 0.05,
}

# Threat tier thresholds (upper bounds for each tier)
THREAT_TIERS = {
    "BENIGN": 0.10,
    "ELEVATED": 0.40,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}

__all__ = [
    "ThreatFusion",
    "CompositeScorer",
    "SigmoidEngine",
    "COMPOSITE_WEIGHTS",
    "THREAT_TIERS",
]
