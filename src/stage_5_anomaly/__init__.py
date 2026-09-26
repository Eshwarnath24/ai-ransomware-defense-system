"""
src/stage_5_anomaly/__init__.py
==================================
Stage 5 — Anomaly Scoring & Benign Profiling (DAC-OCF)

This package implements the Density-Adaptive One-Class Fusion (DAC-OCF)
anomaly detection engine that sits between Stage 4 (Feature Extraction)
and Stage 6 (Threat Fusion).

Architecture:
    1. DataPreprocessor  — Loads & preprocesses the RansomwareData.csv dataset
    2. ModelTrainer      — Trains dual Isolation Forest + One-Class SVM models
    3. AnomalyScorer     — Real-time scoring engine for live Stage 4 feature vectors

Pipeline:
    Stage 4 FeatureVector
        -> AnomalyScorer.score(feature_vector)
            -> { anomaly_score, isolation_score, svm_score, confidence, risk_tier }
                -> feeds Stage 6 (Threat Fusion)

Mathematical Foundation:
    Fusion Score:  S_anomaly = w_IF * S_IF + w_SVM * S_SVM

    Where:
        S_IF  = Isolation Forest anomaly score (normalized to [0, 1])
        S_SVM = One-Class SVM decision function (normalized to [0, 1])
        w_IF  = 0.6 (Isolation Forest weight)
        w_SVM = 0.4 (One-Class SVM weight)

Risk Tiers:
    SAFE     : S_anomaly < 0.25
    WATCH    : 0.25 <= S_anomaly < 0.50
    SUSPECT  : 0.50 <= S_anomaly < 0.75
    CRITICAL : S_anomaly >= 0.75

Exports
-------
AnomalyScorer    — Main real-time scoring engine (consumed by Stage 6).
DataPreprocessor — Dataset loading, filtering, and scaling.
ModelTrainer     — Dual-model training pipeline.
FEATURE_COLUMNS  — The 7 Stage 4 feature column names used for scoring.
RISK_TIERS       — Enum-like mapping of risk tier thresholds.
"""

__version__ = "1.0.0"
__stage__ = "Stage 5: Anomaly Scoring & Benign Profiling (DAC-OCF)"

from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer
from src.stage_5_anomaly.preprocessor import DataPreprocessor
from src.stage_5_anomaly.model_trainer import ModelTrainer

# The 7 normalized feature columns from Stage 4 used for real-time scoring
FEATURE_COLUMNS = [
    "S_entropy",
    "S_ETD",
    "S_dist",
    "S_dev",
    "S_stab",
    "lambda_norm",
    "branching_n",
]

# Risk tier thresholds (upper bounds)
RISK_TIERS = {
    "SAFE": 0.25,
    "WATCH": 0.50,
    "SUSPECT": 0.75,
    "CRITICAL": 1.0,
}

__all__ = [
    "AnomalyScorer",
    "DataPreprocessor",
    "ModelTrainer",
    "FEATURE_COLUMNS",
    "RISK_TIERS",
]
