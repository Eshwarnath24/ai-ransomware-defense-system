"""
src/stage_5_anomaly/anomaly_scorer.py
=======================================
Stage 5 — Real-Time Anomaly Scoring Engine (DAC-OCF Runtime)

This is the RUNTIME component consumed by Stage 6 (Threat Fusion).
It accepts per-event Stage 4 feature vectors (7 dimensions) and produces
calibrated anomaly scores with risk tier classifications.

Two operating modes:
    1. ML Mode (primary):
       - Uses pre-trained Isolation Forest (DAC) + One-Class SVM (OCF)
       - Evaluates against the 7 Stage 4 behavioral telemetry features
       - Produces fused DAC-OCF anomaly score: S_anomaly = w_IF * S_IF + w_SVM * S_SVM
       - Requires models to be trained via train_stage5.py

    2. Heuristic Fallback Mode:
       - Uses weighted combination of Stage 4 signals directly
       - Used if model files are missing or unreadable

Risk Tier Assignment:
    SAFE     : S_anomaly < 0.25
    WATCH    : 0.25 <= S_anomaly < 0.50
    SUSPECT  : 0.50 <= S_anomaly < 0.75
    CRITICAL : S_anomaly >= 0.75
"""

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# The 7 Stage 4 feature columns used for ML scoring
FEATURE_COLUMNS: List[str] = [
    "S_entropy",
    "S_ETD",
    "S_dist",
    "S_dev",
    "S_stab",
    "lambda_norm",
    "branching_n",
]

# Heuristic weights for fallback mode
HEURISTIC_WEIGHTS: Dict[str, float] = {
    "S_entropy": 0.30,
    "S_ETD": 0.20,
    "S_dist": 0.15,
    "S_dev": 0.15,
    "S_stab_inv": 0.10,
    "lambda_norm": 0.10,
}

# Default baseline feature values for unobserved or partial fields
DEFAULT_FEATURE_VALUES: Dict[str, float] = {
    "S_entropy": 0.50,
    "S_ETD": 0.50,
    "S_dist": 0.05,
    "S_dev": 0.05,
    "S_stab": 0.80,
    "lambda_norm": 0.05,
    "branching_n": 0.625,
}

# Default risk tier thresholds
DEFAULT_THRESHOLDS: Dict[str, float] = {
    "SAFE": 0.25,
    "WATCH": 0.50,
    "SUSPECT": 0.75,
}


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert any input value to a finite float."""
    if val is None:
        return default
    try:
        f = float(val)
        return default if np.isnan(f) or np.isinf(f) else f
    except (ValueError, TypeError):
        return default


class AnomalyScorer:
    """
    Real-time anomaly scoring engine for Stage 4 feature vectors.

    Parameters
    ----------
    model_dir : str, optional
        Directory containing pre-trained model files.
    w_if : float
        Weight for Isolation Forest score in fusion (default 0.6).
    w_svm : float
        Weight for One-Class SVM score in fusion (default 0.4).
    thresholds : dict, optional
        Risk tier thresholds.
    """

    def __init__(
        self,
        model_dir: str = "models",
        w_if: float = 0.3,
        w_svm: float = 0.7,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self.model_dir = model_dir
        self.w_if = w_if
        self.w_svm = w_svm
        self.thresholds = thresholds or DEFAULT_THRESHOLDS.copy()

        # Models & Scaler
        self._isolation_forest = None
        self._one_class_svm = None
        self._scaler = None
        self._ml_mode: bool = False
        self._lock = threading.RLock()

        # Statistics
        self.total_scored: int = 0
        self.total_anomalies: int = 0

        # Attempt to load models
        self._try_load_models()

    def _try_load_models(self) -> None:
        """Attempt to load pre-trained models from the model directory."""
        if_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        svm_path = os.path.join(self.model_dir, "one_class_svm.joblib")
        scaler_path = os.path.join(self.model_dir, "scaler.joblib")

        if os.path.isfile(if_path) and os.path.isfile(svm_path):
            try:
                self._isolation_forest = joblib.load(if_path)
                self._one_class_svm = joblib.load(svm_path)
                if os.path.isfile(scaler_path):
                    self._scaler = joblib.load(scaler_path)
                self._ml_mode = True
                logger.info(
                    "[Stage5-Scorer] ML mode active. Loaded models from: %s",
                    self.model_dir,
                )
            except Exception as exc:
                logger.warning(
                    "[Stage5-Scorer] Failed to load models, using heuristic fallback: %s",
                    exc,
                )
                self._ml_mode = False
        else:
            logger.info(
                "[Stage5-Scorer] No trained models found in '%s'. Using heuristic fallback.",
                self.model_dir,
            )
            self._ml_mode = False

    @property
    def is_ml_mode(self) -> bool:
        """Return True if ML models are loaded and active."""
        return self._ml_mode

    def score(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a single Stage 4 feature vector.
        """
        with self._lock:
            if self._ml_mode and self._isolation_forest is not None and self._one_class_svm is not None:
                try:
                    result = self._score_ml(feature_vector)
                except Exception as exc:
                    logger.debug("[Stage5-Scorer] ML scoring exception, fallback to heuristic: %s", exc)
                    result = self._score_heuristic(feature_vector)
            else:
                result = self._score_heuristic(feature_vector)

            # Assign risk tier
            result["risk_tier"] = self._assign_risk_tier(result["anomaly_score"])
            result["is_anomaly"] = result["anomaly_score"] >= self.thresholds["WATCH"]

            # Passthrough event context
            result["pid"] = feature_vector.get("pid", -1)
            result["file_path"] = feature_vector.get("file_path", "")
            result["timestamp"] = feature_vector.get("timestamp", 0)

            # Update statistics
            self.total_scored += 1
            if result["is_anomaly"]:
                self.total_anomalies += 1

            return result

    def score_feature_dict(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for score()."""
        return self.score(feature_vector)

    def score_batch(self, feature_vectors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score a batch of Stage 4 feature vectors."""
        return [self.score(fv) for fv in feature_vectors]

    def _score_ml(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score using the trained ML models (Isolation Forest + One-Class SVM).
        """
        # Extract 7 features
        X = self._feature_vector_to_array(feature_vector)

        # Check feature dimension compatibility
        n_expected = getattr(self._isolation_forest, "n_features_in_", None)
        if n_expected is not None and X.shape[1] != n_expected:
            return self._score_heuristic(feature_vector)

        # Scale features if scaler is loaded
        X_proc = self._scaler.transform(X) if self._scaler is not None else X

        # Get raw decision function scores
        # In sklearn OneClass: positive values = inliers (benign), negative = outliers (anomaly)
        # So we negate decision_function so higher = more anomalous
        if_raw = -float(self._isolation_forest.decision_function(X_proc)[0])
        svm_raw = -float(self._one_class_svm.decision_function(X_proc)[0])

        # Normalize to [0, 1] using calibrated sigmoid normalization
        # Negative decision_function indicates an anomaly (outlier)
        if_score = self._sigmoid_normalize(if_raw, scale=10.0)
        svm_score = self._sigmoid_normalize(svm_raw, scale=3.0)

        # Superheated or extreme Hawkes burst boost
        if feature_vector.get("is_superheated", False) or feature_vector.get("branching_n", 0.0) >= 1.0:
            if_score = min(1.0, if_score + 0.20)
            svm_score = min(1.0, svm_score + 0.20)

        # Fused DAC-OCF score
        anomaly_score = self.w_if * if_score + self.w_svm * svm_score
        confidence = 2.0 * abs(anomaly_score - 0.5)

        return {
            "anomaly_score": float(np.clip(anomaly_score, 0.0, 1.0)),
            "isolation_score": float(np.clip(if_score, 0.0, 1.0)),
            "svm_score": float(np.clip(svm_score, 0.0, 1.0)),
            "confidence": float(np.clip(confidence, 0.0, 1.0)),
            "scoring_mode": "ml",
            "dimension_matched": True,
        }

    def _score_heuristic(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic fallback calculation."""
        s_entropy = _safe_float(feature_vector.get("S_entropy"), 0.0)
        s_etd = _safe_float(feature_vector.get("S_ETD"), 0.0)
        s_dist = _safe_float(feature_vector.get("S_dist"), 0.0)
        s_dev = _safe_float(feature_vector.get("S_dev"), 0.0)
        s_stab = _safe_float(feature_vector.get("S_stab"), 0.5)
        lambda_norm = _safe_float(feature_vector.get("lambda_norm"), 0.0)
        branching_n = _safe_float(feature_vector.get("branching_n"), 0.0)

        anomaly_score = (
            HEURISTIC_WEIGHTS["S_entropy"] * s_entropy
            + HEURISTIC_WEIGHTS["S_ETD"] * s_etd
            + HEURISTIC_WEIGHTS["S_dist"] * s_dist
            + HEURISTIC_WEIGHTS["S_dev"] * s_dev
            + HEURISTIC_WEIGHTS["S_stab_inv"] * (1.0 - s_stab)
            + HEURISTIC_WEIGHTS["lambda_norm"] * lambda_norm
        )

        if feature_vector.get("is_superheated", False) or branching_n >= 1.0:
            anomaly_score = min(1.0, anomaly_score + 0.20)

        anomaly_score = max(0.0, min(1.0, anomaly_score))
        confidence = 0.5 * (2.0 * abs(anomaly_score - 0.5))

        return {
            "anomaly_score": float(anomaly_score),
            "isolation_score": None,
            "svm_score": None,
            "confidence": float(np.clip(confidence, 0.0, 1.0)),
            "scoring_mode": "heuristic",
            "dimension_matched": False,
        }

    def _feature_vector_to_array(self, feature_vector: Dict[str, Any]) -> np.ndarray:
        """Convert a Stage 4 feature dict to a numpy array for model input."""
        values = [
            _safe_float(
                feature_vector.get(col),
                DEFAULT_FEATURE_VALUES.get(col, 0.0),
            )
            for col in FEATURE_COLUMNS
        ]
        return np.array([values], dtype=np.float64)

    def _assign_risk_tier(self, score: float) -> str:
        """Map an anomaly score to a risk tier string."""
        if score < self.thresholds["SAFE"]:
            return "SAFE"
        elif score < self.thresholds["WATCH"]:
            return "WATCH"
        elif score < self.thresholds["SUSPECT"]:
            return "SUSPECT"
        else:
            return "CRITICAL"

    @staticmethod
    def _sigmoid_normalize(x: float, scale: float = 1.0) -> float:
        """Smooth logistic sigmoid normalization centered around 0."""
        # x > 0 means anomaly, x < 0 means inlier
        return float(1.0 / (1.0 + np.exp(-x * scale)))

    def get_stats(self) -> Dict[str, Any]:
        """Return runtime scoring statistics."""
        with self._lock:
            return {
                "total_scored": self.total_scored,
                "total_anomalies": self.total_anomalies,
                "anomaly_rate": (
                    self.total_anomalies / max(1, self.total_scored)
                ),
                "scoring_mode": "ml" if self._ml_mode else "heuristic",
                "is_ml_mode": self._ml_mode,
            }
