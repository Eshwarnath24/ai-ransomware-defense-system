"""
src/stage_5_anomaly/anomaly_scorer.py
=======================================
Stage 5 — Real-Time Anomaly Scoring Engine (DAC-OCF Runtime)

This is the RUNTIME component consumed by Stage 6 (Threat Fusion).
It accepts per-event feature vectors from Stage 4 and produces
calibrated anomaly scores with risk tier classifications.

Two operating modes:
    1. ML Mode (preferred):
       - Uses pre-trained Isolation Forest + One-Class SVM
       - Produces fused DAC-OCF anomaly score
       - Requires models to be trained first via train_stage5.py

    2. Heuristic Fallback Mode:
       - Uses weighted combination of Stage 4 signals directly
       - No ML model required — works out of the box
       - Less accurate but always available

Fusion Score (ML Mode):
    S_anomaly = w_IF * S_IF + w_SVM * S_SVM

Heuristic Score (Fallback Mode):
    S_anomaly = 0.30 * S_entropy + 0.20 * S_ETD + 0.15 * S_dist
              + 0.15 * S_dev + 0.10 * (1 - S_stab) + 0.10 * lambda_norm

Risk Tier Assignment:
    SAFE     : S_anomaly < 0.25
    WATCH    : 0.25 <= S_anomaly < 0.50
    SUSPECT  : 0.50 <= S_anomaly < 0.75
    CRITICAL : S_anomaly >= 0.75

Thread Safety:
    All scoring operations are thread-safe via a read lock.
    Models are loaded once and shared across scoring calls.
"""

import logging
import os
import threading
from typing import Any, Dict, List, Optional

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
    "S_stab_inv": 0.10,   # Uses (1 - S_stab)
    "lambda_norm": 0.10,
}

# Default risk tier thresholds
DEFAULT_THRESHOLDS: Dict[str, float] = {
    "SAFE": 0.25,
    "WATCH": 0.50,
    "SUSPECT": 0.75,
}


class AnomalyScorer:
    """
    Real-time anomaly scoring engine for Stage 4 feature vectors.

    Parameters
    ----------
    model_dir : str, optional
        Directory containing pre-trained model files. If models exist,
        uses ML mode; otherwise falls back to heuristic mode.
    w_if : float
        Weight for Isolation Forest score in fusion (default 0.6).
    w_svm : float
        Weight for One-Class SVM score in fusion (default 0.4).
    thresholds : dict, optional
        Risk tier thresholds (SAFE, WATCH, SUSPECT). Default values used
        if not provided.
    """

    def __init__(
        self,
        model_dir: str = "models",
        w_if: float = 0.6,
        w_svm: float = 0.4,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self.model_dir = model_dir
        self.w_if = w_if
        self.w_svm = w_svm
        self.thresholds = thresholds or DEFAULT_THRESHOLDS.copy()

        # Models (loaded on init if available)
        self._isolation_forest = None
        self._one_class_svm = None
        self._ml_mode: bool = False
        self._lock = threading.RLock()

        # Statistics
        self.total_scored: int = 0
        self.total_anomalies: int = 0

        # Normalization bounds for ML scores (set during first batch)
        self._if_score_bounds: Optional[tuple] = None
        self._svm_score_bounds: Optional[tuple] = None

        # Attempt to load models
        self._try_load_models()

    def _try_load_models(self) -> None:
        """Attempt to load pre-trained models from the model directory."""
        import joblib

        if_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        svm_path = os.path.join(self.model_dir, "one_class_svm.joblib")

        if os.path.isfile(if_path) and os.path.isfile(svm_path):
            try:
                self._isolation_forest = joblib.load(if_path)
                self._one_class_svm = joblib.load(svm_path)
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
                "[Stage5-Scorer] No trained models found in '%s'. "
                "Using heuristic fallback mode.",
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

        Parameters
        ----------
        feature_vector : dict
            A Stage 4 feature vector dict containing at minimum:
            S_entropy, S_ETD, S_dist, S_dev, S_stab, lambda_norm, branching_n.

        Returns
        -------
        dict
            Anomaly scoring result:
            {
                "anomaly_score": float [0, 1],
                "isolation_score": float [0, 1] or None,
                "svm_score": float [0, 1] or None,
                "confidence": float [0, 1],
                "risk_tier": str (SAFE|WATCH|SUSPECT|CRITICAL),
                "is_anomaly": bool,
                "scoring_mode": str (ml|heuristic),
                "pid": int,
                "file_path": str,
            }
        """
        with self._lock:
            if self._ml_mode:
                result = self._score_ml(feature_vector)
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

            logger.debug(
                "[Stage5-Scorer] PID=%d  score=%.3f  tier=%s  mode=%s  %s",
                result["pid"], result["anomaly_score"], result["risk_tier"],
                result["scoring_mode"], result["file_path"],
            )

            return result

    def score_feature_dict(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for score()."""
        return self.score(feature_vector)

    def score_batch(self, feature_vectors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Score a batch of Stage 4 feature vectors.

        Parameters
        ----------
        feature_vectors : list of dict
            Multiple Stage 4 feature vector dicts.

        Returns
        -------
        list of dict
            List of anomaly scoring results.
        """
        return [self.score(fv) for fv in feature_vectors]

    def _score_ml(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score using the trained ML models (Isolation Forest + One-Class SVM).
        """
        # Extract features into array
        if "feature_vector" in feature_vector and isinstance(feature_vector["feature_vector"], (list, np.ndarray)):
            X = np.asarray(feature_vector["feature_vector"], dtype=np.float64).reshape(1, -1)
        else:
            X = self._feature_vector_to_array(feature_vector)

        # Check feature dimension compatibility with loaded models
        n_expected = getattr(self._isolation_forest, "n_features_in_", None)
        if n_expected is not None and X.shape[1] != n_expected:
            # Dimension mismatch (e.g. 7 runtime signals vs N-dim API features) -> fallback to heuristic
            return self._score_heuristic(feature_vector)

        # Get raw decision function scores (more negative = more anomalous)
        if_raw = -self._isolation_forest.decision_function(X)[0]
        svm_raw = -self._one_class_svm.decision_function(X)[0]

        # Normalize to [0, 1] using sigmoid-based normalization
        if_score = self._sigmoid_normalize(if_raw)
        svm_score = self._sigmoid_normalize(svm_raw)

        # Fused DAC-OCF score
        anomaly_score = self.w_if * if_score + self.w_svm * svm_score

        # Confidence = how decisive the model is (distance from 0.5)
        confidence = 2.0 * abs(anomaly_score - 0.5)

        return {
            "anomaly_score": float(np.clip(anomaly_score, 0.0, 1.0)),
            "isolation_score": float(np.clip(if_score, 0.0, 1.0)),
            "svm_score": float(np.clip(svm_score, 0.0, 1.0)),
            "confidence": float(np.clip(confidence, 0.0, 1.0)),
            "scoring_mode": "ml",
        }

    def _score_heuristic(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score using the heuristic fallback (weighted Stage 4 signal combination).

        Formula:
            S_anomaly = 0.30 * S_entropy + 0.20 * S_ETD + 0.15 * S_dist
                      + 0.15 * S_dev + 0.10 * (1 - S_stab) + 0.10 * lambda_norm
        """
        s_entropy = float(feature_vector.get("S_entropy", 0.0))
        s_etd = float(feature_vector.get("S_ETD", 0.0))
        s_dist = float(feature_vector.get("S_dist", 0.0))
        s_dev = float(feature_vector.get("S_dev", 0.0))
        s_stab = float(feature_vector.get("S_stab", 0.5))
        lambda_norm = float(feature_vector.get("lambda_norm", 0.0))
        branching_n = float(feature_vector.get("branching_n", 0.0))

        # Compute weighted heuristic score
        anomaly_score = (
            HEURISTIC_WEIGHTS["S_entropy"] * s_entropy
            + HEURISTIC_WEIGHTS["S_ETD"] * s_etd
            + HEURISTIC_WEIGHTS["S_dist"] * s_dist
            + HEURISTIC_WEIGHTS["S_dev"] * s_dev
            + HEURISTIC_WEIGHTS["S_stab_inv"] * (1.0 - s_stab)
            + HEURISTIC_WEIGHTS["lambda_norm"] * lambda_norm
        )

        # Superheated boost: if Hawkes branching ratio >= 1.0, add penalty
        if branching_n >= 1.0:
            anomaly_score = min(1.0, anomaly_score + 0.15)

        anomaly_score = max(0.0, min(1.0, anomaly_score))

        # Confidence is lower in heuristic mode (no learned model)
        confidence = 0.5 * (2.0 * abs(anomaly_score - 0.5))

        return {
            "anomaly_score": float(anomaly_score),
            "isolation_score": None,
            "svm_score": None,
            "confidence": float(np.clip(confidence, 0.0, 1.0)),
            "scoring_mode": "heuristic",
        }

    def _feature_vector_to_array(self, feature_vector: Dict[str, Any]) -> np.ndarray:
        """
        Convert a Stage 4 feature dict to a numpy array for model input.

        Parameters
        ----------
        feature_vector : dict
            Stage 4 feature vector.

        Returns
        -------
        np.ndarray, shape (1, 7)
            2D array suitable for sklearn predict/decision_function.
        """
        values = [
            float(feature_vector.get(col, 0.0))
            for col in FEATURE_COLUMNS
        ]
        return np.array([values], dtype=np.float64)

    def _assign_risk_tier(self, score: float) -> str:
        """
        Map an anomaly score to a risk tier string.

        Parameters
        ----------
        score : float
            Anomaly score in [0, 1].

        Returns
        -------
        str
            One of: SAFE, WATCH, SUSPECT, CRITICAL.
        """
        if score < self.thresholds["SAFE"]:
            return "SAFE"
        elif score < self.thresholds["WATCH"]:
            return "WATCH"
        elif score < self.thresholds["SUSPECT"]:
            return "SUSPECT"
        else:
            return "CRITICAL"

    @staticmethod
    def _sigmoid_normalize(x: float, scale: float = 2.0) -> float:
        """
        Normalize a raw score to [0, 1] using a sigmoid function.

        This provides smooth, bounded normalization that handles
        arbitrary score ranges gracefully.

        Parameters
        ----------
        x : float
            Raw score.
        scale : float
            Controls sigmoid steepness (default 2.0).

        Returns
        -------
        float
            Normalized score in [0, 1].
        """
        return 1.0 / (1.0 + np.exp(-scale * x))

    def get_stats(self) -> Dict[str, Any]:
        """Return scoring statistics."""
        return {
            "total_scored": self.total_scored,
            "total_anomalies": self.total_anomalies,
            "anomaly_rate": (
                self.total_anomalies / max(1, self.total_scored)
            ),
            "scoring_mode": "ml" if self._ml_mode else "heuristic",
            "model_dir": self.model_dir,
        }

    def reload_models(self) -> bool:
        """
        Reload models from disk (e.g., after retraining).

        Returns
        -------
        bool
            True if models were successfully reloaded.
        """
        with self._lock:
            self._try_load_models()
            return self._ml_mode

    def __repr__(self) -> str:
        mode = "ML" if self._ml_mode else "Heuristic"
        return (
            f"AnomalyScorer(mode={mode}, "
            f"scored={self.total_scored}, "
            f"anomalies={self.total_anomalies}, "
            f"w_if={self.w_if}, w_svm={self.w_svm})"
        )
