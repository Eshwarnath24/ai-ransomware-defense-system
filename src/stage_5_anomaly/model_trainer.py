"""
src/stage_5_anomaly/model_trainer.py
=======================================
Stage 5 — Dual-Model Training Pipeline (DAC-OCF)

Trains the two complementary anomaly detection models:

    1. Isolation Forest — Tree-based anomaly isolation
       - Partitions feature space with random splits
       - Anomalies require fewer splits to isolate (shorter path length)
       - Score: S_IF = -(decision_function), normalized to [0, 1]

    2. One-Class SVM — Kernel-based boundary learning
       - Learns a tight boundary around benign data in RBF kernel space
       - Points outside the boundary are classified as anomalous
       - Score: S_SVM = -(decision_function), normalized to [0, 1]

Training Strategy (One-Class Approach):
    - Train ONLY on Goodware (label=0) samples
    - The model learns "what normal looks like"
    - Anything that deviates from normal = anomalous = potential ransomware

Evaluation:
    - Test on the full held-out test set (both Goodware and Ransomware)
    - Metrics: Accuracy, Precision, Recall, F1-Score, AUC-ROC
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Dual-model anomaly detection training pipeline.

    Trains Isolation Forest and One-Class SVM on goodware-only data,
    then evaluates on mixed test data (goodware + ransomware).

    Parameters
    ----------
    if_n_estimators : int
        Number of trees in the Isolation Forest (default 200).
    if_contamination : float
        Expected proportion of outliers in training data (default 0.05).
    if_max_features : float
        Fraction of features for each tree (default 0.8).
    svm_kernel : str
        SVM kernel type (default "rbf").
    svm_nu : float
        Upper bound on training errors / lower bound on support vectors (default 0.1).
    svm_gamma : str or float
        Kernel coefficient (default "scale").
    random_state : int
        Random seed for reproducibility (default 42).
    """

    def __init__(
        self,
        if_n_estimators: int = 200,
        if_contamination: float = 0.05,
        if_max_features: float = 0.8,
        svm_kernel: str = "rbf",
        svm_nu: float = 0.1,
        svm_gamma: str = "scale",
        random_state: int = 42,
    ) -> None:
        self.if_n_estimators = if_n_estimators
        self.if_contamination = if_contamination
        self.if_max_features = if_max_features
        self.svm_kernel = svm_kernel
        self.svm_nu = svm_nu
        self.svm_gamma = svm_gamma
        self.random_state = random_state

        # Trained models (populated after train)
        self.isolation_forest = None
        self.one_class_svm = None

        # Training metrics
        self.training_time_sec: float = 0.0
        self.evaluation_metrics: Dict[str, Any] = {}

    def train(
        self, X_train_goodware: np.ndarray
    ) -> None:
        """
        Train both anomaly detection models on goodware-only data.

        Parameters
        ----------
        X_train_goodware : np.ndarray
            Feature matrix of ONLY goodware samples (no ransomware).
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.svm import OneClassSVM

        logger.info(
            "[Stage5-Trainer] Training on %d goodware samples with %d features",
            X_train_goodware.shape[0], X_train_goodware.shape[1],
        )

        t_start = time.time()

        # ── Train Isolation Forest ───────────────────────────────────────
        logger.info(
            "[Stage5-Trainer] Training Isolation Forest "
            "(n_estimators=%d, contamination=%.3f, max_features=%.2f)...",
            self.if_n_estimators, self.if_contamination, self.if_max_features,
        )

        self.isolation_forest = IsolationForest(
            n_estimators=self.if_n_estimators,
            contamination=self.if_contamination,
            max_features=self.if_max_features,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.isolation_forest.fit(X_train_goodware)

        # ── Train One-Class SVM ──────────────────────────────────────────
        logger.info(
            "[Stage5-Trainer] Training One-Class SVM "
            "(kernel=%s, nu=%.3f, gamma=%s)...",
            self.svm_kernel, self.svm_nu, self.svm_gamma,
        )

        self.one_class_svm = OneClassSVM(
            kernel=self.svm_kernel,
            nu=self.svm_nu,
            gamma=self.svm_gamma,
        )
        self.one_class_svm.fit(X_train_goodware)

        self.training_time_sec = time.time() - t_start

        logger.info(
            "[Stage5-Trainer] Training completed in %.2f seconds",
            self.training_time_sec,
        )

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        fusion_weights: Optional[Tuple[float, float]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate both models on the held-out test set.

        One-Class models output:
            +1 = inlier (normal/goodware)
            -1 = outlier (anomaly/ransomware)

        We convert to binary: anomaly_pred = 1 if prediction == -1, else 0
        Then compare against y_test (1 = ransomware, 0 = goodware).

        Parameters
        ----------
        X_test : np.ndarray
            Test feature matrix.
        y_test : np.ndarray
            True binary labels (0 = goodware, 1 = ransomware).
        fusion_weights : tuple of (w_if, w_svm), optional
            Fusion weights (default (0.6, 0.4)).

        Returns
        -------
        dict
            Evaluation metrics including accuracy, precision, recall, F1, AUC-ROC.
        """
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            roc_auc_score,
            classification_report,
            confusion_matrix,
        )

        if self.isolation_forest is None or self.one_class_svm is None:
            raise RuntimeError("Models not trained. Call train() first.")

        if fusion_weights is None:
            fusion_weights = (0.6, 0.4)

        w_if, w_svm = fusion_weights

        # ── Get raw predictions ──────────────────────────────────────────
        # OneClass: +1 = inlier, -1 = outlier
        if_pred = self.isolation_forest.predict(X_test)
        svm_pred = self.one_class_svm.predict(X_test)

        # Convert to anomaly labels: 1 = anomaly (ransomware), 0 = normal
        if_anomaly = (if_pred == -1).astype(int)
        svm_anomaly = (svm_pred == -1).astype(int)

        # ── Compute anomaly scores for fusion ────────────────────────────
        if_scores = self._normalize_scores(
            -self.isolation_forest.decision_function(X_test)
        )
        svm_scores = self._normalize_scores(
            -self.one_class_svm.decision_function(X_test)
        )

        # Fused anomaly score
        fused_scores = w_if * if_scores + w_svm * svm_scores

        # Fused binary prediction: threshold at 0.5
        fused_pred = (fused_scores >= 0.5).astype(int)

        # ── Compute metrics ──────────────────────────────────────────────
        metrics = {
            "isolation_forest": {
                "accuracy": float(accuracy_score(y_test, if_anomaly)),
                "precision": float(precision_score(y_test, if_anomaly, zero_division=0)),
                "recall": float(recall_score(y_test, if_anomaly, zero_division=0)),
                "f1": float(f1_score(y_test, if_anomaly, zero_division=0)),
                "auc_roc": float(roc_auc_score(y_test, if_scores)),
            },
            "one_class_svm": {
                "accuracy": float(accuracy_score(y_test, svm_anomaly)),
                "precision": float(precision_score(y_test, svm_anomaly, zero_division=0)),
                "recall": float(recall_score(y_test, svm_anomaly, zero_division=0)),
                "f1": float(f1_score(y_test, svm_anomaly, zero_division=0)),
                "auc_roc": float(roc_auc_score(y_test, svm_scores)),
            },
            "fused_dac_ocf": {
                "accuracy": float(accuracy_score(y_test, fused_pred)),
                "precision": float(precision_score(y_test, fused_pred, zero_division=0)),
                "recall": float(recall_score(y_test, fused_pred, zero_division=0)),
                "f1": float(f1_score(y_test, fused_pred, zero_division=0)),
                "auc_roc": float(roc_auc_score(y_test, fused_scores)),
                "fusion_weights": {"isolation_forest": w_if, "one_class_svm": w_svm},
            },
            "confusion_matrix": confusion_matrix(y_test, fused_pred).tolist(),
            "classification_report": classification_report(
                y_test, fused_pred,
                target_names=["Goodware", "Ransomware"],
                output_dict=True,
            ),
            "training_time_sec": self.training_time_sec,
        }

        self.evaluation_metrics = metrics

        logger.info(
            "[Stage5-Trainer] Evaluation Results:\n"
            "  Isolation Forest — Acc=%.3f  F1=%.3f  AUC=%.3f\n"
            "  One-Class SVM    — Acc=%.3f  F1=%.3f  AUC=%.3f\n"
            "  Fused DAC-OCF    — Acc=%.3f  F1=%.3f  AUC=%.3f",
            metrics["isolation_forest"]["accuracy"],
            metrics["isolation_forest"]["f1"],
            metrics["isolation_forest"]["auc_roc"],
            metrics["one_class_svm"]["accuracy"],
            metrics["one_class_svm"]["f1"],
            metrics["one_class_svm"]["auc_roc"],
            metrics["fused_dac_ocf"]["accuracy"],
            metrics["fused_dac_ocf"]["f1"],
            metrics["fused_dac_ocf"]["auc_roc"],
        )

        return metrics

    def save_models(self, model_dir: str) -> None:
        """
        Persist trained models and metadata to disk.

        Parameters
        ----------
        model_dir : str
            Directory to save model files.
        """
        import joblib

        os.makedirs(model_dir, exist_ok=True)

        if self.isolation_forest is not None:
            if_path = os.path.join(model_dir, "isolation_forest.joblib")
            joblib.dump(self.isolation_forest, if_path)
            logger.info("[Stage5-Trainer] Saved Isolation Forest to: %s", if_path)

        if self.one_class_svm is not None:
            svm_path = os.path.join(model_dir, "one_class_svm.joblib")
            joblib.dump(self.one_class_svm, svm_path)
            logger.info("[Stage5-Trainer] Saved One-Class SVM to: %s", svm_path)

        # Save training metadata
        metadata = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "training_time_sec": self.training_time_sec,
            "hyperparameters": {
                "isolation_forest": {
                    "n_estimators": self.if_n_estimators,
                    "contamination": self.if_contamination,
                    "max_features": self.if_max_features,
                },
                "one_class_svm": {
                    "kernel": self.svm_kernel,
                    "nu": self.svm_nu,
                    "gamma": str(self.svm_gamma),
                },
            },
            "evaluation_metrics": self.evaluation_metrics,
        }

        metadata_path = os.path.join(model_dir, "training_metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        logger.info("[Stage5-Trainer] Saved metadata to: %s", metadata_path)

    def load_models(self, model_dir: str) -> None:
        """
        Load previously trained models from disk.

        Parameters
        ----------
        model_dir : str
            Directory containing model files.
        """
        import joblib

        if_path = os.path.join(model_dir, "isolation_forest.joblib")
        svm_path = os.path.join(model_dir, "one_class_svm.joblib")

        if os.path.isfile(if_path):
            self.isolation_forest = joblib.load(if_path)
            logger.info("[Stage5-Trainer] Loaded Isolation Forest from: %s", if_path)

        if os.path.isfile(svm_path):
            self.one_class_svm = joblib.load(svm_path)
            logger.info("[Stage5-Trainer] Loaded One-Class SVM from: %s", svm_path)

        # Load metadata if available
        metadata_path = os.path.join(model_dir, "training_metadata.json")
        if os.path.isfile(metadata_path):
            with open(metadata_path, "r") as f:
                meta = json.load(f)
            self.training_time_sec = meta.get("training_time_sec", 0.0)
            self.evaluation_metrics = meta.get("evaluation_metrics", {})

    @staticmethod
    def _normalize_scores(scores: np.ndarray) -> np.ndarray:
        """
        Normalize raw anomaly scores to [0, 1] using min-max scaling.

        Parameters
        ----------
        scores : np.ndarray
            Raw anomaly scores (higher = more anomalous).

        Returns
        -------
        np.ndarray
            Normalized scores in [0, 1].
        """
        s_min = scores.min()
        s_max = scores.max()
        if s_max - s_min < 1e-10:
            return np.full_like(scores, 0.5)
        return (scores - s_min) / (s_max - s_min)

    def __repr__(self) -> str:
        trained = self.isolation_forest is not None
        return (
            f"ModelTrainer(trained={trained}, "
            f"if_trees={self.if_n_estimators}, "
            f"svm_kernel={self.svm_kernel}, "
            f"time={self.training_time_sec:.2f}s)"
        )
