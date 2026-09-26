"""
src/stage_5_anomaly/preprocessor.py
=====================================
Stage 5 — Data Preprocessing Engine for RansomwareData.csv

Handles the complete data preparation pipeline for the anomaly detection models:

1. Load the raw CSV dataset (1,523 samples x 30,970 columns)
2. Separate metadata (ID, Label, Family) from API frequency features
3. Remove zero-variance features (API calls that never occur)
4. Apply VarianceThreshold to reduce dimensionality from ~30,967 to ~500-2000
5. Normalize with StandardScaler
6. Stratified train-test split (80/20)
7. Persist fitted transformers for reuse in real-time scoring

Dataset Layout (RansomwareData.csv):
    Column 0: Sample ID
    Column 1: Label (0 = Goodware, 1 = Ransomware)
    Column 2: Ransomware Family ID (0 = Goodware, 1-11 = families)
    Columns 3-30969: API call frequency counts (30,967 features)

The CSV has NO header row — the first row is data.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Column indices in the raw CSV
COL_ID: int = 0
COL_LABEL: int = 1
COL_FAMILY: int = 2
FEATURE_START_COL: int = 3


class DataPreprocessor:
    """
    Data preprocessing engine for the RansomwareData.csv dataset.

    Handles loading, cleaning, feature selection, scaling, and splitting
    of the raw dataset for anomaly model training.

    Parameters
    ----------
    dataset_path : str
        Path to RansomwareData.csv.
    variance_threshold : float
        Minimum variance a feature must have to be retained (default 0.01).
    test_size : float
        Fraction of data for the test split (default 0.2).
    random_state : int
        Random seed for reproducibility (default 42).
    """

    def __init__(
        self,
        dataset_path: str = "Dataset/RansomwareData.csv",
        variance_threshold: float = 0.01,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> None:
        self.dataset_path = dataset_path
        self.variance_threshold = variance_threshold
        self.test_size = test_size
        self.random_state = random_state

        # Fitted transformers (populated after fit)
        self._scaler = None
        self._selector = None
        self._feature_mask = None

        # Dataset metadata
        self.n_samples: int = 0
        self.n_original_features: int = 0
        self.n_selected_features: int = 0
        self.label_counts: Dict[int, int] = {}
        self.family_counts: Dict[int, int] = {}

    def load_dataset(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Load the raw CSV dataset and separate features from labels.

        Returns
        -------
        X : np.ndarray, shape (n_samples, n_features)
            API call frequency features.
        y_label : np.ndarray, shape (n_samples,)
            Binary labels (0 = Goodware, 1 = Ransomware).
        y_family : np.ndarray, shape (n_samples,)
            Family IDs (0-11).
        """
        import pandas as pd

        logger.info("[Stage5-Preprocessor] Loading dataset from: %s", self.dataset_path)

        if not os.path.isfile(self.dataset_path):
            raise FileNotFoundError(
                f"Dataset not found: {self.dataset_path}. "
                f"Expected at Dataset/RansomwareData.csv"
            )

        # CSV has no header; first row is data
        df = pd.read_csv(self.dataset_path, header=None)

        self.n_samples = len(df)
        self.n_original_features = df.shape[1] - FEATURE_START_COL

        # Extract columns
        y_label = df.iloc[:, COL_LABEL].values.astype(int)
        y_family = df.iloc[:, COL_FAMILY].values.astype(int)
        X = df.iloc[:, FEATURE_START_COL:].values.astype(np.float64)

        # Record label/family distributions
        unique_labels, label_counts = np.unique(y_label, return_counts=True)
        self.label_counts = dict(zip(unique_labels.tolist(), label_counts.tolist()))

        unique_families, family_counts = np.unique(y_family, return_counts=True)
        self.family_counts = dict(zip(unique_families.tolist(), family_counts.tolist()))

        logger.info(
            "[Stage5-Preprocessor] Loaded %d samples, %d features. "
            "Labels: %s, Families: %s",
            self.n_samples, self.n_original_features,
            self.label_counts, self.family_counts,
        )

        return X, y_label, y_family

    def fit_transform(
        self, X: np.ndarray, y_label: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Fit the preprocessing pipeline and transform the dataset.

        Steps:
            1. Remove zero-variance features
            2. Apply VarianceThreshold
            3. Scale with StandardScaler
            4. Stratified train-test split

        Parameters
        ----------
        X : np.ndarray
            Raw feature matrix.
        y_label : np.ndarray
            Binary labels for stratification.

        Returns
        -------
        X_train, X_test, y_train, y_test : np.ndarray
            Processed and split dataset.
        """
        from sklearn.feature_selection import VarianceThreshold
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler

        logger.info(
            "[Stage5-Preprocessor] Fitting pipeline: %d samples x %d features",
            X.shape[0], X.shape[1],
        )

        # Step 1: Variance threshold filtering
        self._selector = VarianceThreshold(threshold=self.variance_threshold)
        X_selected = self._selector.fit_transform(X)
        self._feature_mask = self._selector.get_support()
        self.n_selected_features = X_selected.shape[1]

        logger.info(
            "[Stage5-Preprocessor] VarianceThreshold(%.4f): %d -> %d features",
            self.variance_threshold, X.shape[1], self.n_selected_features,
        )

        # Step 2: StandardScaler normalization
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X_selected)

        # Step 3: Stratified train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_label,
            test_size=self.test_size,
            stratify=y_label,
            random_state=self.random_state,
        )

        logger.info(
            "[Stage5-Preprocessor] Split: train=%d, test=%d (test_size=%.2f)",
            len(X_train), len(X_test), self.test_size,
        )

        return X_train, X_test, y_train, y_test

    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Transform new data using the fitted pipeline.

        Parameters
        ----------
        X : np.ndarray
            Raw feature matrix (must have the same columns as training data).

        Returns
        -------
        np.ndarray
            Transformed feature matrix.
        """
        if self._selector is None or self._scaler is None:
            raise RuntimeError(
                "Preprocessor not fitted. Call fit_transform() first."
            )

        X_selected = self._selector.transform(X)
        X_scaled = self._scaler.transform(X_selected)
        return X_scaled

    def extract_goodware_only(
        self, X: np.ndarray, y_label: np.ndarray
    ) -> np.ndarray:
        """
        Extract only the Goodware (label=0) samples for one-class training.

        Parameters
        ----------
        X : np.ndarray
            Feature matrix.
        y_label : np.ndarray
            Binary labels.

        Returns
        -------
        np.ndarray
            Feature matrix containing only Goodware samples.
        """
        mask = y_label == 0
        X_goodware = X[mask]
        logger.info(
            "[Stage5-Preprocessor] Extracted %d goodware samples from %d total",
            len(X_goodware), len(X),
        )
        return X_goodware

    def save_transformers(self, model_dir: str) -> None:
        """
        Persist fitted scaler and feature selector to disk.

        Parameters
        ----------
        model_dir : str
            Directory to save transformer files.
        """
        import joblib

        os.makedirs(model_dir, exist_ok=True)

        if self._scaler is not None:
            scaler_path = os.path.join(model_dir, "scaler.joblib")
            joblib.dump(self._scaler, scaler_path)
            logger.info("[Stage5-Preprocessor] Saved scaler to: %s", scaler_path)

        if self._selector is not None:
            selector_path = os.path.join(model_dir, "feature_selector.joblib")
            joblib.dump(self._selector, selector_path)
            logger.info("[Stage5-Preprocessor] Saved selector to: %s", selector_path)

    def load_transformers(self, model_dir: str) -> None:
        """
        Load previously fitted scaler and feature selector from disk.

        Parameters
        ----------
        model_dir : str
            Directory containing transformer files.
        """
        import joblib

        scaler_path = os.path.join(model_dir, "scaler.joblib")
        selector_path = os.path.join(model_dir, "feature_selector.joblib")

        if os.path.isfile(scaler_path):
            self._scaler = joblib.load(scaler_path)
            logger.info("[Stage5-Preprocessor] Loaded scaler from: %s", scaler_path)

        if os.path.isfile(selector_path):
            self._selector = joblib.load(selector_path)
            self._feature_mask = self._selector.get_support()
            self.n_selected_features = int(self._feature_mask.sum())
            logger.info(
                "[Stage5-Preprocessor] Loaded selector from: %s (%d features)",
                selector_path, self.n_selected_features,
            )

    def get_metadata(self) -> Dict[str, Any]:
        """Return a dict of preprocessing metadata for logging/persistence."""
        return {
            "n_samples": self.n_samples,
            "n_original_features": self.n_original_features,
            "n_selected_features": self.n_selected_features,
            "variance_threshold": self.variance_threshold,
            "test_size": self.test_size,
            "random_state": self.random_state,
            "label_counts": self.label_counts,
            "family_counts": self.family_counts,
        }

    def __repr__(self) -> str:
        fitted = self._scaler is not None
        return (
            f"DataPreprocessor(fitted={fitted}, "
            f"samples={self.n_samples}, "
            f"features={self.n_original_features}->{self.n_selected_features})"
        )
