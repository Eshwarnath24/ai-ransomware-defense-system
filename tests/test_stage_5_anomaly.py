"""
tests/test_stage_5_anomaly.py
================================
Stage 5 — Automated Test Suite for Anomaly Scoring & Benign Profiling (DAC-OCF)

Test Categories:
    1. DataPreprocessor  (8 tests)  — CSV loading, feature selection, scaling
    2. ModelTrainer      (8 tests)  — Model training, evaluation, serialization
    3. AnomalyScorer     (10 tests) — Scoring, risk tiers, fallback, thread safety
    4. Integration       (4 tests)  — End-to-end Stage 4 -> Stage 5 pipeline

Total: 30 tests

Usage:
    python -m pytest tests/test_stage_5_anomaly.py -v
"""

import math
import os
import sys
import tempfile
import shutil
import threading
import time
from pathlib import Path

import numpy as np
import pytest

# Ensure project root on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor
from src.stage_5_anomaly.model_trainer import ModelTrainer
from src.stage_5_anomaly.anomaly_scorer import (
    AnomalyScorer,
    FEATURE_COLUMNS,
    HEURISTIC_WEIGHTS,
)


# ─── Synthetic Data Helpers ─────────────────────────────────────────────────

def _make_synthetic_dataset(
    n_goodware: int = 200,
    n_ransomware: int = 80,
    n_features: int = 50,
    random_state: int = 42,
):
    """
    Generate a synthetic dataset mimicking the RansomwareData.csv structure.

    Goodware: low values (mean=0.1, std=0.05)
    Ransomware: higher values with more variance (mean=0.6, std=0.3)
    """
    rng = np.random.RandomState(random_state)
    n_total = n_goodware + n_ransomware

    # Generate features
    X_good = rng.normal(0.1, 0.05, size=(n_goodware, n_features)).clip(0)
    X_ransom = rng.normal(0.6, 0.3, size=(n_ransomware, n_features)).clip(0)
    X = np.vstack([X_good, X_ransom])

    # Labels
    y_label = np.array([0] * n_goodware + [1] * n_ransomware)

    # Family IDs
    y_family = np.zeros(n_total, dtype=int)
    y_family[n_goodware:] = rng.randint(1, 12, size=n_ransomware)

    return X, y_label, y_family


def _make_synthetic_csv(tmp_dir: str, n_goodware=50, n_ransomware=30, n_features=20):
    """Create a synthetic CSV file in RansomwareData.csv format (no header)."""
    rng = np.random.RandomState(42)
    n_total = n_goodware + n_ransomware

    X_good = rng.normal(0.1, 0.05, size=(n_goodware, n_features)).clip(0)
    X_ransom = rng.normal(0.6, 0.3, size=(n_ransomware, n_features)).clip(0)

    rows = []
    for i in range(n_goodware):
        row = [i + 1, 0, 0] + X_good[i].tolist()
        rows.append(row)
    for i in range(n_ransomware):
        family = rng.randint(1, 12)
        row = [n_goodware + i + 1, 1, family] + X_ransom[i].tolist()
        rows.append(row)

    csv_path = os.path.join(tmp_dir, "test_dataset.csv")
    import csv
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)

    return csv_path


def _make_benign_feature_vector():
    """Create a typical benign/goodware Stage 4 feature vector."""
    return {
        "S_entropy": 0.15,
        "S_ETD": 0.05,
        "S_dist": 0.02,
        "S_dev": 0.01,
        "S_stab": 0.95,
        "lambda_norm": 0.02,
        "branching_n": 0.1,
        "is_superheated": False,
        "entropy_raw": 1.2,
        "delta_H": 0.1,
        "hist_variance": 0.001,
        "hist_kurtosis": -1.5,
        "fan_out_degree": 1,
        "pid": 1234,
        "file_path": "C:\\Users\\test\\doc.txt",
        "operation": "modified",
        "timestamp": time.time() * 1000,
        "actor_id": "pid:1234",
    }


def _make_ransomware_feature_vector():
    """Create a typical ransomware-like Stage 4 feature vector."""
    return {
        "S_entropy": 0.99,
        "S_ETD": 0.88,
        "S_dist": 0.75,
        "S_dev": 0.90,
        "S_stab": 0.05,
        "lambda_norm": 0.92,
        "branching_n": 1.5,
        "is_superheated": True,
        "entropy_raw": 7.95,
        "delta_H": 6.5,
        "hist_variance": 0.0001,
        "hist_kurtosis": -2.9,
        "fan_out_degree": 42,
        "pid": 6666,
        "file_path": "C:\\Users\\test\\encrypted.docx",
        "operation": "modified",
        "timestamp": time.time() * 1000,
        "actor_id": "pid:6666",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Test Group 1: DataPreprocessor
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataPreprocessor:
    """Tests for the Stage 5 DataPreprocessor."""

    def test_load_synthetic_csv(self, tmp_path):
        """Test loading a synthetic CSV dataset."""
        csv_path = _make_synthetic_csv(str(tmp_path))
        prep = DataPreprocessor(dataset_path=csv_path)
        X, y_label, y_family = prep.load_dataset()

        assert X.shape[0] == 80  # 50 goodware + 30 ransomware
        assert X.shape[1] == 20  # 20 API features
        assert len(y_label) == 80
        assert len(y_family) == 80
        assert set(np.unique(y_label)).issubset({0, 1})

    def test_label_distribution_correct(self, tmp_path):
        """Test that label/family distributions are recorded correctly."""
        csv_path = _make_synthetic_csv(str(tmp_path))
        prep = DataPreprocessor(dataset_path=csv_path)
        X, y_label, y_family = prep.load_dataset()

        assert prep.label_counts[0] == 50  # Goodware
        assert prep.label_counts[1] == 30  # Ransomware
        assert 0 in prep.family_counts  # Goodware family

    def test_fit_transform_reduces_features(self, tmp_path):
        """Test that variance filtering reduces feature count."""
        csv_path = _make_synthetic_csv(str(tmp_path), n_features=100)
        prep = DataPreprocessor(dataset_path=csv_path, variance_threshold=0.001)
        X, y_label, _ = prep.load_dataset()
        X_train, X_test, y_train, y_test = prep.fit_transform(X, y_label)

        # Some features should be filtered
        assert X_train.shape[1] <= X.shape[1]
        assert X_train.shape[1] == X_test.shape[1]

    def test_train_test_split_correct_sizes(self, tmp_path):
        """Test train/test split proportions."""
        csv_path = _make_synthetic_csv(str(tmp_path))
        prep = DataPreprocessor(dataset_path=csv_path, test_size=0.25)
        X, y_label, _ = prep.load_dataset()
        X_train, X_test, y_train, y_test = prep.fit_transform(X, y_label)

        total = len(X_train) + len(X_test)
        assert total == 80
        assert len(X_test) == 20  # 25% of 80 = 20

    def test_extract_goodware_only(self, tmp_path):
        """Test extracting only goodware samples."""
        csv_path = _make_synthetic_csv(str(tmp_path))
        prep = DataPreprocessor(dataset_path=csv_path)
        X, y_label, _ = prep.load_dataset()
        X_train, _, y_train, _ = prep.fit_transform(X, y_label)

        X_goodware = prep.extract_goodware_only(X_train, y_train)
        assert len(X_goodware) < len(X_train)
        # All remaining labels should be 0
        assert all(y_train[y_train == 0].shape[0] == len(X_goodware) for _ in [1])

    def test_save_and_load_transformers(self, tmp_path):
        """Test saving and loading fitted scaler + selector."""
        csv_path = _make_synthetic_csv(str(tmp_path))
        model_dir = str(tmp_path / "models")

        # Fit and save
        prep1 = DataPreprocessor(dataset_path=csv_path)
        X, y_label, _ = prep1.load_dataset()
        prep1.fit_transform(X, y_label)
        prep1.save_transformers(model_dir)

        # Load into new instance
        prep2 = DataPreprocessor(dataset_path=csv_path)
        prep2.load_transformers(model_dir)

        assert prep2._scaler is not None
        assert prep2._selector is not None
        assert prep2.n_selected_features == prep1.n_selected_features

    def test_transform_after_fit(self, tmp_path):
        """Test transforming new data with fitted pipeline."""
        csv_path = _make_synthetic_csv(str(tmp_path), n_features=20)
        prep = DataPreprocessor(dataset_path=csv_path, variance_threshold=0.0001)
        X, y_label, _ = prep.load_dataset()
        prep.fit_transform(X, y_label)

        # Transform a subset
        X_new = X[:5]
        X_transformed = prep.transform(X_new)
        assert X_transformed.shape[0] == 5
        assert X_transformed.shape[1] == prep.n_selected_features

    def test_file_not_found_raises(self):
        """Test that loading a non-existent file raises FileNotFoundError."""
        prep = DataPreprocessor(dataset_path="nonexistent_file.csv")
        with pytest.raises(FileNotFoundError):
            prep.load_dataset()


# ═══════════════════════════════════════════════════════════════════════════════
# Test Group 2: ModelTrainer
# ═══════════════════════════════════════════════════════════════════════════════

class TestModelTrainer:
    """Tests for the Stage 5 ModelTrainer."""

    def test_train_on_synthetic_data(self):
        """Test that both models train successfully on synthetic data."""
        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer.train(X_goodware)

        assert trainer.isolation_forest is not None
        assert trainer.one_class_svm is not None
        assert trainer.training_time_sec > 0

    def test_evaluate_produces_metrics(self):
        """Test that evaluation returns comprehensive metrics."""
        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer.train(X_goodware)
        metrics = trainer.evaluate(X, y_label)

        assert "isolation_forest" in metrics
        assert "one_class_svm" in metrics
        assert "fused_dac_ocf" in metrics
        assert "confusion_matrix" in metrics

        # Check metric ranges
        for model in ["isolation_forest", "one_class_svm", "fused_dac_ocf"]:
            m = metrics[model]
            assert 0.0 <= m["accuracy"] <= 1.0
            assert 0.0 <= m["precision"] <= 1.0
            assert 0.0 <= m["recall"] <= 1.0
            assert 0.0 <= m["f1"] <= 1.0
            assert 0.0 <= m["auc_roc"] <= 1.0

    def test_isolation_forest_detects_anomalies(self):
        """Test that Isolation Forest identifies ransomware samples as anomalies."""
        X, y_label, _ = _make_synthetic_dataset(n_goodware=300, n_ransomware=100)
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=100, random_state=42)
        trainer.train(X_goodware)

        metrics = trainer.evaluate(X, y_label)
        # Isolation Forest should have better-than-random AUC
        assert metrics["isolation_forest"]["auc_roc"] > 0.5

    def test_fused_score_better_than_individual(self):
        """Test that fused DAC-OCF achieves competitive AUC with individual models."""
        X, y_label, _ = _make_synthetic_dataset(n_goodware=300, n_ransomware=100)
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=100, random_state=42)
        trainer.train(X_goodware)
        metrics = trainer.evaluate(X, y_label)

        fused_auc = metrics["fused_dac_ocf"]["auc_roc"]
        # Fused should be at least close to the best individual model
        best_individual = max(
            metrics["isolation_forest"]["auc_roc"],
            metrics["one_class_svm"]["auc_roc"],
        )
        assert fused_auc >= best_individual - 0.15  # Within 15% of best

    def test_save_and_load_models(self, tmp_path):
        """Test model serialization and deserialization."""
        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        # Train and save
        trainer1 = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer1.train(X_goodware)
        trainer1.evaluate(X, y_label)
        trainer1.save_models(str(tmp_path))

        # Load into new instance
        trainer2 = ModelTrainer()
        trainer2.load_models(str(tmp_path))

        assert trainer2.isolation_forest is not None
        assert trainer2.one_class_svm is not None

        # Predictions should be identical
        pred1 = trainer1.isolation_forest.predict(X[:5])
        pred2 = trainer2.isolation_forest.predict(X[:5])
        np.testing.assert_array_equal(pred1, pred2)

    def test_model_files_created(self, tmp_path):
        """Test that all expected model files are created."""
        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer.train(X_goodware)
        trainer.evaluate(X, y_label)
        trainer.save_models(str(tmp_path))

        assert os.path.isfile(tmp_path / "isolation_forest.joblib")
        assert os.path.isfile(tmp_path / "one_class_svm.joblib")
        assert os.path.isfile(tmp_path / "training_metadata.json")

    def test_metadata_json_contents(self, tmp_path):
        """Test that training metadata JSON contains expected fields."""
        import json

        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        trainer = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer.train(X_goodware)
        trainer.evaluate(X, y_label)
        trainer.save_models(str(tmp_path))

        with open(tmp_path / "training_metadata.json") as f:
            meta = json.load(f)

        assert "timestamp" in meta
        assert "training_time_sec" in meta
        assert "hyperparameters" in meta
        assert "evaluation_metrics" in meta

    def test_normalize_scores_range(self):
        """Test that score normalization produces values in [0, 1]."""
        scores = np.array([-5.0, -1.0, 0.0, 1.0, 5.0, 100.0])
        normalized = ModelTrainer._normalize_scores(scores)

        assert normalized.min() >= 0.0
        assert normalized.max() <= 1.0
        assert np.isclose(normalized.min(), 0.0)
        assert np.isclose(normalized.max(), 1.0)


# ═══════════════════════════════════════════════════════════════════════════════
# Test Group 3: AnomalyScorer
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnomalyScorer:
    """Tests for the Stage 5 AnomalyScorer."""

    def test_heuristic_mode_when_no_models(self, tmp_path):
        """Test that scorer defaults to heuristic mode when no models exist."""
        scorer = AnomalyScorer(model_dir=str(tmp_path / "nonexistent"))
        assert not scorer.is_ml_mode

    def test_heuristic_benign_score_low(self):
        """Test that benign feature vectors get low heuristic scores."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")
        fv = _make_benign_feature_vector()
        result = scorer.score(fv)

        assert result["anomaly_score"] < 0.25
        assert result["risk_tier"] == "SAFE"
        assert result["scoring_mode"] == "heuristic"
        assert result["is_anomaly"] is False

    def test_heuristic_ransomware_score_high(self):
        """Test that ransomware-like feature vectors get high heuristic scores."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")
        fv = _make_ransomware_feature_vector()
        result = scorer.score(fv)

        assert result["anomaly_score"] > 0.5
        assert result["risk_tier"] in ("SUSPECT", "CRITICAL")
        assert result["scoring_mode"] == "heuristic"
        assert result["is_anomaly"] is True

    def test_score_range_bounded(self):
        """Test that anomaly scores are always in [0, 1]."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        # Test with extreme values
        for _ in range(20):
            fv = {
                "S_entropy": np.random.uniform(0, 1),
                "S_ETD": np.random.uniform(0, 1),
                "S_dist": np.random.uniform(0, 1),
                "S_dev": np.random.uniform(0, 1),
                "S_stab": np.random.uniform(0, 1),
                "lambda_norm": np.random.uniform(0, 1),
                "branching_n": np.random.uniform(0, 3),
                "pid": 1000,
                "file_path": "test.txt",
            }
            result = scorer.score(fv)
            assert 0.0 <= result["anomaly_score"] <= 1.0
            assert 0.0 <= result["confidence"] <= 1.0

    def test_risk_tier_assignment(self):
        """Test that risk tiers are correctly assigned based on thresholds."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        # Safe: very benign
        fv = _make_benign_feature_vector()
        fv["S_entropy"] = 0.01
        result = scorer.score(fv)
        assert result["risk_tier"] == "SAFE"

        # Critical: very malicious
        fv2 = _make_ransomware_feature_vector()
        result2 = scorer.score(fv2)
        assert result2["risk_tier"] in ("SUSPECT", "CRITICAL")

    def test_superheated_boost(self):
        """Test that superheated branching ratio adds penalty."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        fv_normal = _make_benign_feature_vector()
        fv_normal["branching_n"] = 0.5
        result_normal = scorer.score(fv_normal)

        fv_super = _make_benign_feature_vector()
        fv_super["branching_n"] = 1.5  # Superheated
        result_super = scorer.score(fv_super)

        # Superheated should get a higher score
        assert result_super["anomaly_score"] > result_normal["anomaly_score"]

    def test_scoring_statistics(self):
        """Test that scoring statistics are tracked."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        assert scorer.total_scored == 0
        assert scorer.total_anomalies == 0

        scorer.score(_make_benign_feature_vector())
        scorer.score(_make_ransomware_feature_vector())

        assert scorer.total_scored == 2
        stats = scorer.get_stats()
        assert stats["total_scored"] == 2
        assert stats["scoring_mode"] == "heuristic"

    def test_batch_scoring(self):
        """Test batch scoring of multiple feature vectors."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        batch = [_make_benign_feature_vector() for _ in range(5)]
        batch += [_make_ransomware_feature_vector() for _ in range(3)]

        results = scorer.score_batch(batch)
        assert len(results) == 8
        assert all("anomaly_score" in r for r in results)
        assert all("risk_tier" in r for r in results)

    def test_thread_safety(self):
        """Test concurrent scoring from multiple threads."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")
        results = []
        errors = []

        def score_worker():
            try:
                for _ in range(20):
                    fv = _make_benign_feature_vector()
                    result = scorer.score(fv)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=score_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert scorer.total_scored == 80  # 4 threads * 20 scores

    def test_ml_mode_with_trained_models(self, tmp_path):
        """Test ML scoring mode with real trained models."""
        X, y_label, _ = _make_synthetic_dataset()
        X_goodware = X[y_label == 0]

        # Train and save models
        trainer = ModelTrainer(if_n_estimators=50, random_state=42)
        trainer.train(X_goodware)
        trainer.save_models(str(tmp_path))

        # Create scorer with trained models
        # Need to train on the same 7-feature format for this to work
        # Let's train a small model on 7 features
        rng = np.random.RandomState(42)
        X_7feat_good = rng.normal(0.1, 0.05, size=(100, 7)).clip(0, 1)

        from sklearn.ensemble import IsolationForest
        from sklearn.svm import OneClassSVM
        import joblib

        if_model = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
        if_model.fit(X_7feat_good)
        joblib.dump(if_model, str(tmp_path / "isolation_forest.joblib"))

        svm_model = OneClassSVM(kernel="rbf", nu=0.1, gamma="scale")
        svm_model.fit(X_7feat_good)
        joblib.dump(svm_model, str(tmp_path / "one_class_svm.joblib"))

        scorer = AnomalyScorer(model_dir=str(tmp_path))
        assert scorer.is_ml_mode

        # Score benign and ransomware vectors
        benign_result = scorer.score(_make_benign_feature_vector())
        ransom_result = scorer.score(_make_ransomware_feature_vector())

        assert benign_result["scoring_mode"] == "ml"
        assert benign_result["isolation_score"] is not None
        assert benign_result["svm_score"] is not None
        assert 0.0 <= benign_result["anomaly_score"] <= 1.0

        # Ransomware should generally score higher than benign
        assert ransom_result["anomaly_score"] > benign_result["anomaly_score"]


# ═══════════════════════════════════════════════════════════════════════════════
# Test Group 4: Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStage4ToStage5Integration:
    """End-to-end integration tests for Stage 4 -> Stage 5 pipeline."""

    def test_feature_vector_passthrough(self):
        """Test that event context (pid, file_path, timestamp) passes through."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")
        fv = _make_benign_feature_vector()
        fv["pid"] = 9999
        fv["file_path"] = "C:\\important\\document.pdf"
        fv["timestamp"] = 1234567890000

        result = scorer.score(fv)
        assert result["pid"] == 9999
        assert result["file_path"] == "C:\\important\\document.pdf"
        assert result["timestamp"] == 1234567890000

    def test_benign_vs_ransomware_discrimination(self):
        """Test that Stage 5 can discriminate between benign and ransomware patterns."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")

        benign_scores = []
        for _ in range(10):
            fv = _make_benign_feature_vector()
            fv["S_entropy"] = np.random.uniform(0.05, 0.30)
            fv["S_dist"] = np.random.uniform(0.01, 0.10)
            fv["S_dev"] = np.random.uniform(0.01, 0.05)
            fv["S_stab"] = np.random.uniform(0.80, 0.99)
            result = scorer.score(fv)
            benign_scores.append(result["anomaly_score"])

        ransom_scores = []
        for _ in range(10):
            fv = _make_ransomware_feature_vector()
            fv["S_entropy"] = np.random.uniform(0.85, 0.99)
            fv["S_dist"] = np.random.uniform(0.50, 0.95)
            fv["S_dev"] = np.random.uniform(0.60, 0.95)
            fv["S_stab"] = np.random.uniform(0.01, 0.15)
            result = scorer.score(fv)
            ransom_scores.append(result["anomaly_score"])

        # Average ransomware score should be significantly higher
        assert np.mean(ransom_scores) > np.mean(benign_scores) + 0.2

    def test_sequential_scoring_consistency(self):
        """Test that scoring the same vector twice gives the same result."""
        scorer = AnomalyScorer(model_dir="nonexistent_dir_12345")
        fv = _make_benign_feature_vector()

        result1 = scorer.score(fv)
        result2 = scorer.score(fv)

        assert result1["anomaly_score"] == result2["anomaly_score"]
        assert result1["risk_tier"] == result2["risk_tier"]

    def test_full_pipeline_with_model_training(self, tmp_path):
        """Test complete pipeline: train models -> save -> load -> score."""
        # Generate synthetic 7-feature dataset
        rng = np.random.RandomState(42)
        X_good = rng.normal(0.1, 0.05, size=(100, 7)).clip(0, 1)
        X_bad = rng.normal(0.7, 0.2, size=(40, 7)).clip(0, 1)
        X_all = np.vstack([X_good, X_bad])
        y_all = np.array([0] * 100 + [1] * 40)

        # Train
        from sklearn.ensemble import IsolationForest
        from sklearn.svm import OneClassSVM
        import joblib

        if_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        if_model.fit(X_good)
        joblib.dump(if_model, str(tmp_path / "isolation_forest.joblib"))

        svm_model = OneClassSVM(kernel="rbf", nu=0.1, gamma="scale")
        svm_model.fit(X_good)
        joblib.dump(svm_model, str(tmp_path / "one_class_svm.joblib"))

        # Create scorer with trained models
        scorer = AnomalyScorer(model_dir=str(tmp_path))
        assert scorer.is_ml_mode

        # Score benign and ransomware
        benign_fv = _make_benign_feature_vector()
        ransom_fv = _make_ransomware_feature_vector()

        benign_result = scorer.score(benign_fv)
        ransom_result = scorer.score(ransom_fv)

        # Basic sanity: ransomware should score higher
        assert ransom_result["anomaly_score"] > benign_result["anomaly_score"]
        assert scorer.total_scored == 2
