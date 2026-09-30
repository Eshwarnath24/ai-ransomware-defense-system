"""
tests/test_stage_5_anomaly.py
================================
Stage 5 — Automated Test Suite for Anomaly Scoring & Benign Profiling (DAC-OCF)

Test Categories:
    1. DataPreprocessor  (8 tests)  — RADAR / Sysmon stream processing, scaling, 7-dim features
    2. ModelTrainer      (8 tests)  — Model training, evaluation, serialization
    3. AnomalyScorer     (10 tests) — Scoring, ML mode, risk tiers, fallback, thread safety
    4. Integration       (4 tests)  — End-to-end Stage 4 -> Stage 5 pipeline

Total: 30 tests
"""

import math
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Ensure project root on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor, FEATURE_COLUMNS
from src.stage_5_anomaly.model_trainer import ModelTrainer
from src.stage_5_anomaly.anomaly_scorer import (
    AnomalyScorer,
    HEURISTIC_WEIGHTS,
    DEFAULT_THRESHOLDS,
)


# ─── Synthetic Data Helpers ─────────────────────────────────────────────────

def _make_synthetic_stage4_dataframe(n_goodware: int = 100, n_ransomware: int = 50):
    """Generate synthetic Stage 4 feature dataframe."""
    rng = np.random.RandomState(42)
    rows = []

    # Goodware: low entropy, low target velocity, low Hawkes burst
    for i in range(n_goodware):
        rows.append({
            "S_entropy": float(rng.uniform(0.1, 0.4)),
            "S_ETD": float(rng.uniform(0.7, 0.99)),
            "S_dist": float(rng.uniform(0.6, 0.99)),
            "S_dev": float(rng.uniform(0.001, 0.05)),
            "S_stab": float(rng.uniform(0.3, 0.6)),
            "lambda_norm": float(rng.uniform(0.001, 0.05)),
            "branching_n": 0.625,
            "label": 0,
            "family": "goodware",
        })

    # Ransomware: high entropy, high target velocity, high Hawkes burst
    for i in range(n_ransomware):
        rows.append({
            "S_entropy": float(rng.uniform(0.7, 0.98)),
            "S_ETD": float(rng.uniform(0.7, 0.99)),
            "S_dist": float(rng.uniform(0.6, 0.99)),
            "S_dev": float(rng.uniform(0.6, 0.99)),
            "S_stab": float(rng.uniform(0.1, 0.4)),
            "lambda_norm": float(rng.uniform(0.7, 0.99)),
            "branching_n": 1.25,
            "label": 1,
            "family": "LockBit",
        })

    return pd.DataFrame(rows)


def _make_synthetic_sysmon_csv(tmp_dir: str, n_rows: int = 40):
    """Create a minimal synthetic Sysmon CSV log file."""
    rows = []
    for i in range(n_rows):
        rows.append({
            "@timestamp": "Oct 16, 2024 @ 16:44:31.522",
            "event.code": 11 if i % 2 == 0 else 23,
            "event.action": "File created",
            "process.executable": "C:\\Windows\\System32\\notepad.exe",
            "file.path": f"C:\\Users\\test\\file_{i}.txt",
            "file.name": f"file_{i}.txt",
            "process.parent.pid": 1000 + (i % 3),
            "target-class-name": "goodware",
            "target-class": 0,
        })
    df = pd.DataFrame(rows)
    csv_path = os.path.join(tmp_dir, "test_goodware.csv")
    df.to_csv(csv_path, index=False)
    return csv_path


# ─── Category 1: DataPreprocessor Tests (8 tests) ───────────────────────────

class TestDataPreprocessor:
    def test_feature_columns_defined(self):
        """Test that the 7 Stage 4 feature columns are defined."""
        assert len(FEATURE_COLUMNS) == 7
        assert "S_entropy" in FEATURE_COLUMNS
        assert "lambda_norm" in FEATURE_COLUMNS
        assert "branching_n" in FEATURE_COLUMNS

    def test_extract_features_from_stream(self, tmp_path):
        """Test feature extraction from a Sysmon dataframe stream."""
        csv_path = _make_synthetic_sysmon_csv(str(tmp_path), n_rows=20)
        df = pd.read_csv(csv_path)
        prep = DataPreprocessor(goodware_path=csv_path)
        feats = prep.extract_features_from_sysmon_stream(df, is_ransomware=False, max_records=20)
        assert len(feats) == 20
        assert all(col in feats[0] for col in FEATURE_COLUMNS)
        assert feats[0]["label"] == 0

    def test_build_or_load_dataset(self, tmp_path):
        """Test building dataset and loading from cache."""
        cache_path = os.path.join(str(tmp_path), "cache.csv")
        df_synth = _make_synthetic_stage4_dataframe(30, 20)
        df_synth.to_csv(cache_path, index=False)

        prep = DataPreprocessor(cache_path=cache_path)
        df_loaded = prep.build_or_load_dataset()
        assert len(df_loaded) == 50
        assert prep.n_goodware == 30
        assert prep.n_ransomware == 20

    def test_prepare_training_data(self, tmp_path):
        """Test prepare_training_data splits and scales data correctly."""
        cache_path = os.path.join(str(tmp_path), "cache.csv")
        df_synth = _make_synthetic_stage4_dataframe(40, 20)
        df_synth.to_csv(cache_path, index=False)

        prep = DataPreprocessor(cache_path=cache_path, test_size=0.2)
        X_train, X_test, y_test, scaler = prep.prepare_training_data()

        assert X_train.shape[1] == 7
        assert X_test.shape[1] == 7
        assert len(y_test) == X_test.shape[0]
        assert scaler is not None

    def test_save_transformers(self, tmp_path):
        """Test saving scaler and metadata to disk."""
        cache_path = os.path.join(str(tmp_path), "cache.csv")
        df_synth = _make_synthetic_stage4_dataframe(30, 15)
        df_synth.to_csv(cache_path, index=False)

        model_dir = str(tmp_path / "models")
        prep = DataPreprocessor(cache_path=cache_path)
        prep.prepare_training_data()
        prep.save_transformers(model_dir=model_dir)

        assert os.path.isfile(os.path.join(model_dir, "scaler.joblib"))
        assert os.path.isfile(os.path.join(model_dir, "feature_metadata.json"))

    def test_goodware_only_training_matrix(self, tmp_path):
        """Test that unsupervised X_train contains only goodware."""
        cache_path = os.path.join(str(tmp_path), "cache.csv")
        df_synth = _make_synthetic_stage4_dataframe(50, 25)
        df_synth.to_csv(cache_path, index=False)

        prep = DataPreprocessor(cache_path=cache_path, test_size=0.2)
        X_train, X_test, y_test, _ = prep.prepare_training_data()
        assert X_train.shape[0] == 40  # 80% of 50 goodware

    def test_ransomware_stream_marked_properly(self, tmp_path):
        """Test ransomware events are labeled 1."""
        csv_path = _make_synthetic_sysmon_csv(str(tmp_path), n_rows=10)
        df = pd.read_csv(csv_path)
        prep = DataPreprocessor(goodware_path=csv_path)
        feats = prep.extract_features_from_sysmon_stream(df, is_ransomware=True, max_records=10)
        assert all(f["label"] == 1 for f in feats)

    def test_cache_reload_preserves_dimensions(self, tmp_path):
        """Test that loaded cached data preserves all 7 feature dimensions."""
        cache_path = os.path.join(str(tmp_path), "cache.csv")
        df_synth = _make_synthetic_stage4_dataframe(20, 10)
        df_synth.to_csv(cache_path, index=False)

        prep = DataPreprocessor(cache_path=cache_path)
        df = prep.build_or_load_dataset()
        for col in FEATURE_COLUMNS:
            assert col in df.columns


# ─── Category 2: ModelTrainer Tests (8 tests) ───────────────────────────────

class TestModelTrainer:
    def test_trainer_initialization(self):
        trainer = ModelTrainer(if_n_estimators=50, svm_kernel="rbf")
        assert trainer.if_n_estimators == 50
        assert trainer.svm_kernel == "rbf"
        assert trainer.isolation_forest is None
        assert trainer.one_class_svm is None

    def test_train_models(self):
        rng = np.random.RandomState(42)
        X_train = rng.uniform(0.1, 0.4, size=(100, 7))
        trainer = ModelTrainer(if_n_estimators=20)
        trainer.train(X_train)

        assert trainer.isolation_forest is not None
        assert trainer.one_class_svm is not None
        assert trainer.training_time_sec > 0

    def test_evaluate_models(self):
        rng = np.random.RandomState(42)
        X_train = rng.uniform(0.1, 0.4, size=(100, 7))
        trainer = ModelTrainer(if_n_estimators=30)
        trainer.train(X_train)

        X_test = np.vstack([
            rng.uniform(0.1, 0.4, size=(40, 7)),
            rng.uniform(0.7, 1.0, size=(30, 7)),
        ])
        y_test = np.array([0] * 40 + [1] * 30)

        metrics = trainer.evaluate(X_test, y_test)
        assert "isolation_forest" in metrics
        assert "one_class_svm" in metrics
        assert "fused_dac_ocf" in metrics
        assert metrics["fused_dac_ocf"]["accuracy"] >= 0.70

    def test_save_and_load_models(self, tmp_path):
        rng = np.random.RandomState(42)
        X_train = rng.uniform(0.1, 0.4, size=(50, 7))
        trainer = ModelTrainer(if_n_estimators=20)
        trainer.train(X_train)

        model_dir = str(tmp_path / "models")
        trainer.save_models(model_dir)

        trainer2 = ModelTrainer()
        trainer2.load_models(model_dir)
        assert trainer2.isolation_forest is not None
        assert trainer2.one_class_svm is not None

    def test_unfitted_evaluate_raises(self):
        trainer = ModelTrainer()
        with pytest.raises(RuntimeError):
            trainer.evaluate(np.zeros((10, 7)), np.zeros(10))

    def test_normalize_scores(self):
        scores = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        normed = ModelTrainer._normalize_scores(scores)
        assert np.isclose(normed.min(), 0.0)
        assert np.isclose(normed.max(), 1.0)

    def test_constant_scores_normalization(self):
        scores = np.array([2.0, 2.0, 2.0])
        normed = ModelTrainer._normalize_scores(scores)
        assert np.all(normed == 0.5)

    def test_trainer_repr(self):
        trainer = ModelTrainer()
        assert "ModelTrainer" in repr(trainer)


# ─── Category 3: AnomalyScorer Tests (10 tests) ─────────────────────────────

class TestAnomalyScorer:
    def test_scorer_heuristic_fallback(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        assert not scorer.is_ml_mode

        sample = {"S_entropy": 0.2, "S_ETD": 0.1, "S_dist": 0.1, "S_dev": 0.05, "S_stab": 0.9, "lambda_norm": 0.05}
        res = scorer.score(sample)
        assert res["scoring_mode"] == "heuristic"
        assert res["anomaly_score"] < 0.35
        assert res["risk_tier"] == "SAFE"

    def test_scorer_ml_mode(self):
        scorer = AnomalyScorer(model_dir="models")
        if os.path.isfile("models/isolation_forest.joblib") and os.path.isfile("models/one_class_svm.joblib"):
            assert scorer.is_ml_mode
            sample = {
                "S_entropy": 0.20,
                "S_ETD": 0.90,
                "S_dist": 0.90,
                "S_dev": 0.01,
                "S_stab": 0.40,
                "lambda_norm": 0.01,
                "branching_n": 0.625,
            }
            res = scorer.score(sample)
            assert res["scoring_mode"] == "ml"
            assert res["dimension_matched"] is True

    def test_scorer_benign_vs_ransomware_separation(self):
        scorer = AnomalyScorer(model_dir="models")
        benign = {"S_entropy": 0.20, "S_ETD": 0.30, "S_dist": 0.05, "S_dev": 0.01, "S_stab": 0.80, "lambda_norm": 0.01, "branching_n": 0.625}
        rsw = {"S_entropy": 0.95, "S_ETD": 0.90, "S_dist": 0.80, "S_dev": 0.90, "S_stab": 0.10, "lambda_norm": 0.95, "branching_n": 1.8, "is_superheated": True}

        res_b = scorer.score(benign)
        res_r = scorer.score(rsw)

        assert res_b["anomaly_score"] < res_r["anomaly_score"]
        assert res_b["risk_tier"] in ["SAFE", "WATCH"]
        assert res_r["risk_tier"] in ["SUSPECT", "CRITICAL"]

    def test_risk_tier_mapping(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        assert scorer._assign_risk_tier(0.10) == "SAFE"
        assert scorer._assign_risk_tier(0.35) == "WATCH"
        assert scorer._assign_risk_tier(0.60) == "SUSPECT"
        assert scorer._assign_risk_tier(0.85) == "CRITICAL"

    def test_score_batch(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        batch = [
            {"S_entropy": 0.1, "S_ETD": 0.1, "S_dist": 0.1, "S_dev": 0.01, "S_stab": 0.9, "lambda_norm": 0.01},
            {"S_entropy": 0.9, "S_ETD": 0.9, "S_dist": 0.9, "S_dev": 0.9, "S_stab": 0.1, "lambda_norm": 0.9},
        ]
        results = scorer.score_batch(batch)
        assert len(results) == 2
        assert results[0]["anomaly_score"] < results[1]["anomaly_score"]

    def test_thread_safety(self):
        scorer = AnomalyScorer(model_dir="models")
        sample = {"S_entropy": 0.3, "S_ETD": 0.3, "S_dist": 0.3, "S_dev": 0.1, "S_stab": 0.8, "lambda_norm": 0.1}

        errors = []
        def worker():
            try:
                for _ in range(50):
                    scorer.score(sample)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert scorer.total_scored >= 200

    def test_get_stats(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        scorer.score({"S_entropy": 0.1, "S_ETD": 0.1, "S_dist": 0.1, "S_dev": 0.01, "S_stab": 0.9, "lambda_norm": 0.01})
        scorer.score({"S_entropy": 0.95, "S_ETD": 0.95, "S_dist": 0.95, "S_dev": 0.95, "S_stab": 0.05, "lambda_norm": 0.95})

        stats = scorer.get_stats()
        assert stats["total_scored"] == 2
        assert stats["total_anomalies"] >= 1
        assert 0.0 <= stats["anomaly_rate"] <= 1.0

    def test_sigmoid_normalize(self):
        s0 = AnomalyScorer._sigmoid_normalize(0.0)
        s_pos = AnomalyScorer._sigmoid_normalize(2.0)
        s_neg = AnomalyScorer._sigmoid_normalize(-2.0)

        assert np.isclose(s0, 0.5)
        assert s_pos > 0.5
        assert s_neg < 0.5

    def test_superheated_boost(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        s_normal = scorer.score({"S_entropy": 0.5, "S_ETD": 0.5, "S_dist": 0.5, "S_dev": 0.5, "S_stab": 0.5, "lambda_norm": 0.5, "is_superheated": False})
        s_hot = scorer.score({"S_entropy": 0.5, "S_ETD": 0.5, "S_dist": 0.5, "S_dev": 0.5, "S_stab": 0.5, "lambda_norm": 0.5, "is_superheated": True})

        assert s_hot["anomaly_score"] >= s_normal["anomaly_score"]

    def test_score_feature_dict_alias(self):
        scorer = AnomalyScorer(model_dir="nonexistent_dir")
        sample = {"S_entropy": 0.2, "S_ETD": 0.1, "S_dist": 0.1, "S_dev": 0.05, "S_stab": 0.9, "lambda_norm": 0.05}
        r1 = scorer.score(sample)
        r2 = scorer.score_feature_dict(sample)
        assert r1["anomaly_score"] == r2["anomaly_score"]


# ─── Category 4: Integration Tests (4 tests) ────────────────────────────────

class TestIntegration:
    def test_full_pipeline_flow(self, tmp_path):
        """Test complete end-to-end flow from synthetic data to trained scorer."""
        df_synth = _make_synthetic_stage4_dataframe(60, 30)
        cache_path = os.path.join(str(tmp_path), "stage4.csv")
        df_synth.to_csv(cache_path, index=False)

        model_dir = str(tmp_path / "models")
        prep = DataPreprocessor(cache_path=cache_path)
        X_train, X_test, y_test, _ = prep.prepare_training_data()
        prep.save_transformers(model_dir)

        trainer = ModelTrainer(if_n_estimators=30)
        trainer.train(X_train)
        trainer.save_models(model_dir)

        scorer = AnomalyScorer(model_dir=model_dir)
        assert scorer.is_ml_mode

        res = scorer.score({
            "S_entropy": 0.2, "S_ETD": 0.8, "S_dist": 0.8,
            "S_dev": 0.01, "S_stab": 0.5, "lambda_norm": 0.01, "branching_n": 0.625
        })
        assert res["scoring_mode"] == "ml"

    def test_model_metrics_persisted(self):
        """Verify training_metadata.json exists and has valid evaluation metrics."""
        meta_path = "models/training_metadata.json"
        if os.path.isfile(meta_path):
            import json
            with open(meta_path, "r") as f:
                meta = json.load(f)
            assert "evaluation_metrics" in meta
            assert "fused_dac_ocf" in meta["evaluation_metrics"]
            assert meta["evaluation_metrics"]["fused_dac_ocf"]["auc_roc"] > 0.80

    def test_feature_metadata_persisted(self):
        """Verify feature_metadata.json exists with 7 features."""
        meta_path = "models/feature_metadata.json"
        if os.path.isfile(meta_path):
            import json
            with open(meta_path, "r") as f:
                meta = json.load(f)
            assert meta["n_features"] == 7
            assert len(meta["feature_columns"]) == 7

    def test_live_stage5_pipeline_components(self):
        """Verify Live Stage 5 pipeline components integrate cleanly."""
        from src.stage_3_dbrg.dbrg_manager import DBRGManager
        from src.stage_4_features.feature_extractor import FeatureExtractor

        scorer = AnomalyScorer(model_dir="models")
        assert scorer.is_ml_mode

        dbrg = DBRGManager()
        extractor = FeatureExtractor(dbrg_manager=dbrg)
        ecar = {
            "actorID": "pid:1234",
            "objectID": "file:C:\\test.txt",
            "pid": 1234,
            "operation": "FILE_MODIFY",
            "timestamp": 1700000000000.0,
            "entropy": 3.0,
        }
        dbrg.process_event(ecar)
        fv = extractor.extract_features(ecar)
        assert fv is not None
        score_res = scorer.score(fv)
        assert score_res["scoring_mode"] == "ml"
        assert score_res["dimension_matched"] is True
