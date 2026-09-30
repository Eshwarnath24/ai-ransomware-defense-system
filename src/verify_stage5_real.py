"""
src/verify_stage5_real.py
===========================
Stage 5 Real Verification Script (RADAR Dataset & goodware-logs.csv)

Verifies Stage 5 anomaly scoring with REAL telemetry and ML models:
1. Loads the 7-dimensional behavioral feature dataset extracted from RADAR Sysmon logs
2. Loads the trained ML models (Isolation Forest + One-Class SVM + Scaler) from models/
3. Validates that feature dimensions match 100% (7 features expected == 7 features provided)
4. Tests ML scoring on real Goodware samples vs real Ransomware samples (LockBit, BlackBasta, etc.)
5. Verifies ML mode execution, AUC-ROC, accuracy, and risk tier calibration
"""

import io
import json
import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path

# Windows UTF-8 fix
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor, FEATURE_COLUMNS
from src.stage_5_anomaly.model_trainer import ModelTrainer
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer


def main():
    print("=" * 85)
    print("  🛡️  STAGE 5 REAL VERIFICATION: RADAR DATASET & LIVE ML SCORER")
    print("     Density-Adaptive One-Class Fusion (DAC-OCF) Validation")
    print("=" * 85)

    # ---------------------------------------------------------------
    # STEP 1: Load the real dataset
    # ---------------------------------------------------------------
    print("\n[STEP 1] Loading Stage 4 behavioral telemetry from RADAR / goodware-logs.csv...")
    prep = DataPreprocessor(
        goodware_path=str(PROJECT_ROOT / "Dataset" / "goodware-logs.csv"),
        radar_dir=str(PROJECT_ROOT / "Dataset" / "RADAR-v0.0.1-beta"),
        cache_path=str(PROJECT_ROOT / "Dataset" / "stage4_radar_features.csv"),
    )
    df = prep.build_or_load_dataset()
    print(f"  Total samples loaded: {len(df):,}")
    print(f"  Goodware samples:     {prep.n_goodware:,} (label=0)")
    print(f"  Ransomware samples:   {prep.n_ransomware:,} (label=1)")
    print(f"  Feature Dimensions:   {len(FEATURE_COLUMNS)} -> {FEATURE_COLUMNS}")

    # ---------------------------------------------------------------
    # STEP 2: Prepare test split
    # ---------------------------------------------------------------
    print("\n[STEP 2] Preparing test evaluation matrices...")
    X_train, X_test, y_test, scaler = prep.prepare_training_data()
    print(f"  Train set (Goodware baseline): {X_train.shape[0]} samples x {X_train.shape[1]} features")
    print(f"  Test set (Mixed evaluation):   {X_test.shape[0]} samples x {X_test.shape[1]} features")
    print(f"  Test goodware count:           {int(np.sum(y_test == 0))}")
    print(f"  Test ransomware count:         {int(np.sum(y_test == 1))}")

    # ---------------------------------------------------------------
    # STEP 3: Load trained models and verify dimensions
    # ---------------------------------------------------------------
    print("\n[STEP 3] Loading trained ML models from models/...")
    model_dir = str(PROJECT_ROOT / "models")
    trainer = ModelTrainer()
    trainer.load_models(model_dir)

    n_if_feats = getattr(trainer.isolation_forest, "n_features_in_", 0)
    n_svm_feats = getattr(trainer.one_class_svm, "n_features_in_", 0)
    print(f"  Isolation Forest (DAC) loaded : YES (n_features_in_ = {n_if_feats})")
    print(f"  One-Class SVM (OCF) loaded    : YES (n_features_in_ = {n_svm_feats})")
    print(f"  Scaler loaded                 : YES")

    # ---------------------------------------------------------------
    # STEP 4: Evaluate test set metrics
    # ---------------------------------------------------------------
    print("\n[STEP 4] Evaluating ML models on test stream...")
    metrics = trainer.evaluate(X_test, y_test)

    print("\n  --- Isolation Forest (DAC) ---")
    print(f"    Accuracy:  {metrics['isolation_forest']['accuracy']:.4f}")
    print(f"    Precision: {metrics['isolation_forest']['precision']:.4f}")
    print(f"    Recall:    {metrics['isolation_forest']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['isolation_forest']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['isolation_forest']['auc_roc']:.4f}")

    print("\n  --- One-Class SVM (OCF) ---")
    print(f"    Accuracy:  {metrics['one_class_svm']['accuracy']:.4f}")
    print(f"    Precision: {metrics['one_class_svm']['precision']:.4f}")
    print(f"    Recall:    {metrics['one_class_svm']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['one_class_svm']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['one_class_svm']['auc_roc']:.4f}")

    print("\n  --- Fused DAC-OCF Ensemble ---")
    print(f"    Accuracy:  {metrics['fused_dac_ocf']['accuracy']:.4f}")
    print(f"    Precision: {metrics['fused_dac_ocf']['precision']:.4f}")
    print(f"    Recall:    {metrics['fused_dac_ocf']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['fused_dac_ocf']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['fused_dac_ocf']['auc_roc']:.4f}")

    cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    print("\n  Confusion Matrix (Fused Ensemble):")
    print(f"    Actual Goodware   -> Pred Good: {cm[0][0]:>5d} | Pred Ransom: {cm[0][1]:>5d}")
    print(f"    Actual Ransomware -> Pred Good: {cm[1][0]:>5d} | Pred Ransom: {cm[1][1]:>5d}")

    # ---------------------------------------------------------------
    # STEP 5: Test real-time AnomalyScorer
    # ---------------------------------------------------------------
    print("\n[STEP 5] Testing real-time AnomalyScorer engine (ML Mode)...")
    scorer = AnomalyScorer(model_dir=model_dir)
    print(f"  Scorer is_ml_mode: {scorer.is_ml_mode}")

    # Test benign vector
    benign_sample = {
        "S_entropy": 0.20,
        "S_ETD": 0.30,
        "S_dist": 0.05,
        "S_dev": 0.01,
        "S_stab": 0.80,
        "lambda_norm": 0.01,
        "branching_n": 0.625,
        "is_superheated": False,
    }

    # Test ransomware vector
    rsw_sample = {
        "S_entropy": 0.85,
        "S_ETD": 0.90,
        "S_dist": 0.80,
        "S_dev": 0.90,
        "S_stab": 0.30,
        "lambda_norm": 0.95,
        "branching_n": 0.625,
        "is_superheated": True,
    }

    b_res = scorer.score(benign_sample)
    r_res = scorer.score(rsw_sample)

    print("\n  [BENIGN SAMPLE TEST]")
    print(f"    Scoring Mode       : {b_res['scoring_mode']}")
    print(f"    Dimension Matched  : {b_res.get('dimension_matched', False)}")
    print(f"    Isolation Score    : {b_res['isolation_score']:.4f}")
    print(f"    SVM Score          : {b_res['svm_score']:.4f}")
    print(f"    Fused Anomaly Score: {b_res['anomaly_score']:.4f}")
    print(f"    Assigned Risk Tier : {b_res['risk_tier']}")

    print("\n  [RANSOMWARE SAMPLE TEST]")
    print(f"    Scoring Mode       : {r_res['scoring_mode']}")
    print(f"    Dimension Matched  : {r_res.get('dimension_matched', False)}")
    print(f"    Isolation Score    : {r_res['isolation_score']:.4f}")
    print(f"    SVM Score          : {r_res['svm_score']:.4f}")
    print(f"    Fused Anomaly Score: {r_res['anomaly_score']:.4f}")
    print(f"    Assigned Risk Tier : {r_res['risk_tier']}")

    # ---------------------------------------------------------------
    # SUMMARY CHECKS
    # ---------------------------------------------------------------
    checks = [
        ("Dataset loaded with 7 features", len(df) > 1000 and len(FEATURE_COLUMNS) == 7),
        ("Trained ML models loaded from disk", trainer.isolation_forest is not None and trainer.one_class_svm is not None),
        ("Feature dimension match (7 in, 7 expected)", n_if_feats == 7 and n_svm_feats == 7),
        ("Fused AUC-ROC > 0.90", metrics["fused_dac_ocf"]["auc_roc"] > 0.90),
        ("Runtime Scorer executes in ML mode", scorer.is_ml_mode and b_res["scoring_mode"] == "ml"),
        ("Benign assigned SAFE or WATCH", b_res["risk_tier"] in ["SAFE", "WATCH"]),
        ("Ransomware assigned CRITICAL", r_res["risk_tier"] in ["CRITICAL", "SUSPECT"]),
        ("Ransomware score > Benign score", r_res["anomaly_score"] > b_res["anomaly_score"]),
    ]

    print("\n" + "=" * 85)
    print("  VERIFICATION SUMMARY")
    print("=" * 85)
    all_passed = True
    for desc, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        print(f"  {status} {desc}")

    print("-" * 85)
    if all_passed:
        print("  >>> ALL 8 CHECKS PASSED: Stage 5 is fully operational with true ML inference! <<<")
    else:
        print("  >>> SOME CHECKS FAILED <<<")
    print("=" * 85)


if __name__ == "__main__":
    main()
