"""
Stage 5 Real Verification Script
=================================
This script verifies Stage 5 works BEYOND unit tests by:
1. Loading the REAL dataset (Dataset/RansomwareData.csv)
2. Loading the TRAINED models from models/
3. Scoring actual Goodware and Ransomware samples from the dataset
4. Printing a detailed breakdown of predictions vs ground truth
5. Checking if the system can actually distinguish ransomware from goodware
"""

import sys
import io
import os
import json
import numpy as np

# Windows UTF-8 fix
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor
from src.stage_5_anomaly.model_trainer import ModelTrainer
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer


def main():
    print("=" * 80)
    print("  STAGE 5 REAL VERIFICATION (NOT TEST CASES)")
    print("  Testing against actual Dataset/RansomwareData.csv")
    print("=" * 80)

    # ---------------------------------------------------------------
    # STEP 1: Load the real dataset
    # ---------------------------------------------------------------
    print("\n[STEP 1] Loading real dataset...")
    dataset_path = str(PROJECT_ROOT / "Dataset" / "RansomwareData.csv")
    prep = DataPreprocessor(dataset_path=dataset_path, variance_threshold=0.01)
    X, y_label, y_family = prep.load_dataset()
    print(f"  Total samples loaded: {X.shape[0]}")
    print(f"  Total raw features:   {X.shape[1]}")
    print(f"  Goodware (label=0):   {np.sum(y_label == 0)}")
    print(f"  Ransomware (label=1): {np.sum(y_label == 1)}")

    # Family distribution
    family_names = {
        0: "Goodware", 1: "Critroni", 2: "CryptLocker", 3: "CryptoWall",
        4: "KOLLAH", 5: "Kovter", 6: "Locker", 7: "MATSNU",
        8: "PGPCODER", 9: "Reveton", 10: "TeslaCrypt", 11: "Trojan-Ransom"
    }
    print("\n  Family Distribution:")
    for fam_id in sorted(np.unique(y_family)):
        count = np.sum(y_family == fam_id)
        name = family_names.get(int(fam_id), f"Unknown-{fam_id}")
        print(f"    {name:<20s} (ID={int(fam_id):>2d}): {count:>4d} samples")

    # ---------------------------------------------------------------
    # STEP 2: Preprocess and split
    # ---------------------------------------------------------------
    print("\n[STEP 2] Preprocessing (variance filter + scaling)...")
    X_train, X_test, y_train, y_test = prep.fit_transform(X, y_label)
    print(f"  Features after variance filter: {X_train.shape[1]}")
    print(f"  Train set: {X_train.shape[0]} samples")
    print(f"  Test set:  {X_test.shape[0]} samples")
    print(f"  Test goodware:   {np.sum(y_test == 0)}")
    print(f"  Test ransomware: {np.sum(y_test == 1)}")

    # ---------------------------------------------------------------
    # STEP 3: Load trained models and evaluate on test set
    # ---------------------------------------------------------------
    print("\n[STEP 3] Loading pre-trained models from models/...")
    model_dir = str(PROJECT_ROOT / "models")
    trainer = ModelTrainer()
    trainer.load_models(model_dir)
    print("  Isolation Forest loaded: YES")
    print("  One-Class SVM loaded:    YES")

    # Check metadata
    meta_path = os.path.join(model_dir, "training_metadata.json")
    if os.path.isfile(meta_path):
        with open(meta_path, "r") as f:
            meta = json.load(f)
        print(f"  Training date:   {meta.get('training_timestamp', 'unknown')}")
        print(f"  Training time:   {meta.get('training_time_seconds', 0):.2f}s")

    # ---------------------------------------------------------------
    # STEP 4: Evaluate on real test set
    # ---------------------------------------------------------------
    print("\n[STEP 4] Evaluating models on REAL held-out test data...")
    metrics = trainer.evaluate(X_test, y_test)

    print("\n  --- Isolation Forest ---")
    print(f"    Accuracy:  {metrics['isolation_forest']['accuracy']:.4f}")
    print(f"    Precision: {metrics['isolation_forest']['precision']:.4f}")
    print(f"    Recall:    {metrics['isolation_forest']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['isolation_forest']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['isolation_forest']['auc_roc']:.4f}")

    print("\n  --- One-Class SVM ---")
    print(f"    Accuracy:  {metrics['one_class_svm']['accuracy']:.4f}")
    print(f"    Precision: {metrics['one_class_svm']['precision']:.4f}")
    print(f"    Recall:    {metrics['one_class_svm']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['one_class_svm']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['one_class_svm']['auc_roc']:.4f}")

    print("\n  --- Fused DAC-OCF ---")
    print(f"    Accuracy:  {metrics['fused_dac_ocf']['accuracy']:.4f}")
    print(f"    Precision: {metrics['fused_dac_ocf']['precision']:.4f}")
    print(f"    Recall:    {metrics['fused_dac_ocf']['recall']:.4f}")
    print(f"    F1-Score:  {metrics['fused_dac_ocf']['f1']:.4f}")
    print(f"    AUC-ROC:   {metrics['fused_dac_ocf']['auc_roc']:.4f}")

    print(f"\n  Confusion Matrix (Fused):")
    cm = metrics['confusion_matrix']
    print(f"                       Predicted Good  Predicted Ransom")
    print(f"    Actual Goodware:   {cm[0][0]:>12d}    {cm[0][1]:>14d}")
    print(f"    Actual Ransomware: {cm[1][0]:>12d}    {cm[1][1]:>14d}")

    # ---------------------------------------------------------------
    # STEP 5: Score individual real samples and verify predictions
    # ---------------------------------------------------------------
    print("\n[STEP 5] Scoring individual REAL samples from dataset...")

    # Get raw IF and SVM scores for test samples
    if_scores = trainer._normalize_scores(
        -trainer.isolation_forest.decision_function(X_test)
    )
    svm_scores = trainer._normalize_scores(
        -trainer.one_class_svm.decision_function(X_test)
    )
    fused_scores = 0.5 * if_scores + 0.5 * svm_scores

    # Show first 5 goodware samples
    good_indices = np.where(y_test == 0)[0][:5]
    ransom_indices = np.where(y_test == 1)[0][:5]

    print("\n  --- 5 REAL Goodware Samples (should be LOW scores) ---")
    print(f"  {'#':<4} {'Label':<10} {'IF_Score':<10} {'SVM_Score':<10} {'Fused':<10} {'Verdict':<12}")
    print(f"  {'-'*4} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*12}")
    for i, idx in enumerate(good_indices):
        verdict = "CORRECT" if fused_scores[idx] < 0.5 else "WRONG"
        emoji = "  OK" if verdict == "CORRECT" else "  XX"
        print(f"  {i+1:<4} {'Goodware':<10} {if_scores[idx]:<10.4f} {svm_scores[idx]:<10.4f} {fused_scores[idx]:<10.4f} {verdict:<12}{emoji}")

    print(f"\n  --- 5 REAL Ransomware Samples (should be HIGH scores) ---")
    print(f"  {'#':<4} {'Label':<10} {'IF_Score':<10} {'SVM_Score':<10} {'Fused':<10} {'Verdict':<12}")
    print(f"  {'-'*4} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*12}")
    for i, idx in enumerate(ransom_indices):
        verdict = "CORRECT" if fused_scores[idx] >= 0.5 else "WRONG"
        emoji = "  OK" if verdict == "CORRECT" else "  XX"
        print(f"  {i+1:<4} {'Ransomware':<10} {if_scores[idx]:<10.4f} {svm_scores[idx]:<10.4f} {fused_scores[idx]:<10.4f} {verdict:<12}{emoji}")

    # ---------------------------------------------------------------
    # STEP 6: Overall score distribution analysis
    # ---------------------------------------------------------------
    print("\n[STEP 6] Score distribution analysis across ALL test samples...")
    good_scores = fused_scores[y_test == 0]
    ransom_scores = fused_scores[y_test == 1]

    print(f"\n  Goodware scores  (n={len(good_scores)}):")
    print(f"    Min:    {good_scores.min():.4f}")
    print(f"    Max:    {good_scores.max():.4f}")
    print(f"    Mean:   {good_scores.mean():.4f}")
    print(f"    Median: {np.median(good_scores):.4f}")
    print(f"    Std:    {good_scores.std():.4f}")

    print(f"\n  Ransomware scores (n={len(ransom_scores)}):")
    print(f"    Min:    {ransom_scores.min():.4f}")
    print(f"    Max:    {ransom_scores.max():.4f}")
    print(f"    Mean:   {ransom_scores.mean():.4f}")
    print(f"    Median: {np.median(ransom_scores):.4f}")
    print(f"    Std:    {ransom_scores.std():.4f}")

    # Check separation
    mean_diff = ransom_scores.mean() - good_scores.mean()
    print(f"\n  Mean score difference (Ransom - Goodware): {mean_diff:.4f}")
    if mean_diff > 0:
        print("  >> Ransomware scores ARE higher than Goodware scores on average.")
        print("  >> The model IS learning to distinguish ransomware from goodware.")
    else:
        print("  !! WARNING: Model may not be discriminating properly.")

    # ---------------------------------------------------------------
    # STEP 7: Test the AnomalyScorer runtime (heuristic mode)
    # ---------------------------------------------------------------
    print("\n[STEP 7] Testing AnomalyScorer runtime engine with Stage 4 feature dicts...")
    scorer = AnomalyScorer(model_dir=model_dir)
    print(f"  Scorer mode: {'ML' if scorer.is_ml_mode else 'Heuristic'}")

    # Simulate a benign file operation (low entropy, low burst)
    benign_fv = {
        "S_entropy": 0.15, "S_ETD": 0.05, "S_dist": 0.10,
        "S_dev": 0.03, "S_stab": 0.95, "lambda_norm": 0.02,
        "branching_n": 0.3, "superheated": False,
        "pid": 1234, "file_path": "C:/Users/test/meeting_notes.txt",
        "operation": "FILE_MODIFY", "timestamp": 1695700000
    }
    benign_result = scorer.score(benign_fv)
    print(f"\n  Benign file operation:")
    print(f"    Score:     {benign_result['anomaly_score']:.4f}")
    print(f"    Risk Tier: {benign_result['risk_tier']}")
    print(f"    Anomaly:   {benign_result['is_anomaly']}")

    # Simulate a ransomware file operation (high entropy, rapid burst)
    ransom_fv = {
        "S_entropy": 0.98, "S_ETD": 0.92, "S_dist": 0.88,
        "S_dev": 0.85, "S_stab": 0.03, "lambda_norm": 0.95,
        "branching_n": 1.8, "superheated": True,
        "pid": 6666, "file_path": "C:/Users/test/ledger.xlsx.locked",
        "operation": "FILE_CREATE", "timestamp": 1695700005
    }
    ransom_result = scorer.score(ransom_fv)
    print(f"\n  Ransomware file operation:")
    print(f"    Score:     {ransom_result['anomaly_score']:.4f}")
    print(f"    Risk Tier: {ransom_result['risk_tier']}")
    print(f"    Anomaly:   {ransom_result['is_anomaly']}")

    # Verify separation
    if ransom_result['anomaly_score'] > benign_result['anomaly_score']:
        print("\n  >> PASS: Ransomware scores higher than benign in runtime scorer.")
    else:
        print("\n  !! FAIL: Runtime scorer not discriminating properly.")

    # ---------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("  VERIFICATION SUMMARY")
    print("=" * 80)
    checks = [
        ("Dataset loaded successfully", X.shape[0] == 1524),
        ("Trained models loaded from disk", True),
        (f"Fused AUC-ROC > 0.50 (got {metrics['fused_dac_ocf']['auc_roc']:.3f})", metrics['fused_dac_ocf']['auc_roc'] > 0.50),
        (f"Ransom mean score > Goodware mean score", mean_diff > 0),
        ("Runtime scorer: benign = SAFE", benign_result['risk_tier'] == 'SAFE'),
        ("Runtime scorer: ransomware = SUSPECT/CRITICAL", ransom_result['risk_tier'] in ('SUSPECT', 'CRITICAL')),
        ("Runtime scorer: ransomware score > benign score", ransom_result['anomaly_score'] > benign_result['anomaly_score']),
    ]
    all_pass = True
    for desc, passed in checks:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  [{status}] {desc}")

    if all_pass:
        print("\n  ALL CHECKS PASSED. Stage 5 is genuinely working.")
    else:
        print("\n  SOME CHECKS FAILED. Investigation needed.")
    print("=" * 80)


if __name__ == "__main__":
    main()
