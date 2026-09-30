"""
src/stage_5_anomaly/train_stage5.py
=====================================
Stage 5 — Standalone Training CLI Script (RADAR Dataset & goodware-logs.csv)

Orchestrates the full Stage 5 training pipeline:
    1. Load Sysmon event streams from goodware-logs.csv and RADAR ransomware logs
    2. Extract the 7 Stage 4 behavioral feature vectors (S_entropy, S_ETD, S_dist, S_dev, S_stab, lambda_norm, branching_n)
    3. Scale and normalize baseline benign behavior with StandardScaler
    4. Train Isolation Forest (DAC) + One-Class SVM (OCF) on goodware-only samples
    5. Evaluate on held-out test set (goodware + LockBit, BlackBasta, CyberVolk)
    6. Save trained models (isolation_forest.joblib, one_class_svm.joblib, scaler.joblib) to models/

Usage:
    python -m src.stage_5_anomaly.train_stage5
    python src/stage_5_anomaly/train_stage5.py
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# Windows UTF-8 stdout fix for emoji output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor, FEATURE_COLUMNS
from src.stage_5_anomaly.model_trainer import ModelTrainer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("train_stage5")


def print_banner():
    """Print the training pipeline banner."""
    print("=" * 80)
    print(" 🛡️  STAGE 5: ANOMALY SCORING & BENIGN PROFILING (DAC-OCF)")
    print("    Trained on RADAR Dataset & goodware-logs.csv (7 Stage 4 Features)")
    print("=" * 80)
    print()


def print_metrics(metrics: dict):
    """Pretty-print evaluation metrics."""
    print()
    print("─" * 80)
    print(" 📊 EVALUATION RESULTS (7-DIMENSIONAL BEHAVIORAL FEATURE SPACE)")
    print("─" * 80)

    for model_name in ["isolation_forest", "one_class_svm", "fused_dac_ocf"]:
        m = metrics.get(model_name, {})
        label = {
            "isolation_forest": "Isolation Forest (DAC)",
            "one_class_svm": "One-Class SVM (OCF)",
            "fused_dac_ocf": "Fused DAC-OCF Ensemble",
        }.get(model_name, model_name)

        icon = "🌲" if model_name == "isolation_forest" else (
            "🔮" if model_name == "one_class_svm" else "⚡"
        )

        print(f"\n  {icon} {label}:")
        print(f"     Accuracy  : {m.get('accuracy', 0):.4f}")
        print(f"     Precision : {m.get('precision', 0):.4f}")
        print(f"     Recall    : {m.get('recall', 0):.4f}")
        print(f"     F1-Score  : {m.get('f1', 0):.4f}")
        print(f"     AUC-ROC   : {m.get('auc_roc', 0):.4f}")

    cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    print(f"\n  📐 Confusion Matrix (Fused DAC-OCF):")
    print(f"                  Predicted Goodware  Predicted Ransomware")
    print(f"     Actual Good:     {cm[0][0]:>8}           {cm[0][1]:>8}")
    print(f"     Actual Ransom:   {cm[1][0]:>8}           {cm[1][1]:>8}")

    print(f"\n  ⏱️  Training Time: {metrics.get('training_time_sec', 0):.2f} seconds")
    print("─" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Stage 5: Train DAC-OCF Anomaly Detection on RADAR Dataset"
    )
    parser.add_argument(
        "--goodware-path", type=str,
        default="Dataset/goodware-logs.csv",
        help="Path to goodware-logs.csv",
    )
    parser.add_argument(
        "--radar-dir", type=str,
        default="Dataset/RADAR-v0.0.1-beta",
        help="Path to RADAR dataset directory",
    )
    parser.add_argument(
        "--model-dir", type=str,
        default="models",
        help="Directory to save trained models",
    )
    parser.add_argument(
        "--max-samples", type=int,
        default=4000,
        help="Maximum samples per class to extract",
    )
    parser.add_argument(
        "--n-estimators", type=int,
        default=200,
        help="Number of trees in Isolation Forest",
    )
    parser.add_argument(
        "--force-rebuild", action="store_true",
        help="Force re-extraction of features instead of using cache",
    )
    args = parser.parse_args()

    print_banner()

    cache_path = "Dataset/stage4_radar_features.csv"
    if args.force_rebuild and os.path.exists(cache_path):
        os.remove(cache_path)

    # ── Step 1: Preprocess & Extract Features ─────────────────────────
    print("⚙️  [1/4] Extracting Stage 4 Behavioral Features from RADAR & goodware-logs.csv...")
    t0 = time.time()
    preprocessor = DataPreprocessor(
        goodware_path=args.goodware_path,
        radar_dir=args.radar_dir,
        cache_path=cache_path,
        max_samples_per_class=args.max_samples,
    )

    X_train_scaled, X_test_scaled, y_test, scaler = preprocessor.prepare_training_data()

    print(f"   ✔ Feature extraction complete ({time.time() - t0:.2f}s)")
    print(f"   ✔ Features: {FEATURE_COLUMNS} (dim={len(FEATURE_COLUMNS)})")
    print(f"   ✔ Total Samples: {preprocessor.n_samples} (Goodware: {preprocessor.n_goodware}, Ransomware: {preprocessor.n_ransomware})")
    print(f"   ✔ Train set (Goodware baseline): {X_train_scaled.shape[0]} samples")
    print(f"   ✔ Test set (Mixed evaluation):   {X_test_scaled.shape[0]} samples")

    # ── Step 2: Train Anomaly Models (DAC + OCF) ──────────────────────
    print("\n🌲 [2/4] Training Isolation Forest (DAC) & One-Class SVM (OCF)...")
    trainer = ModelTrainer(
        if_n_estimators=args.n_estimators,
        if_contamination=0.01,
        svm_kernel="rbf",
        svm_nu=0.01,
        svm_gamma=0.1,
    )
    trainer.train(X_train_scaled)
    print(f"   ✔ Models trained in {trainer.training_time_sec:.2f}s")

    # ── Step 3: Evaluate on Test Set ──────────────────────────────────
    print("\n📈 [3/4] Evaluating models against ransomware and goodware test streams...")
    metrics = trainer.evaluate(X_test_scaled, y_test)
    print_metrics(metrics)

    # ── Step 4: Persist Models & Transformers ─────────────────────────
    print("\n💾 [4/4] Saving trained models and feature scaler...")
    os.makedirs(args.model_dir, exist_ok=True)
    trainer.save_models(args.model_dir)
    preprocessor.save_transformers(args.model_dir)

    print(f"   ✔ Models and scaler saved to '{args.model_dir}/'")
    print(f"     - {args.model_dir}/isolation_forest.joblib (n_features={X_train_scaled.shape[1]})")
    print(f"     - {args.model_dir}/one_class_svm.joblib   (n_features={X_train_scaled.shape[1]})")
    print(f"     - {args.model_dir}/scaler.joblib          (StandardScaler fitted on 7 features)")
    print(f"     - {args.model_dir}/feature_metadata.json")
    print(f"     - {args.model_dir}/training_metadata.json")
    print()
    print("=" * 80)
    print(" ✅ STAGE 5 TRAINING COMPLETED SUCCESSFULLY — NO DIMENSION MISMATCH!")
    print("=" * 80)


if __name__ == "__main__":
    main()
