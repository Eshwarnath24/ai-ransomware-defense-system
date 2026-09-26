"""
src/stage_5_anomaly/train_stage5.py
=====================================
Stage 5 — Standalone Training CLI Script

Orchestrates the full training pipeline:
    1. Load RansomwareData.csv dataset
    2. Preprocess (variance filtering, scaling, splitting)
    3. Train Isolation Forest + One-Class SVM on goodware-only data
    4. Evaluate on held-out test set
    5. Save trained models to models/ directory
    6. Print performance metrics

Usage:
    python -m src.stage_5_anomaly.train_stage5
    python -m src.stage_5_anomaly.train_stage5 --dataset Dataset/RansomwareData.csv
    python -m src.stage_5_anomaly.train_stage5 --model-dir models --n-estimators 300
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

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_5_anomaly.preprocessor import DataPreprocessor
from src.stage_5_anomaly.model_trainer import ModelTrainer


def print_banner():
    """Print the training pipeline banner."""
    print("=" * 80)
    print(" 🛡️  STAGE 5: ANOMALY SCORING & BENIGN PROFILING (DAC-OCF)")
    print("    Density-Adaptive One-Class Fusion — Training Pipeline")
    print("=" * 80)
    print()


def print_metrics(metrics: dict):
    """Pretty-print evaluation metrics."""
    print()
    print("─" * 80)
    print(" 📊 EVALUATION RESULTS")
    print("─" * 80)

    for model_name in ["isolation_forest", "one_class_svm", "fused_dac_ocf"]:
        m = metrics.get(model_name, {})
        label = {
            "isolation_forest": "Isolation Forest",
            "one_class_svm": "One-Class SVM",
            "fused_dac_ocf": "Fused DAC-OCF",
        }[model_name]

        icon = "🌲" if model_name == "isolation_forest" else (
            "🔮" if model_name == "one_class_svm" else "⚡"
        )

        print(f"\n  {icon} {label}:")
        print(f"     Accuracy  : {m.get('accuracy', 0):.4f}")
        print(f"     Precision : {m.get('precision', 0):.4f}")
        print(f"     Recall    : {m.get('recall', 0):.4f}")
        print(f"     F1-Score  : {m.get('f1', 0):.4f}")
        print(f"     AUC-ROC   : {m.get('auc_roc', 0):.4f}")

    # Confusion Matrix
    cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    print(f"\n  📐 Confusion Matrix (Fused DAC-OCF):")
    print(f"                  Predicted Goodware  Predicted Ransomware")
    print(f"     Actual Good:     {cm[0][0]:>8}           {cm[0][1]:>8}")
    print(f"     Actual Ransom:   {cm[1][0]:>8}           {cm[1][1]:>8}")

    print(f"\n  ⏱️  Training Time: {metrics.get('training_time_sec', 0):.2f} seconds")
    print("─" * 80)


def main():
    """Run the full Stage 5 training pipeline."""
    parser = argparse.ArgumentParser(
        description="Stage 5: Train DAC-OCF Anomaly Detection Models"
    )
    parser.add_argument(
        "--dataset", type=str,
        default="Dataset/RansomwareData.csv",
        help="Path to the RansomwareData.csv file",
    )
    parser.add_argument(
        "--model-dir", type=str,
        default="models",
        help="Directory to save trained models",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=200,
        help="Number of Isolation Forest trees",
    )
    parser.add_argument(
        "--contamination", type=float, default=0.05,
        help="IF contamination parameter",
    )
    parser.add_argument(
        "--svm-nu", type=float, default=0.1,
        help="One-Class SVM nu parameter",
    )
    parser.add_argument(
        "--variance-threshold", type=float, default=0.01,
        help="Minimum feature variance for selection",
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Test set fraction",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print_banner()

    # ── Step 1: Load Dataset ─────────────────────────────────────────────
    print(" 📂 Step 1: Loading dataset...")
    preprocessor = DataPreprocessor(
        dataset_path=args.dataset,
        variance_threshold=args.variance_threshold,
        test_size=args.test_size,
        random_state=42,
    )

    try:
        X, y_label, y_family = preprocessor.load_dataset()
    except FileNotFoundError as e:
        print(f"\n ❌ ERROR: {e}")
        print("    Make sure the dataset exists at the expected path.")
        sys.exit(1)

    print(f"    ✅ Loaded {X.shape[0]} samples × {X.shape[1]} features")
    print(f"    Goodware: {preprocessor.label_counts.get(0, 0)}, "
          f"Ransomware: {preprocessor.label_counts.get(1, 0)}")

    # ── Step 2: Preprocess ───────────────────────────────────────────────
    print("\n 🔧 Step 2: Preprocessing (variance filtering + scaling)...")
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y_label)
    print(f"    ✅ Features reduced: {X.shape[1]} → {preprocessor.n_selected_features}")
    print(f"    Train: {len(X_train)} samples, Test: {len(X_test)} samples")

    # ── Step 3: Extract Goodware-Only Training Set ───────────────────────
    print("\n 🏷️  Step 3: Extracting goodware-only training set...")
    X_train_goodware = preprocessor.extract_goodware_only(X_train, y_train)
    print(f"    ✅ {len(X_train_goodware)} goodware samples for one-class training")

    # ── Step 4: Train Models ─────────────────────────────────────────────
    print("\n 🧠 Step 4: Training dual anomaly detection models...")
    trainer = ModelTrainer(
        if_n_estimators=args.n_estimators,
        if_contamination=args.contamination,
        svm_nu=args.svm_nu,
        random_state=42,
    )
    trainer.train(X_train_goodware)
    print(f"    ✅ Training completed in {trainer.training_time_sec:.2f}s")

    # ── Step 5: Evaluate ─────────────────────────────────────────────────
    print("\n 📊 Step 5: Evaluating on held-out test set...")
    metrics = trainer.evaluate(X_test, y_test)

    # ── Step 6: Save Models ──────────────────────────────────────────────
    print(f"\n 💾 Step 6: Saving models to '{args.model_dir}/'...")
    trainer.save_models(args.model_dir)
    preprocessor.save_transformers(args.model_dir)
    print(f"    ✅ Models and transformers saved")

    # ── Print Results ────────────────────────────────────────────────────
    print_metrics(metrics)

    print(f"\n ✅ Stage 5 training pipeline complete!")
    print(f"    Models saved to: {os.path.abspath(args.model_dir)}/")
    print(f"    Run scorer:  from src.stage_5_anomaly import AnomalyScorer")
    print()


if __name__ == "__main__":
    main()
