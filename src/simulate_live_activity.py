"""
src/simulate_live_activity.py
==============================
Live Activity Simulator for Stages 1–5 Testing

Generates simulated benign or ransomware activity in `monitored_test_dir/`
so you can see `live_stage5_monitor.py` react and classify events in real time.

Usage:
  python src/simulate_live_activity.py --mode benign
  python src/simulate_live_activity.py --mode ransomware
  python src/simulate_live_activity.py --mode mixed
"""

import os
import sys
import time
import secrets
import argparse
from pathlib import Path

# Windows UTF-8 stdout fix
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT_ROOT / "monitored_test_dir"


def run_benign_simulation(n_files: int = 5, delay: float = 0.5):
    print(f"\n[Simulator] [BENIGN] Starting normal document editing ({n_files} files)...")
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    for i in range(1, n_files + 1):
        file_path = TARGET_DIR / f"benign_doc_{i}.txt"
        text_content = f"Meeting notes #{i}\nDate: 2026-09-23\nAgenda: Project status review and discussion.\nAll systems operational."
        
        # Write normal plaintext
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(text_content)
        print(f"  [CREATE] Normal text document: {file_path.name}")
        time.sleep(delay)

        # Modify normal document
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("\nAction item: Follow up with team tomorrow.")
        print(f"  [MODIFY] Normal text document: {file_path.name}")
        time.sleep(delay)


def run_ransomware_simulation(n_files: int = 10, delay: float = 0.05):
    print(f"\n[Simulator] [RANSOMWARE] Starting rapid burst encryption simulation ({n_files} files)...")
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    # First create vulnerable target files
    target_files = []
    for i in range(1, n_files + 1):
        p = TARGET_DIR / f"financial_records_{i}.docx"
        with open(p, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL ACCOUNT BALANCES AND LEDGER DATA " * 10)
        target_files.append(p)

    time.sleep(0.5)
    print("  [ATTACK] Launching rapid high-entropy encryption burst...")

    # Rapidly overwrite with high-entropy pseudo-random ciphertext
    for p in target_files:
        encrypted_bytes = secrets.token_bytes(4096)
        encrypted_path = p.with_suffix(".docx.locked")
        
        # Overwrite with high entropy
        with open(p, "wb") as f:
            f.write(encrypted_bytes)
        
        # Rename to simulate ransomware extension appending
        if p.exists():
            os.replace(p, encrypted_path)
            
        print(f"  [ENCRYPTED] High entropy written: {encrypted_path.name}")
        time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description="Live Activity Simulator")
    parser.add_argument("--mode", choices=["benign", "ransomware", "mixed"], default="mixed", help="Activity type")
    args = parser.parse_args()

    if args.mode == "benign":
        run_benign_simulation()
    elif args.mode == "ransomware":
        run_ransomware_simulation()
    elif args.mode == "mixed":
        run_benign_simulation(n_files=3, delay=0.3)
        time.sleep(0.8)
        run_ransomware_simulation(n_files=6, delay=0.08)

    print("\n[Simulator] Done! Check your live monitor window to see real-time classifications.\n")


if __name__ == "__main__":
    main()
