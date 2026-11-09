"""
simulate_ransomware.py
======================
Safely simulates ransomware behavior inside `monitored_test_dir/`
(or a specified target directory) using the Stage 8 Synthetic
Ransomware Test Harness.

Used to test live pipeline detection and trust degradation in real time.

Usage:
  python simulate_ransomware.py
  python simulate_ransomware.py --profile wannacry --num-files 20
  python simulate_ransomware.py --target-dir path/to/folder
"""

import sys
import io
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_8_harness.sandbox_manager import SandboxManager
from src.stage_8_harness.attack_profiles import get_profile, LOCKBIT_AGGRESSIVE
from src.stage_8_harness.attack_engine import AttackEngine
from src.stage_8_harness.benchmark_logger import BenchmarkLogger


def main():
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        description="Safe Ransomware Simulation Harness (Stage 8 Powered)"
    )
    parser.add_argument(
        "--profile",
        type=str,
        default="lockbit",
        choices=["lockbit", "wannacry", "blackcat"],
        help="Simulated ransomware behavior profile (default: lockbit)",
    )
    parser.add_argument(
        "--num-files",
        type=int,
        default=20,
        help="Number of victim files to simulate (default: 20)",
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=str(PROJECT_ROOT / "monitored_test_dir"),
        help="Directory to populate and attack (default: monitored_test_dir)",
    )
    parser.add_argument(
        "--keep-files",
        action="store_true",
        help="Do not clean up encrypted files after simulation ends",
    )
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    profile = get_profile(args.profile)

    print("=" * 70)
    print(" RANSOMWARE ATTACK SIMULATOR (SAFE & NON-DESTRUCTIVE — STAGE 8)")
    print("=" * 70)
    print(f" Target Directory : {target_dir}")
    print(f" Attack Profile   : {profile.name}")
    print(f" Target File Count: {args.num_files}")
    print(f" Delay / Batch    : {profile.interval_ms} ms / batch={profile.batch_size}")
    print("=" * 70 + "\n")

    sandbox = SandboxManager(sandbox_dir=target_dir)
    bench = BenchmarkLogger(profile.name)

    print("[1/3] Populating victim files with low-entropy content...")
    created_files = sandbox.setup(num_files=args.num_files)
    print(f"  [+] Created {len(created_files)} structured victim files in {target_dir}\n")

    print(f"[2/3] Launching {profile.name} attack engine...")
    engine = AttackEngine(
        sandbox=sandbox,
        profile=profile,
        logger_=bench,
    )
    result = engine.execute()

    for idx, f_path in enumerate(result.files_encrypted, 1):
        print(f"  [+] Encrypted target file {idx:2d}/{result.total_files}: {Path(f_path).name}")

    print("\n" + "=" * 70)
    print(f" 🛑 Attack Complete! Encrypted {result.encrypted_count} files in {result.elapsed_ms:.1f} ms.")
    print("    Check your Live Monitor / Dashboard terminal to observe Stage 7 Trust decay!")
    print("=" * 70)

    if not args.keep_files:
        print("\nCleaning up simulation directory...")
        sandbox.cleanup()
        print("Done.")


if __name__ == "__main__":
    main()
