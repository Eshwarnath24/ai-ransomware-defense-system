"""
src/stage_8_harness/runner.py
================================
CLI & programmatic orchestrator for the Stage 8 Test Harness.

Usage
-----
    # Standalone attack (no pipeline)
    python -m src.stage_8_harness.runner --profile lockbit

    # With live pipeline integration (Stages 3-7)
    python -m src.stage_8_harness.runner --profile blackcat --with-pipeline

    # Custom file count (dynamically scales beyond 13 base templates)
    python -m src.stage_8_harness.runner --profile wannacry --num-files 50

    # Reset sandbox only
    python -m src.stage_8_harness.runner --clean
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

from src.stage_8_harness.sandbox_manager import SandboxManager
from src.stage_8_harness.attack_profiles import (
    AttackProfile,
    LOCKBIT_AGGRESSIVE,
    WANNACRY_BURST,
    BLACKCAT_STEALTH,
    get_profile,
)
from src.stage_8_harness.attack_engine import AttackEngine, AttackResult
from src.stage_8_harness.benchmark_logger import BenchmarkLogger, BenchmarkReport

logger = logging.getLogger(__name__)


def _configure_utf8_output() -> None:
    """Ensure Windows terminal handles UTF-8 characters properly when running as CLI."""
    if sys.platform == "win32":
        try:
            import io
            if hasattr(sys.stdout, "buffer") and not isinstance(sys.stdout, io.TextIOWrapper):
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        except Exception:
            pass


def run_standalone(
    profile: AttackProfile,
    sandbox_dir: Optional[Path] = None,
    num_files: Optional[int] = None,
    abort_on_detection: bool = False,
) -> tuple:
    """
    Run a standalone attack (no pipeline) and return (AttackResult, BenchmarkReport).

    Parameters
    ----------
    profile : AttackProfile
        Attack speed and behavior profile.
    sandbox_dir : Path, optional
        Custom sandbox directory. Uses default if None.
    num_files : int, optional
        Target number of victim files. Scales dynamically.
    abort_on_detection : bool
        Whether to stop if a detection event is recorded.

    Returns
    -------
    tuple of (AttackResult, BenchmarkReport)
    """
    sandbox = SandboxManager(sandbox_dir)
    bench = BenchmarkLogger(profile.name)

    print("=" * 65)
    print(f"  STAGE 8 — SYNTHETIC RANSOMWARE TEST HARNESS")
    print(f"  Profile : {profile.name}")
    print(f"  Sandbox : {sandbox.sandbox_dir}")
    print("=" * 65)

    # Setup sandbox
    print("\n[1/3] Setting up victim file environment...")
    created = sandbox.setup(num_files=num_files)
    file_count = sandbox.file_count()
    print(f"  Created {file_count} victim files\n")

    # Execute attack
    print(f"[2/3] Executing {profile.name} attack...")
    engine = AttackEngine(
        sandbox=sandbox,
        profile=profile,
        logger_=bench,
        abort_on_detection=abort_on_detection,
    )
    result = engine.execute()

    # Print per-file progress
    for i, fpath in enumerate(result.files_encrypted, 1):
        fname = Path(fpath).name
        print(f"  [{i:3d}/{result.total_files}] Encrypted: {fname}")

    if result.aborted:
        print(f"\n  ATTACK ABORTED: {result.abort_reason}")

    # Report
    print(f"\n[3/3] Benchmark Report")
    report = bench.get_report(total_files=file_count)
    report.print_report()

    # Cleanup
    sandbox.cleanup()
    print("\nSandbox cleaned up.")

    return result, report


def run_with_pipeline(
    profile: AttackProfile,
    sandbox_dir: Optional[Path] = None,
    num_files: Optional[int] = None,
) -> tuple:
    """
    Run an attack with live Stages 3-7 pipeline integration.

    Uses the AttackEngine's on_file_encrypted callback to feed each
    encrypted file through the pipeline in real time, eliminating
    code duplication between the engine and the runner.

    Returns
    -------
    tuple of (AttackResult, BenchmarkReport)
    """
    # Late imports to avoid circular dependencies
    try:
        from lineage.rarity_engine import RarityEngine
        rarity = RarityEngine()
    except Exception:
        rarity = None

    from src.stage_3_dbrg.dbrg_manager import DBRGManager
    from src.stage_4_features.feature_extractor import FeatureExtractor
    from src.stage_5_anomaly import AnomalyScorer
    from src.stage_6_fusion import ThreatFusion
    from src.stage_7_trust import TrustEvolution

    sandbox = SandboxManager(sandbox_dir)
    bench = BenchmarkLogger(profile.name)

    print("=" * 65)
    print(f"  STAGE 8 — LIVE PIPELINE INTEGRATION TEST")
    print(f"  Profile : {profile.name}")
    print(f"  Pipeline: Stages {'2 → ' if rarity else ''}3 → 4 → 5 → 6 → 7")
    print(f"  Sandbox : {sandbox.sandbox_dir}")
    print("=" * 65)

    # Initialize pipeline stages
    print("\n[1/4] Initializing pipeline stages...")
    dbrg = DBRGManager(decay_lambda=0.01)
    feature_extractor = FeatureExtractor(dbrg_manager=dbrg)
    anomaly_scorer = AnomalyScorer()
    threat_fusion = ThreatFusion()
    trust_evolution = TrustEvolution()
    stage_str = "Stages 2-7" if rarity else "Stages 3-7"
    print(f"  {stage_str} initialized")

    # Setup sandbox
    print("\n[2/4] Setting up victim file environment...")
    created = sandbox.setup(num_files=num_files)
    file_count = sandbox.file_count()
    print(f"  Created {file_count} victim files")

    # Build the pipeline callback
    attack_pid = 9999  # Simulated malicious PID
    detection_triggered = False
    total_target_files = file_count

    def pipeline_callback(original_path, renamed_path, data, index):
        """Feed each encrypted file through Stages 3→4→5→6→7."""
        nonlocal detection_triggered

        ecar_event = {
            "actorID": f"pid:{attack_pid}",
            "objectID": f"file:{renamed_path}",
            "pid": attack_pid,
            "operation": "MODIFY",
            "timestamp": time.time() * 1000,
            "context": {
                "exe_path": "malware.exe",
                "parent_exe": "cmd.exe",
            },
        }

        # Stage 3: Graph topology update
        dbrg.process_event(ecar_event)

        # Stage 4: Extract features
        try:
            features = feature_extractor.extract_features(ecar_event)
        except Exception:
            features = None

        if not features:
            return

        # Stage 5: Anomaly scoring
        try:
            anomaly_result = anomaly_scorer.score(features)
        except Exception:
            return

        # Stage 6: Threat fusion
        try:
            features_to_fuse = dict(features)
            if rarity is not None:
                features_to_fuse["S_rel"] = rarity.calculate_s_rel("cmd.exe", "malware.exe")
            fusion_result = threat_fusion.fuse(features_to_fuse, anomaly_result=anomaly_result)
            fusion_result["pid"] = attack_pid
        except Exception:
            return

        # Stage 7: Trust evolution
        try:
            trust_result = trust_evolution.evolve(fusion_result)
        except Exception:
            return

        bench.record_trust_point(
            pid=attack_pid,
            trust=trust_result["trust"],
            tier=trust_result["risk_tier"],
        )

        print(
            f"  [{index+1:2d}/{total_target_files}] Encrypted: {original_path.name:<25} | "
            f"Entropy={features.get('S_entropy', 0):.2f} | "
            f"AnomScore={anomaly_result.get('anomaly_score', 0):.2f} | "
            f"Trust={trust_result['trust']:5.1f} | "
            f"Tier={trust_result['risk_tier']:<13}"
        )

        if trust_result["should_contain"] and not detection_triggered:
            detection_triggered = True
            bench.record_detection(
                stage="stage_7",
                tier=trust_result["risk_tier"],
                trust=trust_result["trust"],
                pid=attack_pid,
            )
            print(f"\n  🚨 *** CONTAINMENT TRIGGERED at file {index+1}! ***")
            print(f"  🚨 *** Trust={trust_result['trust']:.1f}, "
                  f"Risk Tier={trust_result['risk_tier']} -> Dispatching Stage 9 NtSuspendProcess ***\n")
            # Signal the engine to stop the attack
            engine.signal_abort("Pipeline containment triggered")

    # Execute attack with callback
    print(f"\n[3/4] Executing {profile.name} attack with live pipeline...")
    engine = AttackEngine(
        sandbox=sandbox,
        profile=profile,
        logger_=bench,
        abort_on_detection=True,
        on_file_encrypted=pipeline_callback,
    )
    result = engine.execute()

    # Report
    print(f"\n[4/4] Benchmark Report")
    report = bench.get_report(total_files=file_count)
    report.print_report()

    # Trust trajectory summary
    if report.trust_trajectory:
        print("\n  Trust Trajectory:")
        for tp in report.trust_trajectory:
            print(f"    PID={tp['pid']}  Trust={tp['trust']:5.1f}  Tier={tp['tier']}")

    # Cleanup
    sandbox.cleanup()
    print("\nSandbox cleaned up.")

    return result, report


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="stage_8_harness",
        description="Stage 8 — Synthetic Ransomware Test Harness",
    )
    parser.add_argument(
        "--profile",
        choices=["lockbit", "wannacry", "blackcat"],
        default="lockbit",
        help="Attack profile to use (default: lockbit)",
    )
    parser.add_argument(
        "--num-files",
        type=int,
        default=None,
        help="Target number of victim files (scales dynamically beyond 13 templates)",
    )
    parser.add_argument(
        "--sandbox-dir",
        type=str,
        default=None,
        help="Custom sandbox directory path",
    )
    parser.add_argument(
        "--with-pipeline",
        action="store_true",
        help="Run with live Stages 3-7 pipeline integration",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Only clean up the sandbox directory and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser


def main() -> None:
    """CLI entry point."""
    _configure_utf8_output()
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    sandbox_dir = Path(args.sandbox_dir) if args.sandbox_dir else None

    if args.clean:
        sandbox = SandboxManager(sandbox_dir)
        sandbox.cleanup()
        print("Sandbox cleaned up.")
        return

    profile = get_profile(args.profile)

    if args.with_pipeline:
        run_with_pipeline(profile, sandbox_dir, args.num_files)
    else:
        run_standalone(profile, sandbox_dir, args.num_files)


if __name__ == "__main__":
    main()
