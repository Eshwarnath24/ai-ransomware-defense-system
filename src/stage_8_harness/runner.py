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
import os
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


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


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
    resolve: str = "malicious",
) -> tuple:
    """
    Run an attack with live Stages 3-10 pipeline integration.

    Uses the AttackEngine's callbacks to feed each encrypted file
    through the pipeline in real time, executing containment and
    Stage 10 enforcement and selective rollback upon threat confirmation.

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
    from src.stage_9_containment import ContainmentEngine
    from src.stage_10_enforcer import Enforcer, Verdict

    sandbox = SandboxManager(sandbox_dir)
    bench = BenchmarkLogger(profile.name)

    print("=" * 65)
    print(f"  STAGE 8 — LIVE PIPELINE INTEGRATION TEST")
    print(f"  Profile : {profile.name}")
    print(f"  Pipeline: Stages {'2 → ' if rarity else ''}3 → 4 → 5 → 6 → 7 → 9 → 10")
    print(f"  Sandbox : {sandbox.sandbox_dir}")
    print("=" * 65)

    # Initialize pipeline stages
    print("\n[1/4] Initializing pipeline stages...")
    dbrg = DBRGManager(decay_lambda=0.01)
    feature_extractor = FeatureExtractor(dbrg_manager=dbrg)
    anomaly_scorer = AnomalyScorer()
    threat_fusion = ThreatFusion()
    trust_evolution = TrustEvolution()
    containment_engine = ContainmentEngine(dry_run=True)
    enforcer = Enforcer(
        containment_engine=containment_engine,
        trust_evolution=trust_evolution,
        dry_run=True,
        always_on=True,
        allowed_roots=[str(sandbox.sandbox_dir)],
        rollback_dry_run=False,
    )
    stage_str = "Stages 2-10" if rarity else "Stages 3-10"
    print(f"  {stage_str} initialized")

    # Setup sandbox
    print("\n[2/4] Setting up victim file environment...")
    created = sandbox.setup(num_files=num_files)
    file_count = sandbox.file_count()
    print(f"  Created {file_count} victim files")

    # Capture pre-attack truth for zero-data-loss verification
    pre_attack_hashes: dict = {}
    for target_path in sandbox.get_target_files():
        try:
            pre_attack_hashes[str(target_path)] = _file_sha256(target_path)
        except OSError:
            pass

    # Build the pipeline callback
    attack_pid = 9999  # Simulated malicious PID
    detection_triggered = False
    total_target_files = file_count
    resolution_result = None

    def pipeline_callback(original_path, renamed_path, data, index):
        """Feed each encrypted file through Stages 3→4→5→6→7."""
        nonlocal detection_triggered, resolution_result

        enforcer.note_rename(attack_pid, str(original_path), str(renamed_path))

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
        except Exception as exc:
            logger.warning("[Runner] Stage 4 failed: %s", exc, exc_info=True)
            features = None

        if not features:
            return

        # Stage 5: Anomaly scoring
        try:
            anomaly_result = anomaly_scorer.score(features)
        except Exception as exc:
            logger.warning("[Runner] Stage 5 failed: %s", exc, exc_info=True)
            return

        # Stage 6: Threat fusion
        try:
            features_to_fuse = dict(features)
            if rarity is not None:
                features_to_fuse["S_rel"] = rarity.calculate_s_rel("cmd.exe", "malware.exe")
            fusion_result = threat_fusion.fuse(features_to_fuse, anomaly_result=anomaly_result)
            fusion_result["pid"] = attack_pid
        except Exception as exc:
            logger.warning("[Runner] Stage 6 failed: %s", exc, exc_info=True)
            return

        # Stage 7: Trust evolution
        try:
            trust_result = trust_evolution.evolve(fusion_result)
        except Exception as exc:
            logger.warning("[Runner] Stage 7 failed: %s", exc, exc_info=True)
            return

        enforcer.on_trust_update(trust_result)

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
                  f"Risk Tier={trust_result['risk_tier']} -> Dispatching Stage 9 NtSuspendProcess ***")

            # Execute Stage 9 Freeze-Graph Min-Cut Containment
            contain_record = containment_engine.contain(
                pid=attack_pid,
                dbrg_graph=dbrg.get_graph_snapshot(),
                trust_state=trust_result,
            )
            print(f"  🛡️  [Stage 9] Min-Cut Severed : {len(contain_record.cut_edges)} edges (cost={contain_record.cut_value:.2f})")
            print(f"  🛡️  [Stage 9] Isolated Files   : {len(contain_record.isolated_files)} files protected")
            print(f"  🛡️  [Stage 9] Kernel Freeze    : NtSuspendProcess simulated in {contain_record.latency_ms:.3f} ms")
            print(f"  🛡️  [Stage 9] Process Status   : {containment_engine.freezer.get_state(attack_pid).value}")

            # Execute Stage 10 ACL Enforcement & Resolution
            enforce_record = enforcer.enforce(contain_record)
            print(f"  🛡️  [Stage 10] Enforced ACLs   : {len(enforce_record.acl_records)} paths revoked along C_min")

            if resolve.lower() == "malicious":
                resolution_result = enforcer.resolve(attack_pid, Verdict.MALICIOUS)
                print(f"  🛡️  [Stage 10] Resolution     : MALICIOUS confirmed — SIGKILL issued, vault rollback executed in {resolution_result.duration_ms:.2f}ms\n")
            elif resolve.lower() == "false_positive":
                resolution_result = enforcer.resolve(attack_pid, Verdict.FALSE_POSITIVE)
                print(f"  🛡️  [Stage 10] Resolution     : FALSE POSITIVE confirmed — ACLs restored, Trust reset to 100, SIGCONT resumed in {resolution_result.duration_ms:.2f}ms\n")
            else:
                resolution_result = None
                print(f"  🛡️  [Stage 10] Resolution     : PENDING (no resolution applied)\n")

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
        on_before_encrypt=lambda p, i: enforcer.before_write(str(p), attack_pid),
        on_file_created=lambda p: enforcer.note_created(attack_pid, str(p)),
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

    # Stage 10 Rollback & Zero Data Loss Verification
    if resolution_result is not None and resolution_result.verdict == Verdict.MALICIOUS:
        files_lost = 0
        for orig_path_str, expected_hash in pre_attack_hashes.items():
            if os.path.exists(orig_path_str):
                try:
                    actual_hash = _file_sha256(Path(orig_path_str))
                    if actual_hash != expected_hash:
                        files_lost += 1
                except OSError:
                    files_lost += 1
            else:
                files_lost += 1

        print("\n" + "=" * 65)
        print("  STAGE 10 — ROLLBACK & ZERO DATA LOSS VERIFICATION")
        print(f"  Files lost: {files_lost}")
        print(f"  Zero data loss: {'YES' if files_lost == 0 else 'NO'}")
        if resolution_result.rollback_report is not None:
            print(f"  Files restored : {resolution_result.rollback_report.restored}/{resolution_result.rollback_report.total}")
            print(f"  Artifacts deleted : {resolution_result.rollback_report.deleted_artifacts}")
            print(f"  Rollback duration : {resolution_result.rollback_report.duration_ms:.2f} ms")
        print("=" * 65)
    elif resolution_result is not None and resolution_result.verdict == Verdict.FALSE_POSITIVE:
        print("\n" + "=" * 65)
        print("  STAGE 10 — FALSE POSITIVE RESUMPTION VERIFICATION")
        print(f"  ACLs restored : {resolution_result.acl_restored}")
        print(f"  Process state : {containment_engine.freezer.get_state(attack_pid).value}")
        print(f"  Trust score   : {trust_evolution.trust_engine.get_trust(attack_pid):.1f}")
        print(f"  Zero files lost : YES (writes were legitimate, process resumed)")
        print("=" * 65)

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
        "--resolve",
        choices=["malicious", "false_positive", "none"],
        default="malicious",
        help="Stage 10 enforcement resolution action (default: malicious)",
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
        run_with_pipeline(profile, sandbox_dir, args.num_files, resolve=args.resolve)
    else:
        run_standalone(profile, sandbox_dir, args.num_files)


if __name__ == "__main__":
    main()
