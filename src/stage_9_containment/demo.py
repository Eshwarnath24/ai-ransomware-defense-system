#!/usr/bin/env python
"""
Stage 9 — LIVE INTERACTIVE DEMO
================================
Run this script to see Stage 9 (Freeze-Graph Min-Cut Containment Engine)
working end-to-end with real Stage 3 (DBRG), Stage 6 (Threat Fusion),
and Stage 7 (Trust Evolution).

Usage:
    python -m src.stage_9_containment.demo

What it does:
    1. Builds a real DBRG graph by feeding simulated malicious file events
    2. Runs Stage 6 threat fusion and Stage 7 trust evolution per event
    3. When trust hits CRITICAL_RISK, triggers Stage 9 containment:
       - Computes Edmonds-Karp min-cut on the live DBRG
       - Freezes the process (simulated NtSuspendProcess)
       - Logs full containment audit record
    4. Demonstrates false-positive recovery (release)
    5. Shows final containment stats
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_4_features.feature_extractor import FeatureExtractor
from src.stage_5_anomaly import AnomalyScorer
from src.stage_6_fusion import ThreatFusion
from src.stage_7_trust import TrustEvolution
from src.stage_9_containment import (
    ContainmentEngine,
    ContainmentState,
)


def _configure_utf8():
    if sys.platform == "win32":
        try:
            import io
            if hasattr(sys.stdout, "buffer"):
                sys.stdout = io.TextIOWrapper(
                    sys.stdout.buffer, encoding="utf-8", errors="replace"
                )
        except Exception:
            pass


def main():
    _configure_utf8()

    ATTACK_PID = 6666
    BENIGN_PID = 7777
    VICTIM_FILES = [
        "file:C:/Users/victim/Documents/budget_2024.xlsx",
        "file:C:/Users/victim/Documents/thesis_final.docx",
        "file:C:/Users/victim/Desktop/family_photo.png",
        "file:C:/Users/victim/Desktop/tax_returns.pdf",
        "file:C:/Users/victim/Downloads/project_backup.zip",
    ]

    print("=" * 70)
    print("  STAGE 9 — LIVE INTERACTIVE DEMO")
    print("  Freeze-Graph Min-Cut Containment Engine")
    print("=" * 70)

    # ── Step 1: Initialize all pipeline stages ───────────────────────
    print("\n[1/6] Initializing pipeline stages 3 → 4 → 5 → 6 → 7 → 9...")
    dbrg = DBRGManager(decay_lambda=0.01)
    feature_extractor = FeatureExtractor(dbrg_manager=dbrg)
    anomaly_scorer = AnomalyScorer()
    threat_fusion = ThreatFusion()
    trust_evolution = TrustEvolution()
    containment = ContainmentEngine(dry_run=True)  # Simulation mode
    print("  ✅ All stages initialized (Stage 9 in dry-run/simulation mode)")

    # ── Step 2: Simulate benign process activity ─────────────────────
    print(f"\n[2/6] Simulating BENIGN process (PID={BENIGN_PID})...")
    for i in range(3):
        ecar = {
            "actorID": f"pid:{BENIGN_PID}",
            "objectID": f"file:C:/Users/victim/Documents/notes_{i}.txt",
            "pid": BENIGN_PID,
            "operation": "FILE_MODIFY",
            "timestamp": time.time() * 1000,
            "context": {"exe_path": "notepad.exe", "parent_exe": "explorer.exe"},
        }
        dbrg.process_event(ecar)
        features = feature_extractor.extract_features(ecar)
        if features:
            anomaly = anomaly_scorer.score(features)
            fusion = threat_fusion.fuse(features, anomaly_result=anomaly)
            fusion["pid"] = BENIGN_PID
            trust_result = trust_evolution.evolve(fusion)
            print(
                f"  [{i+1}/3] notepad.exe → notes_{i}.txt  |  "
                f"Trust={trust_result['trust']:5.1f}  |  "
                f"Tier={trust_result['risk_tier']:<13}  |  "
                f"Contain={trust_result['should_contain']}"
            )

    print(f"\n  → PID {BENIGN_PID} stays SAFE. No containment needed.")

    # ── Step 3: Simulate ransomware attack ───────────────────────────
    print(f"\n[3/6] Simulating RANSOMWARE attack (PID={ATTACK_PID})...")
    print(f"       Malware: lockbit.exe encrypting {len(VICTIM_FILES)} files\n")

    containment_triggered = False
    trust_at_trigger = None

    for i, victim_file in enumerate(VICTIM_FILES):
        # Simulate the malicious event
        ecar = {
            "actorID": f"pid:{ATTACK_PID}",
            "objectID": victim_file,
            "pid": ATTACK_PID,
            "operation": "FILE_MODIFY",
            "timestamp": time.time() * 1000,
            "context": {"exe_path": "lockbit.exe", "parent_exe": "cmd.exe"},
        }

        # Stage 3: Update DBRG
        dbrg.process_event(ecar)

        # Stage 4: Features
        features = feature_extractor.extract_features(ecar)
        if not features:
            continue
        # Simulate ransomware file entropy (since mock paths aren't real disk files)
        features["S_entropy"] = 0.98
        features["S_ETD"] = 0.95

        # Stage 5: Anomaly scoring
        anomaly = anomaly_scorer.score(features)

        # Stage 6: Threat fusion
        fusion = threat_fusion.fuse(features, anomaly_result=anomaly)
        fusion["pid"] = ATTACK_PID

        # Stage 7: Trust evolution
        trust_result = trust_evolution.evolve(fusion)

        file_name = victim_file.split("/")[-1]
        print(
            f"  [{i+1}/{len(VICTIM_FILES)}] lockbit.exe → {file_name:<25} |  "
            f"Entropy={features.get('S_entropy', 0):.2f}  |  "
            f"Anomaly={anomaly.get('anomaly_score', 0):.2f}  |  "
            f"Trust={trust_result['trust']:5.1f}  |  "
            f"Tier={trust_result['risk_tier']:<13}"
        )

        if trust_result["should_contain"] and not containment_triggered:
            containment_triggered = True
            trust_at_trigger = trust_result
            print(f"\n  🚨 CRITICAL_RISK DETECTED at file {i+1}!")
            print(f"  🚨 Trust={trust_result['trust']:.1f} → Triggering Stage 9...\n")
            break

    if not containment_triggered:
        print("\n  ⚠️  Trust did not reach CRITICAL_RISK in this demo.")
        print("  (This can happen with heuristic scoring. The containment")
        print("   engine can still be demonstrated manually below.)\n")
        # Force a containment for demo purposes
        trust_at_trigger = {"trust": 5.0, "risk_tier": "CRITICAL_RISK"}

    # ── Step 4: Execute Stage 9 containment ──────────────────────────
    print("[4/6] EXECUTING STAGE 9 CONTAINMENT...")
    print("  ├── Computing Edmonds-Karp min-cut on DBRG...")
    print(f"  ├── DBRG state: {dbrg.get_node_count()} nodes, {dbrg.get_edge_count()} edges")

    snapshot = dbrg.get_graph_snapshot()
    record = containment.contain(
        pid=ATTACK_PID,
        dbrg_graph=snapshot,
        trust_state=trust_at_trigger,
    )

    print(f"  ├── Min-Cut Value      : {record.cut_value:.4f}")
    print(f"  ├── Edges Severed      : {len(record.cut_edges)}")
    for u, v in record.cut_edges:
        file_name = v.replace("file:", "").split("/")[-1]
        print(f"  │     ✂️  {u} → {file_name}")
    print(f"  ├── Files Isolated     : {len(record.isolated_files)}")
    for f in record.isolated_files:
        print(f"  │     🔒 {f.replace('file:', '')}")
    print(f"  ├── Process Frozen     : {record.freeze_result.success}")
    print(f"  ├── Dry-Run Mode       : {record.freeze_result.dry_run}")
    print(f"  ├── Containment Latency: {record.latency_ms:.3f} ms")
    print(f"  ├── Trust at Trigger   : {record.trust_at_containment}")
    print(f"  └── Risk Tier          : {record.risk_tier_at_containment}")

    # Verify state
    state = containment.freezer.get_state(ATTACK_PID)
    print(f"\n  Process State: PID {ATTACK_PID} → {state.value}")
    assert state == ContainmentState.FROZEN, "Process should be FROZEN!"
    print("  ✅ Process is FROZEN (NtSuspendProcess simulated)")

    # Verify benign process unaffected
    benign_state = containment.freezer.get_state(BENIGN_PID)
    print(f"  Process State: PID {BENIGN_PID} → {benign_state.value}")
    assert benign_state == ContainmentState.ACTIVE
    print("  ✅ Benign process UNAFFECTED")

    # ── Step 5: False-positive recovery ──────────────────────────────
    print(f"\n[5/6] FALSE-POSITIVE RECOVERY DEMO...")
    print(f"  Analyst decides PID {ATTACK_PID} was a false alarm.")
    release_record = containment.release(
        pid=ATTACK_PID, reason="analyst_confirmed_false_positive"
    )
    print(f"  ├── Release Success : {release_record.success}")
    print(f"  ├── Release Latency : {release_record.latency_ms:.3f} ms")
    state_after = containment.freezer.get_state(ATTACK_PID)
    print(f"  └── New State       : {state_after.value}")
    assert state_after == ContainmentState.RELEASED
    print("  ✅ Process RELEASED (NtResumeProcess simulated)")

    # ── Step 6: Final stats ──────────────────────────────────────────
    print(f"\n[6/6] CONTAINMENT ENGINE STATS")
    stats = containment.get_stats()
    print(f"  ├── Total Containments  : {stats['total_containments']}")
    print(f"  ├── Total Releases      : {stats['total_releases']}")
    print(f"  ├── Currently Frozen    : {stats['currently_frozen']}")
    print(f"  ├── Min-Cuts Computed   : {stats['total_cuts_computed']}")
    print(f"  ├── Log Entries         : {stats['total_log_entries']}")
    print(f"  └── Dry-Run Mode        : {stats['dry_run']}")

    # Audit log
    print(f"\n  CONTAINMENT AUDIT LOG:")
    for i, rec in enumerate(containment.get_containment_history()):
        print(
            f"    [{i+1}] {rec.action}  PID={rec.pid}  "
            f"success={rec.success}  "
            f"latency={rec.latency_ms:.3f}ms  "
            f"cut_edges={len(rec.cut_edges)}"
        )

    print("\n" + "=" * 70)
    print("  ✅ STAGE 9 LIVE DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()

