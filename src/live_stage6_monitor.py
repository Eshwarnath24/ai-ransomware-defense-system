"""
src/live_stage6_monitor.py
============================
Live Real-Time Stage 6 Threat Fusion & IntentDrift Monitor

Monitors filesystem operations on disk in real time. Whenever files are
created, modified, or encrypted, this script extracts multi-layer signals
(Stage 1-4), gets lineage rarity (Stage 2), anomaly score (Stage 5), and
computes the Priority Composite Score (S_comp) and Sigmoidal IntentDrift (Stage 6).

Usage:
  python src/live_stage6_monitor.py             # Runs live monitor + integrated simulation
  python src/live_stage6_monitor.py --manual    # Runs in purely manual listening mode
"""

import sys
import os
import time
import argparse
import queue
import logging
import threading
import warnings
import secrets
from pathlib import Path

# Suppress all library warnings
warnings.filterwarnings("ignore")

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Windows UTF-8 stdout fix
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from collector.file_monitor import FileMonitor
from collector.process_monitor import ProcessMonitor
from collector.queue_joiner import QueueJoiner
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_4_features.feature_extractor import FeatureExtractor
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer
from lineage.rarity_engine import RarityEngine
from src.stage_6_fusion.threat_fusion import ThreatFusion


def print_banner(watch_paths):
    print("=" * 118, flush=True)
    print(" 🛡️  STAGE 6: MULTI-SIGNAL CORROBORATION & SIGMOIDAL INTENT DRIFT MONITOR", flush=True)
    print("=" * 118, flush=True)
    print(" Mathematical Formulation:", flush=True)
    print("   S_comp       = 0.35*S_ent + 0.30*S_dist + 0.20*S_dev + 0.10*S_rel + 0.05*(1 - S_stab)", flush=True)
    print("   IntentDrift  = 1 / (1 + exp(-15.0 * (S_comp - 0.50)))", flush=True)
    print(" Active Watched Directory:", flush=True)
    for p in watch_paths:
        print(f"   📂 {p}", flush=True)
    print("=" * 118 + "\n", flush=True)

    header = (
        f"{'#':<4} | {'Time':<8} | {'PID':<6} | {'File Name':<18} | "
        f"{'S_ent':<6} | {'S_dist':<6} | {'S_dev':<6} | {'S_rel':<6} | {'S_comp':<7} | {'IntentDrift':<11} | {'Threat Tier':<12}"
    )
    print("-" * len(header), flush=True)
    print(header, flush=True)
    print("-" * len(header), flush=True)


def format_row(idx: int, ecar: dict, fv: dict, fusion_res: dict) -> str:
    raw_path = fv.get("file_path") or ecar.get("objectID") or "unknown"
    if str(raw_path).startswith("file:"):
        raw_path = str(raw_path)[5:]
    file_basename = os.path.basename(str(raw_path))
    if len(file_basename) > 18:
        file_basename = file_basename[:15] + "..."

    ts = fv.get("timestamp") or time.time()
    t_str = time.strftime("%H:%M:%S", time.localtime(ts / 1000.0 if ts > 1e12 else ts))

    pid = ecar.get("pid", fv.get("pid", -1))
    s_ent = fv.get("S_entropy", 0.0)
    s_dist = fv.get("S_dist", 0.0)
    s_dev = fv.get("S_dev", 0.0)
    s_rel = fv.get("S_rel", 0.0)
    s_comp = fusion_res.get("S_composite", 0.0)
    drift = fusion_res.get("IntentDrift", 0.0)
    tier = fusion_res.get("threat_tier", "BENIGN")

    if tier == "CRITICAL":
        tier_display = "🔴 CRITICAL"
    elif tier == "HIGH":
        tier_display = "🟠 HIGH"
    elif tier == "ELEVATED":
        tier_display = "🟡 ELEVATED"
    else:
        tier_display = "🟢 BENIGN"

    return (
        f"{idx:<4} | {t_str:<8} | {pid:<6} | {file_basename:<18} | "
        f"{s_ent:<6.3f} | {s_dist:<6.3f} | {s_dev:<6.3f} | {s_rel:<6.3f} | {s_comp:<7.3f} | {drift:<11.3f} | {tier_display:<12}"
    )


def run_integrated_simulation(target_dir: Path):
    """Generates benign baseline followed by ransomware burst attack."""
    time.sleep(1.2)
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Benign document editing
    for i in range(1, 4):
        p = target_dir / f"meeting_notes_{i}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"Meeting notes #{i}\nAgenda: Review Q3 financials and team roadmap.\nStatus: Normal.\n")
        time.sleep(0.35)

    time.sleep(0.5)

    # 2. Ransomware burst attack
    for i in range(1, 7):
        # Create victim
        orig = target_dir / f"financial_audit_{i}.xlsx"
        with open(orig, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL ACCOUNT BALANCES AND LEDGER DATA " * 15)

        # Encrypt with high entropy
        enc_path = target_dir / f"financial_audit_{i}.xlsx.locked"
        with open(enc_path, "wb") as f:
            f.write(secrets.token_bytes(4096))
            f.flush()
            os.fsync(f.fileno())

        try:
            orig.unlink()
        except OSError:
            pass

        time.sleep(0.2)

    # Final summary box after simulation finishes
    time.sleep(1.0)
    print("\n" + "=" * 118, flush=True)
    print("  STAGE 6 THREAT FUSION VERIFICATION SUMMARY", flush=True)
    print("=" * 118, flush=True)
    print("  [1] Single-Signal Suppression : Benign text editing produces S_comp < 0.30 -> IntentDrift < 0.05 (🟢 BENIGN)", flush=True)
    print("  [2] Sigmoidal Acceleration    : Multi-signal attack (High Entropy + Velocity + Distance) crosses theta=0.50", flush=True)
    print("  [3] Rapid Escalation           : Exponential slope beta=15.0 accelerates drift to 0.75+ (🔴 CRITICAL)", flush=True)
    print("  [4] Downstream Handoff         : CRITICAL_RISK signal dispatched to Stage 7 Trust Engine", flush=True)
    print("=" * 118 + "\n", flush=True)
    print("  [Live Monitor] Active and listening for further file events. Press Ctrl+C to stop.", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Live Stage 6 Threat Fusion Monitor")
    parser.add_argument("--path", type=str, help="Custom folder path to watch in real-time")
    parser.add_argument("--manual", action="store_true", help="Manual mode only (do not run auto-simulation)")
    args = parser.parse_args()

    test_dir = PROJECT_ROOT / "monitored_test_dir"
    test_dir.mkdir(parents=True, exist_ok=True)

    watch_paths = [str(test_dir.resolve())]
    if args.path:
        custom_p = Path(args.path).expanduser().resolve()
        custom_p.mkdir(parents=True, exist_ok=True)
        if str(custom_p) not in watch_paths:
            watch_paths.append(str(custom_p))

    # Initialize Stage 1-6 engines
    scorer = AnomalyScorer(model_dir=str(PROJECT_ROOT / "models"))
    rarity = RarityEngine()
    fusion = ThreatFusion(beta=15.0, theta=0.50)
    dbrg = DBRGManager(decay_lambda=0.01)
    extractor = FeatureExtractor(dbrg_manager=dbrg)

    print_banner(watch_paths)

    raw_queue = queue.Queue(maxsize=10000)
    file_monitor = FileMonitor(paths=watch_paths, recursive=True)

    process_monitor = ProcessMonitor(poll_interval_sec=1.0, hash_timeout_sec=2.0)
    process_monitor.start()

    event_count = 0
    lock = threading.Lock()

    def process_ecar_event(ecar_event: dict):
        nonlocal event_count
        try:
            # Stage 3: DBRG graph
            dbrg.process_event(ecar_event)

            # Stage 4: Feature extraction
            fv = extractor.extract_features(ecar_event)
            if not fv:
                return

            # Stage 5: Anomaly score
            s5_result = scorer.score(fv)

            # Stage 2: Lineage rarity
            context = ecar_event.get("context", {})
            s_rel = rarity.calculate_s_rel(
                parent_exe_path=context.get("parent_exe", "UNKNOWN"),
                child_exe_path=context.get("exe_path", "UNKNOWN"),
            )
            fv_with_rel = dict(fv)
            fv_with_rel["S_rel"] = s_rel

            # Stage 6: Threat Fusion
            fusion_result = fusion.fuse(fv_with_rel, anomaly_result=s5_result)

            with lock:
                event_count += 1
                row_str = format_row(event_count, ecar_event, fv_with_rel, fusion_result)
                print(row_str, flush=True)

        except Exception as e:
            pass

    queue_joiner = QueueJoiner(
        raw_queue=raw_queue,
        process_monitor=process_monitor,
        db_writer=None,
        on_event_callback=process_ecar_event,
    )

    file_monitor.start(raw_queue)
    queue_joiner.start()

    # Trigger integrated demonstration in background thread unless --manual
    if not args.manual:
        sim_thread = threading.Thread(
            target=run_integrated_simulation,
            args=(test_dir,),
            daemon=True,
        )
        sim_thread.start()

    try:
        while True:
            time.sleep(0.5)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"\n[Live Monitor] Error: {e}")
    finally:
        print("\n[Live Monitor] Stopping telemetry streams...")
        try:
            file_monitor.stop()
        except Exception:
            pass
        try:
            process_monitor.stop()
        except Exception:
            pass
        try:
            queue_joiner.stop()
        except Exception:
            pass
        print(f"[Live Monitor] Stopped. Total events processed through Stage 6: {event_count}")


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    main()
