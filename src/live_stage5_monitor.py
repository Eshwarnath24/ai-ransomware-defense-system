"""
src/live_stage5_monitor.py
============================
Live Real-Time End-to-End System Monitor (Stages 1 through 5)

Watches real filesystem operations on disk in real time. Whenever YOU or any
process creates, edits, renames, or modifies files in the watched directory:
  1. Stage 1: Captures File I/O & Process PID / Hash Telemetry
  2. Stage 2: Enriches into structured eCAR Events
  3. Stage 3: Updates Dynamic Behavior Relationship Graph (DBRG)
  4. Stage 4: Extracts multi-layer statistical features & Hawkes Point Process
  5. Stage 5: Evaluates live Anomaly Score (DAC-OCF) & assigns Risk Tier

Usage:
  python src/live_stage5_monitor.py
  python src/live_stage5_monitor.py --path monitored_test_dir
  python src/live_stage5_monitor.py --path C:/Users/YourName/Downloads
"""

import sys
import os
import time
import argparse
import queue
import logging
from pathlib import Path

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Windows UTF-8 stdout fix
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import threading
from collector.file_monitor import FileMonitor
from collector.process_monitor import ProcessMonitor
from collector.queue_joiner import QueueJoiner
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_4_features.feature_extractor import FeatureExtractor
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer

# Suppress verbose debug logs in console
logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


def print_banner(watch_paths, scorer):
    print("=" * 105)
    print(" 🛡️  AI RANSOMWARE DEFENSE SYSTEM — LIVE END-TO-END MONITOR (STAGES 1 TO 5)")
    print("=" * 105)
    print(f" Engine Status : Stage 1-4 Active | Stage 5 Scorer Mode: {scorer.get_stats()['scoring_mode'].upper()}")
    print(" Active Watched Directories:")
    for p in watch_paths:
        print(f"   📂 {p}")
    print("\n HOW TO TEST LIVE:")
    print("   1. Keep this terminal window OPEN.")
    print("   2. Create/edit/save normal files in the watched folder  -->  Watch it classify as 🟢 SAFE")
    print("   3. Run encryption/burst workloads                     -->  Watch it escalate to 🟠 SUSPECT / 🔴 CRITICAL")
    print("=" * 105 + "\n")

    header = (
        f"{'#':<4} | {'Time':<8} | {'PID':<6} | {'Operation':<10} | {'File Name':<18} | "
        f"{'Entropy':<7} | {'λ_norm':<6} | {'S_anomaly':<9} | {'Confidence':<10} | {'Risk Tier':<12}"
    )
    print("-" * len(header))
    print(header)
    print("-" * len(header))


def format_row(idx: int, ecar: dict, fv: dict, score_res: dict) -> str:
    file_basename = os.path.basename(fv.get("file_path", ecar.get("file_path", "unknown")))
    if len(file_basename) > 18:
        file_basename = file_basename[:15] + "..."

    ts = fv.get("timestamp", ecar.get("timestamp", time.time()))
    t_str = time.strftime("%H:%M:%S", time.localtime(ts / 1000.0 if ts > 1e12 else ts))

    pid = ecar.get("process_id", fv.get("pid", -1))
    op = ecar.get("operation_type", fv.get("operation", "MODIFY"))
    entropy = fv.get("S_entropy", 0.0)
    lambda_norm = fv.get("lambda_norm", 0.0)
    anomaly_score = score_res.get("anomaly_score", 0.0)
    conf = score_res.get("confidence", 0.0)
    tier = score_res.get("risk_tier", "SAFE")

    # Visual indicators
    if tier == "CRITICAL":
        tier_display = "🔴 CRITICAL"
    elif tier == "SUSPECT":
        tier_display = "🟠 SUSPECT"
    elif tier == "WATCH":
        tier_display = "🟡 WATCH"
    else:
        tier_display = "🟢 SAFE"

    return (
        f"{idx:<4} | {t_str:<8} | {pid:<6} | {op:<10} | {file_basename:<18} | "
        f"{entropy:<7.3f} | {lambda_norm:<6.3f} | {anomaly_score:<9.3f} | {conf:<10.3f} | {tier_display:<12}"
    )


def main():
    parser = argparse.ArgumentParser(description="Live End-to-End Stages 1-5 Ransomware Defense Monitor")
    parser.add_argument("--path", type=str, help="Custom folder path to watch in real-time")
    args = parser.parse_args()

    # Default watch path: monitored_test_dir in workspace root
    test_dir = PROJECT_ROOT / "monitored_test_dir"
    if not test_dir.exists():
        test_dir.mkdir(parents=True, exist_ok=True)

    watch_paths = [str(test_dir.resolve())]
    if args.path:
        custom_p = Path(args.path).expanduser().resolve()
        if custom_p.exists():
            if str(custom_p) not in watch_paths:
                watch_paths.append(str(custom_p))
        else:
            print(f"⚠️ Creating watched folder: {custom_p}")
            custom_p.mkdir(parents=True, exist_ok=True)
            watch_paths.append(str(custom_p))

    # Initialize Stage 5 Anomaly Scorer
    scorer = AnomalyScorer(model_dir=str(PROJECT_ROOT / "models"))

    print_banner(watch_paths, scorer)

    raw_queue = queue.Queue(maxsize=10000)
    file_monitor = FileMonitor(paths=watch_paths, recursive=True)

    # Stage 1 Process Monitor
    process_monitor = ProcessMonitor(poll_interval_sec=1.0, hash_timeout_sec=2.0)
    process_monitor.start()

    # Stage 3 DBRG Graph Engine
    dbrg = DBRGManager(decay_lambda=0.01)

    # Stage 4 Feature Extractor
    extractor = FeatureExtractor(dbrg_manager=dbrg)

    event_count = 0
    lock = threading.Lock()

    def process_ecar_event(ecar_event: dict):
        nonlocal event_count
        # Stage 3
        dbrg.process_event(ecar_event)
        # Stage 4
        fv = extractor.extract_features(ecar_event)
        if fv:
            # Stage 5
            score_result = scorer.score(fv)
            with lock:
                event_count += 1
                print(format_row(event_count, ecar_event, fv, score_result), flush=True)

    queue_joiner = QueueJoiner(
        raw_queue=raw_queue,
        process_monitor=process_monitor,
        db_writer=None,
        on_event_callback=process_ecar_event,
    )

    # Start live telemetry capture
    file_monitor.start(raw_queue)
    queue_joiner.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[Live Monitor] Stopping telemetry streams...")
        file_monitor.stop()
        process_monitor.stop()
        queue_joiner.stop()
        print(f"[Live Monitor] Stopped. Total events processed through Stages 1-5: {event_count}")


if __name__ == "__main__":
    main()
