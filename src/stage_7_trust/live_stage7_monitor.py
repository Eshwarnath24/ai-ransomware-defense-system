"""
src/stage_7_trust/live_stage7_monitor.py
============================================
Live Real-Time End-to-End System Monitor (Stages 1 through 7)

Watches real filesystem operations and runs each one through the full
implemented pipeline: Stage 1 telemetry -> Stage 2 lineage -> Stage 3
DBRG -> Stage 4 features -> Stage 5 anomaly score -> Stage 6 threat
fusion -> Stage 7 trust evolution. Prints one row per event showing how
trust evolves and which risk tier the process is sitting in.

Usage:
  python src/stage_7_trust/live_stage7_monitor.py
  python src/stage_7_trust/live_stage7_monitor.py --path monitored_test_dir
"""

import sys
import os
import time
import argparse
import queue
import logging
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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
from src.stage_6_fusion import ThreatFusion
from src.stage_7_trust import TrustEvolution

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")

_TIER_ICON = {
    "SAFE": "\U0001F7E2",
    "MONITOR": "\U0001F7E1",
    "VERIFY": "\U0001F7E0",
    "CRITICAL_RISK": "\U0001F534",
}


def print_banner(watch_paths, scorer):
    print("=" * 130)
    print(" \U0001F6E1️  AI RANSOMWARE DEFENSE SYSTEM - LIVE END-TO-END MONITOR (STAGES 1 TO 7)")
    print("=" * 130)
    print(f" Stage 5 Scorer Mode : {scorer.get_stats()['scoring_mode'].upper()}")
    print(" Stage 6/7 Engines   : ThreatFusion -> TrustEvolution (gamma=0.5)")
    print(" Active Watched Directories:")
    for p in watch_paths:
        print(f"   \U0001F4C2 {p}")
    print("\n HOW TO TEST LIVE:")
    print("   1. Keep this terminal window OPEN.")
    print("   2. Create/edit/save normal files in the watched folder")
    print("      -->  Trust should barely move, stay 🟢 SAFE.")
    print("   3. In a SECOND terminal, run:  python simulate_ransomware.py")
    print("      -->  Watch Trust collapse across successive events,")
    print("           SAFE -> MONITOR -> VERIFY -> CRITICAL_RISK.")
    print("=" * 130 + "\n")

    header = (
        f"{'#':<4} | {'Time':<8} | {'PID':<6} | {'File Name':<18} | "
        f"{'S6:Drift':<8} | {'S6:Vel':<7} | {'Trust':<7} | {'RiskTier':<16} | {'Action'}"
    )
    print("-" * len(header))
    print(header)
    print("-" * len(header))


def format_row(idx: int, ecar: dict, fv: dict, s6: dict, s7: dict) -> str:
    file_basename = os.path.basename(fv.get("file_path", "unknown"))
    if len(file_basename) > 18:
        file_basename = file_basename[:15] + "..."

    ts = fv.get("timestamp", ecar.get("timestamp", time.time()))
    t_str = time.strftime("%H:%M:%S", time.localtime(ts / 1000.0 if ts > 1e12 else ts))

    pid = ecar.get("pid", fv.get("pid", -1))
    drift = s7.get("intent_drift", 0.0)
    velocity = s6.get("drift_rate", 0.0)  # Stage 6's IntentDrift finite-difference rate
    trust = s7.get("trust", 100.0)
    tier = s7.get("risk_tier", "SAFE")
    tier_display = f"{_TIER_ICON.get(tier, '')} {tier}"

    action = ""
    if s7.get("escalated"):
        action = "ESCALATED"
    if s7.get("should_contain"):
        action = "CONTAIN (Stage 9)"
    elif s7.get("prewarm_journal"):
        action = "pre-warm journal"
    elif s7.get("sampling_multiplier", 1) > 1:
        action = "2x sampling"

    return (
        f"{idx:<4} | {t_str:<8} | {pid:<6} | {file_basename:<18} | "
        f"{drift:<8.3f} | {velocity:<+7.2f} | {trust:<7.2f} | {tier_display:<16} | {action}"
    )


def main():
    parser = argparse.ArgumentParser(description="Live End-to-End Stages 1-7 Ransomware Defense Monitor")
    parser.add_argument("--path", type=str, help="Custom folder path to watch in real-time")
    parser.add_argument("--gamma", type=float, default=0.5, help="Stage 7 trust decay multiplier")
    args = parser.parse_args()

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
            print(f"Creating watched folder: {custom_p}")
            custom_p.mkdir(parents=True, exist_ok=True)
            watch_paths.append(str(custom_p))

    scorer = AnomalyScorer(model_dir=str(PROJECT_ROOT / "models"))
    rarity = RarityEngine()
    fusion = ThreatFusion()
    evolution = TrustEvolution(gamma=args.gamma)

    print_banner(watch_paths, scorer)
    print("  >> Monitor is RUNNING. Keep this terminal open.")
    print()

    raw_queue = queue.Queue(maxsize=10000)
    file_monitor = FileMonitor(paths=watch_paths, recursive=True)

    process_monitor = ProcessMonitor(poll_interval_sec=1.0, hash_timeout_sec=2.0)
    process_monitor.start()

    dbrg = DBRGManager(decay_lambda=0.01)
    extractor = FeatureExtractor(dbrg_manager=dbrg)

    event_count = 0
    lock = threading.Lock()

    def process_ecar_event(ecar_event: dict):
        nonlocal event_count
        try:
            # Stage 3
            dbrg.process_event(ecar_event)
            # Stage 4
            fv = extractor.extract_features(ecar_event)
            if not fv:
                return

            # Stage 5
            s5_result = scorer.score(fv)

            # Stage 2: live lineage rarity, folded into the feature vector
            # so Stage 6's composite scorer can read S_rel directly
            context = ecar_event.get("context", {})
            s_rel = rarity.calculate_s_rel(
                parent_exe_path=context.get("parent_exe", "UNKNOWN"),
                child_exe_path=context.get("exe_path", "UNKNOWN"),
            )
            fv_with_rel = dict(fv)
            fv_with_rel["S_rel"] = s_rel

            # Stage 6
            s6_result = fusion.fuse(fv_with_rel, anomaly_result=s5_result)

            # Stage 7
            s7_result = evolution.evolve(s6_result)

            with lock:
                event_count += 1
                print(format_row(event_count, ecar_event, fv, s6_result, s7_result), flush=True)
        except Exception:
            pass  # Silently skip problematic events

    queue_joiner = QueueJoiner(
        raw_queue=raw_queue,
        process_monitor=process_monitor,
        db_writer=None,
        on_event_callback=process_ecar_event,
    )

    file_monitor.start(raw_queue)
    queue_joiner.start()

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
        print(f"[Live Monitor] Stopped. Total events processed through Stages 1-7: {event_count}")
        print(f"[Live Monitor] Stage 7 stats: {evolution.get_stats()}")


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    main()
