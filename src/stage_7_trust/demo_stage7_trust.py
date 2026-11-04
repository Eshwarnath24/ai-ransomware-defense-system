"""
src/stage_7_trust/demo_stage7_trust.py
==========================================
Stage 7 Demo: Trust Decay and Risk Escalation Over a Sequence of Events

Feeds a sequence of Stage 6 fuse()-shaped results through TrustEvolution
and prints how a process's trust collapses (or doesn't) across SAFE ->
MONITOR -> VERIFY -> CRITICAL_RISK, including the false-positive
forgiveness path.

Usage:
    python src/stage_7_trust/demo_stage7_trust.py
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_7_trust import TrustEvolution

TIER_ICON = {
    "SAFE": "\U0001F7E2",
    "MONITOR": "\U0001F7E1",
    "VERIFY": "\U0001F7E0",
    "CRITICAL_RISK": "\U0001F534",
}


def print_header(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def make_stage6_result(pid, intent_drift, drift_rate, t):
    """Build a minimal dict shaped like ThreatFusion.fuse()'s output."""
    return {
        "pid": pid,
        "IntentDrift": intent_drift,
        "drift_rate": drift_rate,
        "threat_tier": "CRITICAL" if intent_drift >= 0.75 else "ELEVATED",
        "timestamp": t,
    }


def run_sequence(evolution: TrustEvolution, pid: int, events):
    for idx, (intent_drift, drift_rate, label) in enumerate(events, 1):
        t = time.time() + idx
        s6 = make_stage6_result(pid, intent_drift, drift_rate, t)
        result = evolution.evolve(s6)
        icon = TIER_ICON.get(result["risk_tier"], "")
        flag = ""
        if result["escalated"]:
            flag = "  <-- ESCALATED"
        elif result["deescalated"]:
            flag = "  <-- de-escalated"
        print(
            f"  [{idx}] {label:<28} IntentDrift={intent_drift:.2f}  rate={drift_rate:+.2f}  "
            f"-> Trust={result['trust']:6.2f}  {icon} {result['risk_tier']:<13}{flag}"
        )
        if result["should_contain"]:
            print(f"        >>> Stage 9 containment would trigger here (PID {pid})")
        if result["prewarm_journal"] and result["risk_tier"] == "VERIFY":
            print(f"        >>> Stage 10 journal buffers pre-warmed")


def main():
    print_header("STAGE 7: DYNAMIC ADAPTIVE TRUST EVOLUTION DEMO")

    evolution = TrustEvolution(gamma=0.5)
    print(f"\n  Engine: {evolution}")

    print("\n[CASE 1] Benign process - low, flat IntentDrift, trust should barely move")
    run_sequence(evolution, pid=4001, events=[
        (0.05, 0.0, "normal file save"),
        (0.06, 0.01, "normal file save"),
        (0.04, -0.02, "normal file save"),
    ])

    print("\n[CASE 2] Ransomware burst - IntentDrift rising fast, trust should collapse quickly")
    run_sequence(evolution, pid=6666, events=[
        (0.30, 0.00, "first suspicious write"),
        (0.60, 0.30, "fan-out widening"),
        (0.85, 0.25, "entropy + fan-out converge"),
        (0.95, 0.10, "sustained high intent"),
    ])

    print("\n[CASE 3] False positive on PID 6666 - analyst resolves it via Stage 10")
    before = evolution.trust_engine.get_trust(6666)
    result = evolution.confirm_false_positive(6666)
    print(f"  Trust before resolution: {before:.2f}")
    print(f"  Trust after Stage 10 resolves as false positive: {result['trust']:.2f} -> {result['risk_tier']}")

    print_header("SUMMARY")
    print(f"  {evolution.get_stats()}")
    print("  Case 1: flat low intent -> trust stays near 100, process never leaves SAFE.")
    print("  Case 2: accelerating intent -> trust collapses in a handful of events,")
    print("          crossing MONITOR -> VERIFY -> CRITICAL_RISK, triggering containment.")
    print("  Case 3: once Stage 10 confirms false positive, trust is fully restored,")
    print("          independent of how low it had fallen.")


if __name__ == "__main__":
    main()
