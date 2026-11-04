"""
src/stage_7_trust
=====================
Stage 7 - Dynamic Adaptive Trust Evolution & Risk State Engine

Consumes Stage 6's ThreatFusion.fuse() output and evolves a per-process
Trust score (100 -> 0) with a momentum penalty for accelerating threats,
then maps that score onto one of four risk tiers: SAFE, MONITOR, VERIFY,
CRITICAL_RISK. CRITICAL_RISK is what should trigger Stage 9's kernel
containment.

Exports:
    TrustDecayEngine  - Trust(t) formula, per-PID state
    RiskStateMachine  - Trust -> tier mapping + transition tracking
    TrustEvolution    - orchestrator combining both into one evolve() call
"""

from src.stage_7_trust.trust_engine import TrustDecayEngine, DEFAULT_GAMMA
from src.stage_7_trust.risk_state_machine import (
    RiskStateMachine,
    DEFAULT_THRESHOLDS,
    TIER_ORDER,
)
from src.stage_7_trust.trust_evolution import TrustEvolution

__all__ = [
    "TrustDecayEngine",
    "RiskStateMachine",
    "TrustEvolution",
    "DEFAULT_GAMMA",
    "DEFAULT_THRESHOLDS",
    "TIER_ORDER",
]
