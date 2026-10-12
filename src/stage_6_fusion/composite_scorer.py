"""
src/stage_6_fusion/composite_scorer.py
========================================
Stage 6 — Priority-Weighted Causality Fusion Engine

Computes the Priority Composite Score (S_composite) by fusing five
independent threat sub-signals from Stage 2 (Lineage) and Stage 4
(Feature Extraction) using causality-priority weights.

Mathematical Foundation (from architecture specification):

    S_composite = (w_entropy * S_entropy)
                + (w_dist   * S_dist)
                + (w_dev    * S_dev)
                + (w_rel    * S_rel)
                + (w_stab   * (1 - S_stab))

Default Weights (from architecture specification — Section "Stage 6"):
    w_entropy = 0.35    (Content entropy — highest priority)
    w_dist    = 0.30    (Graph fan-out distance)
    w_dev     = 0.20    (Trajectory velocity)
    w_rel     = 0.10    (Lineage rarity — from Stage 2)
    w_stab    = 0.05    (Operational stability — inverted)

Design Notes:
    - S_stab measures stability (high = benign), so it is INVERTED to
      (1 - S_stab) so that instability contributes to threat.
    - S_rel may not be present in the Stage 4 feature vector (it comes
      from Stage 2's lineage module). Defaults to 0.0 if absent.
    - All input signals are clamped to [0.0, 1.0] before weighting.
    - Output S_composite is guaranteed in [0.0, 1.0].
    - This component is stateless and thread-safe.

Signal Source Mapping:
    S_entropy → Stage 4 feature_vector["S_entropy"]
    S_dist    → Stage 4 feature_vector["S_dist"]
    S_dev     → Stage 4 feature_vector["S_dev"]
    S_rel     → Stage 2 lineage rarity (feature_vector.get("S_rel", 0.0))
    S_stab    → Stage 4 feature_vector["S_stab"]
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Architecture-specified default signal weights
DEFAULT_WEIGHTS: Dict[str, float] = {
    "S_entropy": 0.35,
    "S_dist": 0.30,
    "S_dev": 0.20,
    "S_rel": 0.10,
    "S_stab": 0.05,
}


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a value to the range [lo, hi]."""
    return max(lo, min(hi, value))


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert any input value to a finite float."""
    if val is None:
        return default
    try:
        f = float(val)
        if f != f:  # NaN check without numpy
            return default
        if f == float("inf") or f == float("-inf"):
            return default
        return f
    except (ValueError, TypeError):
        return default


class CompositeScorer:
    """
    Priority-weighted causality fusion engine for threat sub-signals.

    Computes S_composite from 5 independent behavioural signals using
    architecture-specified priority weights.

    Parameters
    ----------
    weights : dict, optional
        Custom signal weights. Keys must be a subset of
        {"S_entropy", "S_dist", "S_dev", "S_rel", "S_stab"}.
        Defaults to the architecture-specified weights.

    Attributes
    ----------
    weights : dict
        Active signal weights.
    total_scored : int
        Number of composite scores computed.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights: Dict[str, float] = (
            weights.copy() if weights is not None else DEFAULT_WEIGHTS.copy()
        )
        self.total_scored: int = 0

    def compute(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute the priority composite score from a Stage 4 feature vector.

        Parameters
        ----------
        feature_vector : dict
            Must contain at minimum S_entropy, S_dist, S_dev, S_stab.
            S_rel is optional (defaults to 0.0 if absent — lineage not active).

        Returns
        -------
        dict
            {
                "S_composite": float,   # Weighted composite [0, 1]
                "signals": {            # Individual clamped signal values
                    "S_entropy": float,
                    "S_dist": float,
                    "S_dev": float,
                    "S_rel": float,
                    "S_stab_inv": float,  # 1 - S_stab (inverted)
                },
                "weights": dict,        # Active weights used
            }
        """
        # Extract and clamp individual signals to [0, 1]
        s_entropy = _clamp(_safe_float(feature_vector.get("S_entropy"), 0.0))
        s_dist = _clamp(_safe_float(feature_vector.get("S_dist"), 0.0))
        s_dev = _clamp(_safe_float(feature_vector.get("S_dev"), 0.0))
        s_rel = _clamp(_safe_float(feature_vector.get("S_rel"), 0.0))
        s_stab = _clamp(_safe_float(feature_vector.get("S_stab"), 0.5))

        # Invert S_stab: high stability (benign) → low threat contribution
        s_stab_inv = 1.0 - s_stab

        # Priority-weighted fusion
        s_composite = (
            self.weights.get("S_entropy", 0.35) * s_entropy
            + self.weights.get("S_dist", 0.30) * s_dist
            + self.weights.get("S_dev", 0.20) * s_dev
            + self.weights.get("S_rel", 0.10) * s_rel
            + self.weights.get("S_stab", 0.05) * s_stab_inv
        )

        # Clamp output to [0, 1]
        s_composite = _clamp(s_composite)

        self.total_scored += 1

        logger.debug(
            "[Stage6-Composite] S_ent=%.3f  S_dist=%.3f  S_dev=%.3f  "
            "S_rel=%.3f  S_stab_inv=%.3f  → S_composite=%.4f",
            s_entropy, s_dist, s_dev, s_rel, s_stab_inv, s_composite,
        )

        return {
            "S_composite": s_composite,
            "signals": {
                "S_entropy": s_entropy,
                "S_dist": s_dist,
                "S_dev": s_dev,
                "S_rel": s_rel,
                "S_stab_inv": s_stab_inv,
            },
            "weights": self.weights.copy(),
        }

    def get_weight_sum(self) -> float:
        """Return the sum of all weights (should equal 1.0)."""
        return sum(self.weights.values())

    def __repr__(self) -> str:
        return (
            f"CompositeScorer(weights={self.weights}, "
            f"total_scored={self.total_scored})"
        )
