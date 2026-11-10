"""
src/stage_9_containment
=========================
Stage 9 — Freeze-Graph Min-Cut Containment Engine

Receives the ``should_contain`` signal from Stage 7 when a process
reaches CRITICAL_RISK (Trust < 20) and executes the full containment
sequence:

    1. Compute the Edmonds-Karp minimum s-t cut on the Stage 3 DBRG to
       find the optimal set of edges to sever, isolating the malicious
       process from its file targets at minimum total cut cost.
    2. Freeze (suspend) the process via simulated NtSuspendProcess
       (Windows) or SIGSTOP (Linux), with dry-run mode by default.
    3. Record the containment event with full audit details: cut edges,
       isolated files, trust score, risk tier, and latency.
    4. Support false-positive recovery by releasing frozen processes
       (Stage 10 or analyst override).

Safety:
    All operations default to dry-run (simulation) mode.  No real OS
    process suspension occurs unless ``dry_run=False`` is explicitly
    set during engine construction.

Exports:
    ContainmentEngine  — Main orchestrator (Stage 7 → contain → Stage 10)
    ContainmentRecord  — Dataclass for containment audit log entries
    GraphCutEngine     — Edmonds-Karp min-cut on the DBRG
    MinCutResult       — Frozen dataclass for min-cut computation results
    ProcessFreezer     — Simulated kernel process suspension manager
    FreezeResult       — Dataclass for freeze/release operation results
    ContainmentAction  — Enum: FREEZE, RELEASE, REVOKE_ACCESS
    ContainmentState   — Enum: ACTIVE, FROZEN, RELEASED
"""

__version__ = "1.0.0"
__stage__ = "Stage 9: Freeze-Graph Min-Cut Containment Engine"

from src.stage_9_containment.graph_cut import GraphCutEngine, MinCutResult
from src.stage_9_containment.process_freezer import (
    ContainmentAction,
    ContainmentState,
    FreezeResult,
    ProcessFreezer,
)
from src.stage_9_containment.containment_engine import (
    ContainmentEngine,
    ContainmentRecord,
)

__all__ = [
    "ContainmentEngine",
    "ContainmentRecord",
    "GraphCutEngine",
    "MinCutResult",
    "ProcessFreezer",
    "FreezeResult",
    "ContainmentAction",
    "ContainmentState",
]

