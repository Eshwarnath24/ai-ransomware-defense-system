"""
src/stage_10_enforcer
========================
Stage 10 — Fine-Grained Enforcer, Write-Ahead Journaling & Selective Rollback

Enforces fine-grained ACL access revocations along C_min paths and
executes zero-data-loss rollback for confirmed threats, or seamless
resumption for false positives.

Pipeline Position:
    Stage 7 (prewarm_journal) → arm journaling
    Stage 9 (ContainmentRecord) → enforce ACL revocations
    Stage 11 (dashboard buttons) → resolve(MALICIOUS / FALSE_POSITIVE)

Exports:
    Enforcer            — Main orchestrator
    EnforcementRecord   — Per-PID enforcement state
    ResolutionResult    — Result of resolve()
    Verdict             — MALICIOUS | FALSE_POSITIVE
    EnforcementState    — PENDING | RESOLVED_MALICIOUS | RESOLVED_FP

    JournalVault        — Write-ahead mmap vault
    JournalEntry        — Single file snapshot metadata
    RollbackEngine      — Byte-for-byte file restore
    RollbackReport      — Aggregate restore result
    FileRestoreResult   — Per-file restore result

    ACLManager          — Write-permission revocation
    ACLRecord           — Per-path ACL audit record

    ProcessTerminator   — SIGKILL with safety guards
    TerminateResult     — Kill attempt result

    Stage10Config       — Configuration with defaults
"""

__version__ = "1.0.0"
__stage__ = "Stage 10: Fine-Grained Enforcer, Write-Ahead Journaling & Selective Rollback"

from src.stage_10_enforcer.acl_manager import ACLManager, ACLRecord
from src.stage_10_enforcer.journal_rollback import (
    FileRestoreResult,
    JournalEntry,
    JournalVault,
    RollbackEngine,
    RollbackReport,
)
from src.stage_10_enforcer.process_terminator import ProcessTerminator, TerminateResult
from src.stage_10_enforcer.enforcer import (
    Enforcer,
    EnforcementRecord,
    EnforcementState,
    ResolutionResult,
    Stage10Config,
    Verdict,
)

__all__ = [
    "Enforcer",
    "EnforcementRecord",
    "ResolutionResult",
    "Verdict",
    "EnforcementState",
    "JournalVault",
    "JournalEntry",
    "RollbackEngine",
    "RollbackReport",
    "FileRestoreResult",
    "ACLManager",
    "ACLRecord",
    "ProcessTerminator",
    "TerminateResult",
    "Stage10Config",
]

