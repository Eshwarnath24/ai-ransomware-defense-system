"""
src/stage_8_harness
======================
Stage 8 — Synthetic Ransomware Test Harness

A safe, sandboxed red-team attack simulator that:
  1. Creates realistic mock victim file environments (Documents, Desktop, etc.)
  2. Simulates multi-phase ransomware attacks (encryption, renaming, ransom notes)
  3. Supports multiple attack speed profiles (LockBit, WannaCry, BlackCat)
  4. Measures detection latency and file damage before containment

Safety:
  Every file operation is guarded by hard path-boundary checks that
  prevent any write/rename/delete outside the sandbox directory.

Exports:
    SandboxManager   — Creates and manages the victim file environment
    AttackEngine     — Executes simulated ransomware encryption attacks
    AttackProfile    — Dataclass defining attack speed/behavior parameters
    BenchmarkLogger  — Millisecond-precision latency and damage tracker
    LOCKBIT_AGGRESSIVE, WANNACRY_BURST, BLACKCAT_STEALTH — preset profiles
"""

__version__ = "1.0.0"
__stage__ = "Stage 8: Synthetic Ransomware Test Harness"

from src.stage_8_harness.sandbox_manager import SandboxManager
from src.stage_8_harness.attack_profiles import (
    AttackProfile,
    LOCKBIT_AGGRESSIVE,
    WANNACRY_BURST,
    BLACKCAT_STEALTH,
)
from src.stage_8_harness.attack_engine import AttackEngine, AttackResult
from src.stage_8_harness.benchmark_logger import BenchmarkLogger, BenchmarkReport

__all__ = [
    "SandboxManager",
    "AttackEngine",
    "AttackResult",
    "AttackProfile",
    "BenchmarkLogger",
    "BenchmarkReport",
    "LOCKBIT_AGGRESSIVE",
    "WANNACRY_BURST",
    "BLACKCAT_STEALTH",
]
