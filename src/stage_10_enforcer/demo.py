"""
src/stage_10_enforcer/demo.py
================================
Stage 10 — Standalone CLI Demo (Zero-Data-Loss Proof)

Demonstrates the full Stage 10 pipeline in a self-contained sandbox:
  1. Creates victim files with known content
  2. Arms the journal
  3. Simulates encryption (overwrites with random bytes + renames)
  4. Enforces ACL revocation
  5. Resolves as MALICIOUS → rollback
  6. Verifies byte-for-byte restoration

Usage:
    python -m src.stage_10_enforcer.demo
    python -m src.stage_10_enforcer.demo --num-files 20
    python -m src.stage_10_enforcer.demo --verdict false_positive
"""

import argparse
import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_10_enforcer.acl_manager import ACLManager
from src.stage_10_enforcer.journal_rollback import JournalVault, RollbackEngine
from src.stage_10_enforcer.process_terminator import ProcessTerminator
from src.stage_10_enforcer.enforcer import Enforcer, Verdict


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Stage 10 — Zero-Data-Loss Demo",
    )
    parser.add_argument("--num-files", type=int, default=10)
    parser.add_argument(
        "--verdict",
        choices=["malicious", "false_positive"],
        default="malicious",
    )
    args = parser.parse_args()

    num_files = args.num_files
    verdict = Verdict.MALICIOUS if args.verdict == "malicious" else Verdict.FALSE_POSITIVE
    fake_pid = 9999

    print("=" * 65)
    print("  STAGE 10 — ZERO DATA LOSS DEMONSTRATION")
    print(f"  Files: {num_files}    Verdict: {verdict.value}")
    print("=" * 65)

    # Create a temporary sandbox
    with tempfile.TemporaryDirectory(prefix="stage10_demo_") as sandbox_dir:
        vault_dir = os.path.join(sandbox_dir, ".vault")

        # ── 1. Create victim files ────────────────────────────
        print("\n[1/6] Creating victim files...")
        victim_dir = os.path.join(sandbox_dir, "victims")
        os.makedirs(victim_dir)
        pre_hashes = {}
        for i in range(num_files):
            content = f"Important document #{i}\nThis is critical data.\n" * 100
            fp = os.path.join(victim_dir, f"document_{i:03d}.txt")
            with open(fp, "w") as f:
                f.write(content)
            pre_hashes[fp] = _sha256(fp)
            print(f"  Created: document_{i:03d}.txt ({len(content)} bytes)")

        # ── 2. Initialize Stage 10 ────────────────────────────
        print("\n[2/6] Initializing Stage 10 Enforcer...")

        # Minimal mock for ContainmentEngine (just enough for demo)
        class _MockContainment:
            def release(self, pid, reason=""):
                class _R:
                    success = True
                return _R()

        class _MockTrust:
            def confirm_false_positive(self, pid):
                return {"pid": pid, "trust": 100.0, "risk_tier": "SAFE"}

        vault = JournalVault(
            vault_dir=vault_dir,
            max_vault_bytes=512 * 1024 * 1024,
        )
        enforcer = Enforcer(
            containment_engine=_MockContainment(),
            trust_evolution=_MockTrust(),
            vault=vault,
            dry_run=True,
            always_on=True,
            allowed_roots=[sandbox_dir],
            rollback_dry_run=False,
        )
        print(f"  Vault: {vault_dir}")
        print(f"  Enforcer: dry_run={enforcer.dry_run}, always_on={enforcer.always_on}")

        # ── 3. Simulate encryption (with pre-write journaling) ─
        print(f"\n[3/6] Simulating encryption of {num_files} files...")
        t_attack = time.perf_counter()

        encrypted_paths = {}
        for fp in sorted(pre_hashes.keys()):
            # Snapshot before write (pre-write hook)
            enforcer.before_write(fp, fake_pid)

            # Overwrite with random bytes
            size = os.path.getsize(fp)
            with open(fp, "wb") as f:
                f.write(os.urandom(max(size, 1024)))

            # Rename
            new_path = fp + ".locked"
            os.rename(fp, new_path)
            enforcer.note_rename(fake_pid, fp, new_path)
            encrypted_paths[fp] = new_path

        # Drop a ransom note
        note_path = os.path.join(victim_dir, "RANSOM_NOTE.txt")
        with open(note_path, "w") as f:
            f.write("Your files have been encrypted! Pay 1 BTC to restore.")
        enforcer.note_created(fake_pid, note_path)

        attack_ms = (time.perf_counter() - t_attack) * 1000.0
        print(f"  Encrypted {num_files} files in {attack_ms:.1f}ms")
        print(f"  Ransom note dropped: {os.path.basename(note_path)}")

        # ── 4. Simulate containment (mock) ─────────────────────
        print("\n[4/6] Simulating Stage 9 containment...")
        from dataclasses import dataclass, field

        @dataclass
        class _FreezeResult:
            pid: int = fake_pid
            action: str = "FREEZE"
            success: bool = True
            timestamp: float = 0.0
            reason: str = "demo"
            dry_run: bool = True
            latency_ms: float = 0.1
            error: str = ""

        @dataclass
        class _Record:
            pid: int = fake_pid
            action: str = "CONTAIN"
            timestamp: float = field(default_factory=time.time)
            cut_value: float = 0.0
            cut_edges: list = field(default_factory=list)
            isolated_files: list = field(default_factory=list)
            freeze_result: _FreezeResult = field(default_factory=_FreezeResult)
            trust_at_containment: float = 0.0
            risk_tier_at_containment: str = "CRITICAL_RISK"
            latency_ms: float = 0.5
            success: bool = True

        contain_record = _Record(
            cut_edges=[
                (f"pid:{fake_pid}", f"file:{fp}")
                for fp in pre_hashes.keys()
            ],
            isolated_files=[f"file:{fp}" for fp in pre_hashes.keys()],
        )
        enforcement = enforcer.enforce(contain_record)
        print(f"  Enforcement: state={enforcement.state.value}, ACLs={len(enforcement.acl_records)}")

        # ── 5. Resolve ─────────────────────────────────────────
        print(f"\n[5/6] Resolving as {verdict.value}...")
        t_resolve = time.perf_counter()
        resolution = enforcer.resolve(fake_pid, verdict)
        resolve_ms = (time.perf_counter() - t_resolve) * 1000.0

        print(f"  Success: {resolution.success}")
        for step in resolution.steps:
            print(f"    → {step}")

        # ── 6. Verify ─────────────────────────────────────────
        print(f"\n[6/6] Verification...")
        files_lost = 0

        if verdict == Verdict.MALICIOUS:
            for fp, expected_hash in pre_hashes.items():
                if not os.path.exists(fp):
                    print(f"  MISSING: {os.path.basename(fp)}")
                    files_lost += 1
                    continue
                actual_hash = _sha256(fp)
                if actual_hash != expected_hash:
                    print(f"  CORRUPTED: {os.path.basename(fp)}")
                    files_lost += 1
                else:
                    pass  # OK

            # Check artifacts removed
            artifacts_remaining = sum(
                1 for p in encrypted_paths.values() if os.path.exists(p)
            )
            note_exists = os.path.exists(note_path)

            print(f"\n  {'=' * 50}")
            print(f"  Files lost       : {files_lost}")
            print(f"  Zero data loss   : {'YES' if files_lost == 0 else 'NO'}")
            print(f"  Artifacts removed: {len(encrypted_paths) - artifacts_remaining}/{len(encrypted_paths)}")
            print(f"  Ransom note gone : {'YES' if not note_exists else 'NO'}")
            print(f"  Rollback time    : {resolve_ms:.1f}ms")
            print(f"  {'=' * 50}")
        else:
            print("  FALSE_POSITIVE: No rollback performed (writes were legitimate)")
            print(f"  Trust reset: {resolution.trust_reset}")
            print(f"  ACLs restored: {resolution.acl_restored}")

        stats = enforcer.get_stats()
        print(f"\n  Enforcer stats: enforcements={stats['total_enforcements']}, "
              f"resolutions={stats['total_resolutions']}")

    print("\nDemo complete.\n")


if __name__ == "__main__":
    main()

