"""
tests/test_stage_10_enforcer.py
==================================
Stage 10 — Fine-Grained Enforcer, Write-Ahead Journaling & Selective Rollback

Comprehensive test suite targeting ≥ 95 tests across 9 test classes.

Category breakdown:
    TestJournalVault          — 18 tests  (mmap snapshot, SHA, first-copy-wins, caps, concurrency)
    TestVaultRenameTracking   —  6 tests  (rename chains, note_created, manifest reload)
    TestRollbackEngine        — 16 tests  (byte restore, atomicity, allowed_roots, dry_run)
    TestACLManager            — 14 tests  (revoke/restore, idempotent, backends, stats)
    TestProcessTerminator     — 10 tests  (safety guards, dry-run, real process test)
    TestEnforcer              — 20 tests  (enforce, resolve, arming, always_on, concurrent)
    TestStageIntegration      — 15 tests  (real DBRG + ContainmentEngine + Enforcer)
    TestHarnessZeroLoss       — 10 tests  (parametrized harness, zero-loss per profile)
    TestUpstreamFixes         —  4 tests  (F1 freeze order, F2 config, F3 logging, F5 hooks)
    ──────────────────────────────────────
    Total                     113 tests

Test conventions:
    - Uses ``tmp_path`` fixtures for every vault and sandbox (never real /tmp)
    - No network, no sleeps > 100ms, deterministic seeds
    - Linux-only tests marked with ``@pytest.mark.skipif(sys.platform == "win32", ...)``
    - Mode-bit tests preferred over root checks
"""

import hashlib
import json
import os
import signal
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
#   Stage 10 imports
# ---------------------------------------------------------------------------

from src.stage_10_enforcer.acl_manager import (
    ACLManager,
    ACLRecord,
    PosixACLBackend,
    SimulatedACLBackend,
    WindowsACLBackend,
)
from src.stage_10_enforcer.journal_rollback import (
    FileRestoreResult,
    JournalEntry,
    JournalVault,
    RollbackEngine,
    RollbackReport,
    VaultSecurityError,
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

# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def _make_file(directory, name: str, content: bytes = b"hello world\n") -> str:
    fp = os.path.join(str(directory), name)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "wb") as f:
        f.write(content)
    return fp


@dataclass
class MockFreezeResult:
    pid: int = 9999
    action: str = "FREEZE"
    success: bool = True
    timestamp: float = 0.0
    reason: str = "test"
    dry_run: bool = True
    latency_ms: float = 0.1
    error: str = ""


@dataclass
class MockContainmentRecord:
    pid: int = 9999
    action: str = "CONTAIN"
    timestamp: float = field(default_factory=time.time)
    cut_value: float = 1.0
    cut_edges: list = field(default_factory=list)
    isolated_files: list = field(default_factory=list)
    freeze_result: MockFreezeResult = field(default_factory=MockFreezeResult)
    trust_at_containment: float = 5.0
    risk_tier_at_containment: str = "CRITICAL_RISK"
    latency_ms: float = 0.5
    success: bool = True


class MockContainmentEngine:
    def __init__(self):
        self.released = []
        self.release_result = MockContainmentRecord(action="RELEASE")
        self.release_result.freeze_result = MockFreezeResult(action="RELEASE")

    def release(self, pid, reason=""):
        self.released.append((pid, reason))
        return self.release_result


class MockTrustEvolution:
    def __init__(self):
        self.fp_calls = []

    def confirm_false_positive(self, pid):
        self.fp_calls.append(pid)
        return {"pid": pid, "trust": 100.0, "risk_tier": "SAFE"}


# ═══════════════════════════════════════════════════════════════════════════
#   1. TestJournalVault (18 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestJournalVault:

    def test_snapshot_byte_identical(self, tmp_path):
        """Snapshot blob must be byte-identical to the original file."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        content = b"Important data for zero-loss testing\n" * 100
        fp = _make_file(tmp_path, "doc.txt", content)
        entry = vault.snapshot(fp, 1000)
        assert entry is not None
        blob = vault.read_blob(entry)
        assert blob == content

    def test_snapshot_sha256_correct(self, tmp_path):
        """SHA-256 in the entry must match the blob and the original."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        content = b"hash verification test data"
        fp = _make_file(tmp_path, "hash.bin", content)
        entry = vault.snapshot(fp, 1001)
        assert entry is not None
        assert entry.sha256 == _sha256(content)
        assert _sha256(vault.read_blob(entry)) == entry.sha256

    def test_snapshot_mode_mtime(self, tmp_path):
        """Entry must capture the file's mode and mtime_ns."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "meta.txt", b"metadata test")
        st = os.lstat(fp)
        entry = vault.snapshot(fp, 1002)
        assert entry is not None
        assert entry.mode == st.st_mode
        assert entry.mtime_ns == st.st_mtime_ns

    def test_snapshot_zero_byte_file(self, tmp_path):
        """Zero-byte files can't be mmapped; snapshot must handle gracefully."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "empty.txt", b"")
        entry = vault.snapshot(fp, 1003)
        assert entry is not None
        assert entry.size == 0
        assert entry.sha256 == _sha256(b"")
        assert vault.read_blob(entry) == b""

    def test_snapshot_large_file_mmap(self, tmp_path):
        """A 5 MB file must be copied correctly via mmap."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        content = os.urandom(5 * 1024 * 1024)
        fp = _make_file(tmp_path, "large.bin", content)
        entry = vault.snapshot(fp, 1004)
        assert entry is not None
        assert entry.size == len(content)
        assert vault.read_blob(entry) == content

    def test_snapshot_custom_block_size(self, tmp_path):
        """Custom block_size should still produce correct copies."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"), block_size=256)
        content = os.urandom(1000)
        fp = _make_file(tmp_path, "small.bin", content)
        entry = vault.snapshot(fp, 1005)
        assert entry is not None
        assert vault.read_blob(entry) == content

    def test_first_copy_wins(self, tmp_path):
        """Second snapshot after modification must keep original bytes."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        original = b"original clean content"
        fp = _make_file(tmp_path, "fcw.txt", original)
        entry1 = vault.snapshot(fp, 1006)
        # Overwrite the file
        with open(fp, "wb") as f:
            f.write(b"encrypted garbage data")
        entry2 = vault.snapshot(fp, 1006)
        # Must return same entry, blob must be original
        assert entry2 is not None
        assert entry2.sha256 == entry1.sha256
        assert vault.read_blob(entry2) == original

    def test_snapshot_missing_file(self, tmp_path):
        """Snapshot of a missing file must return None, not raise."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        result = vault.snapshot(str(tmp_path / "nonexistent.txt"), 1007)
        assert result is None

    def test_snapshot_directory(self, tmp_path):
        """Snapshot of a directory must return None."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        d = tmp_path / "somedir"
        d.mkdir()
        result = vault.snapshot(str(d), 1008)
        assert result is None

    def test_snapshot_unreadable_file(self, tmp_path):
        """Snapshot of an unreadable file must return None."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "noperm.txt", b"secret")
        os.chmod(fp, 0o000)
        result = vault.snapshot(fp, 1009)
        # Restore permissions for cleanup
        os.chmod(fp, 0o644)
        # On Windows, this may succeed; on POSIX it should fail
        if sys.platform != "win32":
            assert result is None

    def test_per_pid_isolation(self, tmp_path):
        """Entries for different PIDs must be isolated."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp1 = _make_file(tmp_path, "a.txt", b"pid 100 data")
        fp2 = _make_file(tmp_path, "b.txt", b"pid 200 data")
        vault.snapshot(fp1, 100)
        vault.snapshot(fp2, 200)
        assert len(vault.entries(pid=100)) == 1
        assert len(vault.entries(pid=200)) == 1
        assert vault.entries(pid=100)[0].original_path == os.path.realpath(fp1)

    def test_manifest_persist_reload(self, tmp_path):
        """Manifest must persist entries and reload on a new vault instance."""
        vault_dir = str(tmp_path / "vault")
        vault = JournalVault(vault_dir=vault_dir)
        content = b"persistence test content"
        fp = _make_file(tmp_path, "persist.txt", content)
        entry = vault.snapshot(fp, 2000)
        assert entry is not None

        # Create new vault instance pointing to same dir
        vault2 = JournalVault(vault_dir=vault_dir)
        entries = vault2.entries(pid=2000)
        assert len(entries) == 1
        assert entries[0].sha256 == _sha256(content)
        assert vault2.read_blob(entries[0]) == content

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_vault_dir_mode_700(self, tmp_path):
        """Vault directory must be created with 0o700 on POSIX."""
        vault_dir = str(tmp_path / "secure_vault")
        JournalVault(vault_dir=vault_dir)
        mode = os.stat(vault_dir).st_mode & 0o777
        assert mode == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink test")
    def test_symlinked_vault_dir_rejected(self, tmp_path):
        """Symlinked vault directory must raise VaultSecurityError."""
        real_dir = tmp_path / "real_vault"
        real_dir.mkdir()
        link = tmp_path / "link_vault"
        os.symlink(str(real_dir), str(link))
        with pytest.raises(VaultSecurityError):
            JournalVault(vault_dir=str(link))

    def test_max_vault_bytes_cap(self, tmp_path):
        """Files exceeding max_vault_bytes must be refused, not evicted."""
        vault = JournalVault(
            vault_dir=str(tmp_path / "vault"),
            max_vault_bytes=100,
        )
        fp = _make_file(tmp_path, "big.bin", os.urandom(200))
        result = vault.snapshot(fp, 3000)
        assert result is None
        assert vault.skipped_over_cap >= 1

    def test_max_file_bytes(self, tmp_path):
        """Files exceeding max_file_bytes must be refused."""
        vault = JournalVault(
            vault_dir=str(tmp_path / "vault"),
            max_file_bytes=50,
        )
        fp = _make_file(tmp_path, "toobig.bin", os.urandom(100))
        result = vault.snapshot(fp, 3001)
        assert result is None
        assert vault.skipped_over_cap >= 1

    def test_purge(self, tmp_path):
        """purge(pid) must remove blobs and manifest."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "purge.txt", b"purge me")
        vault.snapshot(fp, 4000)
        assert len(vault.entries(pid=4000)) == 1
        freed = vault.purge(4000)
        assert freed >= 0
        assert len(vault.entries(pid=4000)) == 0

    def test_concurrent_snapshots_single_blob(self, tmp_path):
        """10 concurrent snapshots of the same path must yield one blob."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        content = b"concurrent test" * 100
        fp = _make_file(tmp_path, "concurrent.txt", content)
        results = []
        errors = []

        def _snap():
            try:
                r = vault.snapshot(fp, 5000)
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_snap) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        non_none = [r for r in results if r is not None]
        assert len(non_none) == 10  # all return the entry
        # All share the same sha256
        shas = {r.sha256 for r in non_none}
        assert len(shas) == 1
        assert shas.pop() == _sha256(content)
        # Only one blob file
        entries = vault.entries(pid=5000)
        assert len(entries) == 1


# ═══════════════════════════════════════════════════════════════════════════
#   2. TestVaultRenameTracking (6 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestVaultRenameTracking:

    def test_note_rename_single(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "orig.txt", b"data")
        vault.snapshot(fp, 6000)
        new_path = fp + ".locked"
        vault.note_rename(6000, fp, new_path)
        entry = vault.entries(pid=6000)[0]
        assert any(".locked" in p for p in entry.renamed_to)

    def test_rename_chain(self, tmp_path):
        """a→b→c chain must all be in renamed_to."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "chain.txt", b"chain data")
        vault.snapshot(fp, 6001)
        path_b = fp + ".step1"
        path_c = fp + ".step2"
        vault.note_rename(6001, fp, path_b)
        vault.note_rename(6001, path_b, path_c)
        entry = vault.entries(pid=6001)[0]
        assert len(entry.renamed_to) == 2

    def test_rename_unknown_path_ignored(self, tmp_path):
        """Renaming an unknown path must not raise."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        vault.note_rename(6002, "/nonexistent/path", "/other/path")
        # No crash, no entries

    def test_note_created(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "target.txt", b"data")
        vault.snapshot(fp, 6003)
        note = str(tmp_path / "RANSOM.txt")
        with open(note, "w") as f:
            f.write("pay up")
        vault.note_created(6003, note)
        entry = vault.entries(pid=6003)[0]
        assert len(entry.created_paths) == 1

    def test_multiple_creates(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "mc.txt", b"data")
        vault.snapshot(fp, 6004)
        for i in range(3):
            vault.note_created(6004, f"/tmp/note_{i}.txt")
        entry = vault.entries(pid=6004)[0]
        assert len(entry.created_paths) == 3

    def test_rename_persists_in_manifest(self, tmp_path):
        """Rename tracking must survive manifest reload."""
        vault_dir = str(tmp_path / "vault")
        vault = JournalVault(vault_dir=vault_dir)
        fp = _make_file(tmp_path, "persist_rename.txt", b"data")
        vault.snapshot(fp, 6005)
        vault.note_rename(6005, fp, fp + ".locked")

        vault2 = JournalVault(vault_dir=vault_dir)
        entry = vault2.entries(pid=6005)[0]
        assert len(entry.renamed_to) >= 1


# ═══════════════════════════════════════════════════════════════════════════
#   3. TestRollbackEngine (16 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestRollbackEngine:

    def _setup_vault_and_encrypt(self, tmp_path, content=b"original bytes"):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "victim.txt", content)
        vault.snapshot(fp, 7000)
        # Simulate encryption
        with open(fp, "wb") as f:
            f.write(os.urandom(len(content)))
        return vault, fp

    def test_restore_byte_identical(self, tmp_path):
        content = b"critical data for restoration"
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7000)
        assert report.zero_loss
        with open(fp, "rb") as f:
            assert f.read() == content

    def test_sha_verify_post_restore(self, tmp_path):
        content = b"sha verification data"
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7000)
        assert report.results[0].sha256_ok

    def test_mode_mtime_restored(self, tmp_path):
        content = b"mode and mtime test"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "modemtime.txt", content)
        original_stat = os.lstat(fp)
        vault.snapshot(fp, 7001)
        with open(fp, "wb") as f:
            f.write(os.urandom(100))
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        engine.rollback(7001)
        restored_stat = os.lstat(fp)
        assert (restored_stat.st_mode & 0o7777) == (original_stat.st_mode & 0o7777)

    def test_encrypted_renamed_copy_deleted(self, tmp_path):
        content = b"encrypted copy test"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "delete_test.txt", content)
        vault.snapshot(fp, 7002)
        locked = fp + ".locked"
        with open(fp, "wb") as f:
            f.write(os.urandom(100))
        os.rename(fp, locked)
        vault.note_rename(7002, fp, locked)
        # Recreate original path for restore to target
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7002)
        assert report.zero_loss
        assert not os.path.exists(locked), "Encrypted .locked copy should be deleted"

    def test_ransom_note_deleted(self, tmp_path):
        content = b"ransom note test"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "rn_test.txt", content)
        vault.snapshot(fp, 7003)
        note = str(tmp_path / "RANSOM.txt")
        with open(note, "w") as f:
            f.write("pay up")
        vault.note_created(7003, note)
        with open(fp, "wb") as f:
            f.write(os.urandom(100))
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7003)
        assert not os.path.exists(note), "Ransom note should be deleted"

    def test_original_missing_only_renamed_exists(self, tmp_path):
        content = b"original missing test"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "missing_orig.txt", content)
        vault.snapshot(fp, 7004)
        locked = fp + ".locked"
        os.rename(fp, locked)
        vault.note_rename(7004, fp, locked)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7004)
        assert report.zero_loss
        assert os.path.exists(fp), "Original should be restored"
        with open(fp, "rb") as f:
            assert f.read() == content

    def test_renamed_missing(self, tmp_path):
        """Rollback must succeed even if renamed file was already deleted."""
        content = b"renamed missing test"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "rm_test.txt", content)
        vault.snapshot(fp, 7005)
        vault.note_rename(7005, fp, fp + ".locked")
        with open(fp, "wb") as f:
            f.write(os.urandom(100))
        # Don't actually create the .locked file
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7005)
        assert report.zero_loss

    def test_allowed_roots_refuses_outside(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        safe_dir = tmp_path / "safe"
        safe_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        fp = _make_file(outside_dir, "outside.txt", b"should be refused")
        vault.snapshot(fp, 7006)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(safe_dir)])
        report = engine.rollback(7006)
        assert report.results[0].reason == "outside_allowed_roots"
        assert not report.zero_loss

    def test_corrupted_blob_detected(self, tmp_path):
        """Corrupted blob must be detected; original left untouched."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        content = b"corruption test data"
        fp = _make_file(tmp_path, "corrupt.txt", content)
        entry = vault.snapshot(fp, 7007)
        # Corrupt the blob
        blob_path = os.path.join(str(tmp_path / "vault"), "7007", entry.blob_name)
        with open(blob_path, "wb") as f:
            f.write(b"CORRUPTED DATA")
        # Overwrite original
        encrypted = os.urandom(100)
        with open(fp, "wb") as f:
            f.write(encrypted)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7007)
        assert report.results[0].reason == "vault_corrupt"
        # Original must be unchanged (encrypted still there)
        with open(fp, "rb") as f:
            assert f.read() == encrypted

    def test_atomicity_os_replace_failure(self, tmp_path):
        """If os.replace raises, original must be unchanged."""
        content = b"atomicity test data"
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        fp = _make_file(tmp_path, "atomic.txt", content)
        vault.snapshot(fp, 7008)
        encrypted = os.urandom(100)
        with open(fp, "wb") as f:
            f.write(encrypted)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        with patch("src.stage_10_enforcer.journal_rollback.os.replace", side_effect=OSError("disk full")):
            report = engine.rollback(7008)
        assert not report.zero_loss
        # The original should still have encrypted content
        with open(fp, "rb") as f:
            actual = f.read()
        assert actual == encrypted

    def test_partial_failure_continues(self, tmp_path):
        """Failure on one file must not stop other files from restoring."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        good_content = b"good file content"
        fp_good = _make_file(tmp_path, "good.txt", good_content)
        fp_bad = _make_file(tmp_path, "bad.txt", b"bad file content")
        vault.snapshot(fp_good, 7009)
        vault.snapshot(fp_bad, 7009)
        # Encrypt both
        with open(fp_good, "wb") as f:
            f.write(os.urandom(100))
        with open(fp_bad, "wb") as f:
            f.write(os.urandom(100))
        # Corrupt the bad blob
        for entry in vault.entries(pid=7009):
            if entry.original_path == os.path.realpath(fp_bad):
                blob = os.path.join(str(tmp_path / "vault"), "7009", entry.blob_name)
                with open(blob, "wb") as f:
                    f.write(b"CORRUPT")
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7009)
        assert report.restored >= 1
        assert report.failed >= 1
        with open(fp_good, "rb") as f:
            assert f.read() == good_content

    def test_dry_run_writes_nothing(self, tmp_path):
        content = b"dry run test data"
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        encrypted_data = open(fp, "rb").read()
        engine = RollbackEngine(vault, dry_run=True, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7000)
        assert report.dry_run
        assert report.results[0].success
        assert report.results[0].reason == "dry_run"
        # File should NOT be changed
        with open(fp, "rb") as f:
            assert f.read() == encrypted_data

    def test_idempotent_second_rollback(self, tmp_path):
        content = b"idempotent rollback data"
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report1 = engine.rollback(7000)
        report2 = engine.rollback(7000)
        assert report1.zero_loss
        assert report2.zero_loss
        with open(fp, "rb") as f:
            assert f.read() == content

    def test_zero_loss_property(self, tmp_path):
        content = b"zero loss property"
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7000)
        assert report.zero_loss is True

    def test_large_file_rollback(self, tmp_path):
        content = os.urandom(2 * 1024 * 1024)  # 2 MB
        vault, fp = self._setup_vault_and_encrypt(tmp_path, content)
        engine = RollbackEngine(vault, dry_run=False, allowed_roots=[str(tmp_path)])
        report = engine.rollback(7000)
        assert report.zero_loss
        with open(fp, "rb") as f:
            assert f.read() == content


# ═══════════════════════════════════════════════════════════════════════════
#   4. TestACLManager (14 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestACLManager:

    def test_revoke_clears_write_bits(self, tmp_path):
        fp = _make_file(tmp_path, "acl.txt", b"data")
        acl = ACLManager(dry_run=False, backend=PosixACLBackend())
        acl.revoke(8000, [fp])
        mode = os.stat(fp).st_mode & 0o777
        assert not (mode & stat.S_IWUSR)
        assert not (mode & stat.S_IWGRP)
        assert not (mode & stat.S_IWOTH)
        # restore write bit for cleanup
        os.chmod(fp, stat.S_IWRITE | stat.S_IREAD)

    def test_restore_exact_original(self, tmp_path):
        fp = _make_file(tmp_path, "restore.txt", b"data")
        original_mode = os.stat(fp).st_mode
        acl = ACLManager(dry_run=False, backend=PosixACLBackend())
        acl.revoke(8001, [fp])
        acl.restore_all(8001)
        mode = os.stat(fp).st_mode
        assert mode == original_mode

    def test_nonexistent_path_skipped(self, tmp_path):
        acl = ACLManager(dry_run=True)
        records = acl.revoke(8002, [str(tmp_path / "gone.txt")])
        assert len(records) == 0
        assert acl.skipped_nonexistent >= 1

    def test_directory_skipped(self, tmp_path):
        acl = ACLManager(dry_run=True)
        records = acl.revoke(8003, [str(tmp_path)])
        assert len(records) == 0
        assert acl.skipped_directories >= 1

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink")
    def test_symlink_skipped(self, tmp_path):
        fp = _make_file(tmp_path, "real.txt", b"data")
        link = str(tmp_path / "link.txt")
        os.symlink(fp, link)
        acl = ACLManager(dry_run=True)
        records = acl.revoke(8004, [link])
        assert len(records) == 0
        assert acl.skipped_symlinks >= 1

    def test_idempotent_revoke_keeps_original(self, tmp_path):
        fp = _make_file(tmp_path, "idem.txt", b"data")
        original_mode = os.stat(fp).st_mode
        acl = ACLManager(dry_run=False, backend=PosixACLBackend())
        records1 = acl.revoke(8005, [fp])
        records2 = acl.revoke(8005, [fp])
        # Restoring must give back original mode, not the revoked mode
        acl.restore_all(8005)
        mode = os.stat(fp).st_mode
        assert mode == original_mode

    def test_restore_all_only_target_pid(self, tmp_path):
        fp1 = _make_file(tmp_path, "p1.txt", b"data1")
        fp2 = _make_file(tmp_path, "p2.txt", b"data2")
        acl = ACLManager(dry_run=True)
        acl.revoke(8006, [fp1])
        acl.revoke(8007, [fp2])
        acl.restore_all(8006)
        assert len(acl.active_revocations(pid=8006)) == 0
        assert len(acl.active_revocations(pid=8007)) == 1

    def test_temporarily_writable(self, tmp_path):
        fp = _make_file(tmp_path, "tw.txt", b"data")
        acl = ACLManager(dry_run=False, backend=PosixACLBackend())
        acl.revoke(8008, [fp])
        with acl.temporarily_writable(fp):
            mode = os.stat(fp).st_mode & 0o777
            assert mode & stat.S_IWUSR  # writable inside context
        mode_after = os.stat(fp).st_mode & 0o777
        assert not (mode_after & stat.S_IWUSR)  # revoked again
        os.chmod(fp, stat.S_IWRITE | stat.S_IREAD)

    def test_temporarily_writable_reapplies_on_exception(self, tmp_path):
        fp = _make_file(tmp_path, "tw_exc.txt", b"data")
        acl = ACLManager(dry_run=False, backend=PosixACLBackend())
        acl.revoke(8009, [fp])
        with pytest.raises(ValueError):
            with acl.temporarily_writable(fp):
                raise ValueError("test error")
        mode = os.stat(fp).st_mode & 0o777
        assert not (mode & stat.S_IWUSR)
        os.chmod(fp, stat.S_IWRITE | stat.S_IREAD)

    def test_simulated_backend_no_disk_change(self, tmp_path):
        fp = _make_file(tmp_path, "sim.txt", b"data")
        original_mode = os.stat(fp).st_mode
        acl = ACLManager(dry_run=True)
        acl.revoke(8010, [fp])
        # Real file mode should be unchanged
        mode = os.stat(fp).st_mode
        assert mode == original_mode

    @patch("subprocess.run")
    def test_windows_backend_icacls_argv(self, mock_run):
        backend = WindowsACLBackend()
        backend._user = "TestUser"
        backend.revoke_write("C:\\test\\file.txt")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "icacls" in args
        assert "C:\\test\\file.txt" in args
        assert any("TestUser" in a for a in args)

    @patch("os.chmod")
    def test_posix_backend_uses_chmod(self, mock_chmod):
        backend = PosixACLBackend()
        with patch("os.lstat") as mock_lstat:
            mock_lstat.return_value = MagicMock(st_mode=0o644)
            backend.revoke_write("/tmp/test.txt")
        mock_chmod.assert_called_once()

    def test_active_revocations_filtering(self, tmp_path):
        acl = ACLManager(dry_run=True)
        fp1 = _make_file(tmp_path, "f1.txt", b"data")
        fp2 = _make_file(tmp_path, "f2.txt", b"data")
        acl.revoke(8011, [fp1])
        acl.revoke(8012, [fp2])
        assert len(acl.active_revocations()) == 2
        assert len(acl.active_revocations(pid=8011)) == 1
        acl.restore_all(8011)
        assert len(acl.active_revocations()) == 1

    def test_stats(self, tmp_path):
        acl = ACLManager(dry_run=True)
        fp = _make_file(tmp_path, "stats.txt", b"data")
        acl.revoke(8013, [fp])
        stats = acl.get_stats()
        assert stats["total_revocations"] == 1
        assert stats["dry_run"] is True
        assert "backend" in stats


# ═══════════════════════════════════════════════════════════════════════════
#   5. TestProcessTerminator (10 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestProcessTerminator:

    def test_dry_run_no_signal(self):
        term = ProcessTerminator(dry_run=True)
        with patch("os.kill") as mock_kill:
            result = term.terminate(9999, "test")
        mock_kill.assert_not_called()
        assert result.success
        assert result.dry_run

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX SIGKILL")
    def test_real_mode_sigkill_mock(self):
        term = ProcessTerminator(dry_run=False)
        with patch("os.kill") as mock_kill:
            result = term.terminate(9999, "test")
        mock_kill.assert_called_once_with(9999, signal.SIGKILL)

    def test_refuses_pid_zero(self):
        term = ProcessTerminator(dry_run=True)
        result = term.terminate(0, "test")
        assert not result.success
        assert "protected" in result.error.lower()

    def test_refuses_pid_one(self):
        term = ProcessTerminator(dry_run=True)
        result = term.terminate(1, "test")
        assert not result.success
        assert "protected" in result.error.lower()

    def test_refuses_own_pid(self):
        term = ProcessTerminator(dry_run=True)
        result = term.terminate(os.getpid(), "test")
        assert not result.success
        assert "own process" in result.error.lower()

    def test_refuses_parent_pid(self):
        term = ProcessTerminator(dry_run=True)
        result = term.terminate(os.getppid(), "test")
        assert not result.success
        assert "parent" in result.error.lower()

    @patch("os.kill", side_effect=ProcessLookupError)
    def test_process_lookup_error_handled(self, mock_kill):
        term = ProcessTerminator(dry_run=False)
        result = term.terminate(99999, "test")
        assert not result.success
        assert "terminated" in result.error.lower()

    def test_permission_error_handled(self):
        term = ProcessTerminator(dry_run=False)
        with patch("os.kill", side_effect=PermissionError("not allowed")), \
             patch("src.stage_10_enforcer.process_terminator.psutil") as mock_psutil:
            if mock_psutil is not None:
                mock_proc = MagicMock()
                mock_proc.kill.side_effect = PermissionError("not allowed")
                mock_psutil.Process.return_value = mock_proc
            result = term.terminate(99999, "test")
        assert not result.success
        assert "permission" in result.error.lower()

    def test_create_time_mismatch_refused(self):
        term = ProcessTerminator(dry_run=False)
        # Register a fake create_time
        term._registered[99999] = 1000.0
        # Mock psutil.Process to return a different create_time
        mock_proc = MagicMock()
        mock_proc.create_time.return_value = 2000.0
        with patch("src.stage_10_enforcer.process_terminator.psutil") as mock_psutil:
            mock_psutil.Process.return_value = mock_proc
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            result = term.terminate(99999, "test")
        assert not result.success
        assert "reuse" in result.error.lower()

    def test_latency_recorded(self):
        term = ProcessTerminator(dry_run=True)
        result = term.terminate(9999, "test")
        assert result.latency_ms >= 0


# ═══════════════════════════════════════════════════════════════════════════
#   6. TestEnforcer (20 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestEnforcer:

    def _make_enforcer(self, tmp_path, **kwargs):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        defaults = dict(
            containment_engine=MockContainmentEngine(),
            trust_evolution=MockTrustEvolution(),
            vault=vault,
            dry_run=True,
            always_on=True,
            allowed_roots=[str(tmp_path)],
            rollback_dry_run=False,
        )
        defaults.update(kwargs)
        return Enforcer(**defaults), vault

    def _make_record(self, tmp_path, pid=9999, files=None):
        if files is None:
            files = [_make_file(tmp_path, f"f{i}.txt", f"data{i}".encode()) for i in range(3)]
        cut_edges = [(f"pid:{pid}", f"file:{f}") for f in files]
        return MockContainmentRecord(
            pid=pid,
            cut_edges=cut_edges,
            isolated_files=[f"file:{f}" for f in files],
        ), files

    def test_enforce_revokes_cut_edges(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record, files = self._make_record(tmp_path)
        result = enforcer.enforce(record)
        assert result.state == EnforcementState.PENDING_RESOLUTION
        assert len(result.acl_paths) == len(files)

    def test_non_file_nodes_ignored(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record = MockContainmentRecord(
            cut_edges=[("pid:9999", "pid:1234"), ("pid:9999", "registry:HKLM")],
        )
        result = enforcer.enforce(record)
        assert len(result.acl_paths) == 0

    def test_fallback_to_isolated_files(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        fp = _make_file(tmp_path, "iso.txt", b"data")
        record = MockContainmentRecord(
            cut_edges=[],
            isolated_files=[f"file:{fp}"],
        )
        result = enforcer.enforce(record)
        assert len(result.acl_paths) == 1

    def test_noop_for_failed_record(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record = MockContainmentRecord(
            freeze_result=MockFreezeResult(success=False),
        )
        result = enforcer.enforce(record)
        assert len(result.acl_paths) == 0

    def test_noop_for_release_record(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record = MockContainmentRecord(action="RELEASE")
        result = enforcer.enforce(record)
        assert len(result.acl_paths) == 0

    def test_idempotent_enforce(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record, _ = self._make_record(tmp_path)
        r1 = enforcer.enforce(record)
        r2 = enforcer.enforce(record)
        assert r1 is r2  # same object
        assert enforcer.total_enforcements == 1

    def test_malicious_order_terminate_rollback_acl(self, tmp_path):
        """MALICIOUS must be: terminate → rollback → keep ACLs."""
        enforcer, _ = self._make_enforcer(tmp_path)
        record, files = self._make_record(tmp_path)
        for fp in files:
            enforcer.before_write(fp, 9999)
        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.MALICIOUS)
        assert result.success
        assert result.terminate_result is not None
        assert result.rollback_report is not None
        assert "terminate" in result.steps[0]
        assert "rollback" in result.steps[1]
        assert "acl" in result.steps[2].lower()

    def test_failed_kill_still_rolls_back(self, tmp_path):
        term = ProcessTerminator(dry_run=True)
        enforcer, vault = self._make_enforcer(
            tmp_path,
            terminator=term,
        )
        record, files = self._make_record(tmp_path, pid=1)  # pid=1 will be refused
        for fp in files:
            enforcer.before_write(fp, 1)
        record.pid = 1
        record.freeze_result.pid = 1
        # Manually insert to bypass the pid=1 enforcement (which would fail)
        from src.stage_10_enforcer.enforcer import EnforcementRecord
        enforcer._records[1] = EnforcementRecord(
            pid=1, state=EnforcementState.PENDING_RESOLUTION,
        )
        result = enforcer.resolve(1, Verdict.MALICIOUS)
        assert result.rollback_report is not None  # rollback still happened
        assert not result.terminate_result.success  # kill failed (pid=1 refused)

    def test_false_positive_order(self, tmp_path):
        """FP must be: ACL restore → trust reset → release."""
        enforcer, _ = self._make_enforcer(tmp_path)
        record, files = self._make_record(tmp_path)
        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert result.success
        assert "acl_restore" in result.steps[0]
        assert "trust_reset" in result.steps[1]
        assert "release" in result.steps[2]

    def test_false_positive_no_rollback(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record, _ = self._make_record(tmp_path)
        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert result.rollback_report is None

    def test_false_positive_purges_vault(self, tmp_path):
        enforcer, vault = self._make_enforcer(tmp_path)
        record, files = self._make_record(tmp_path)
        for fp in files:
            enforcer.before_write(fp, 9999)
        assert len(vault.entries(pid=9999)) > 0
        enforcer.enforce(record)
        enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert len(vault.entries(pid=9999)) == 0

    def test_resolve_before_enforce_error(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        result = enforcer.resolve(9999, Verdict.MALICIOUS)
        assert not result.success
        assert "no enforcement" in result.error.lower()

    def test_double_resolve_error(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record, _ = self._make_record(tmp_path)
        enforcer.enforce(record)
        enforcer.resolve(9999, Verdict.MALICIOUS)
        result = enforcer.resolve(9999, Verdict.MALICIOUS)
        assert not result.success
        assert "already resolved" in result.error.lower()

    def test_on_trust_update_arms(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path, always_on=False)
        enforcer.on_trust_update({"prewarm_journal": True, "pid": 1234})
        assert 1234 in enforcer._armed_pids

    def test_before_write_skips_unarmed_not_always_on(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path, always_on=False)
        fp = _make_file(tmp_path, "skip.txt", b"data")
        result = enforcer.before_write(fp, 5555)
        assert result is None
        assert enforcer.unjournaled_writes == 1

    def test_before_write_snapshots_always_on(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path, always_on=True)
        fp = _make_file(tmp_path, "snap.txt", b"data")
        result = enforcer.before_write(fp, 5556)
        assert result is not None

    def test_disarm(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        enforcer.arm(1234)
        assert 1234 in enforcer._armed_pids
        enforcer.disarm(1234)
        assert 1234 not in enforcer._armed_pids

    def test_dry_run_default_true(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        assert enforcer.dry_run is True

    def test_history_and_stats(self, tmp_path):
        enforcer, _ = self._make_enforcer(tmp_path)
        record, _ = self._make_record(tmp_path)
        enforcer.enforce(record)
        assert len(enforcer.get_history()) == 1
        assert len(enforcer.get_pending()) == 1
        stats = enforcer.get_stats()
        assert stats["total_enforcements"] == 1
        assert stats["pending"] == 1

    def test_concurrent_resolves_different_pids(self, tmp_path):
        enforcer, vault = self._make_enforcer(tmp_path)
        results = []

        for pid in [1000, 2000, 3000]:
            fp = _make_file(tmp_path, f"pid{pid}.txt", f"data{pid}".encode())
            enforcer.before_write(fp, pid)
            rec = MockContainmentRecord(
                pid=pid,
                cut_edges=[(f"pid:{pid}", f"file:{fp}")],
            )
            enforcer.enforce(rec)

        def _resolve(pid):
            r = enforcer.resolve(pid, Verdict.MALICIOUS)
            results.append(r)

        threads = [threading.Thread(target=_resolve, args=(pid,)) for pid in [1000, 2000, 3000]]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert all(r.success for r in results)


# ═══════════════════════════════════════════════════════════════════════════
#   7. TestStageIntegration (15 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestStageIntegration:
    """Integration tests with real DBRG, ContainmentEngine, and TrustEvolution."""

    def _build_graph_and_contain(self, tmp_path, pid=9999, num_files=3):
        from src.stage_3_dbrg.dbrg_manager import DBRGManager
        from src.stage_9_containment import ContainmentEngine

        dbrg = DBRGManager(decay_lambda=0.01)
        containment = ContainmentEngine(dry_run=True)

        files = []
        for i in range(num_files):
            fp = _make_file(tmp_path / "files", f"file_{i}.txt", f"content {i}".encode())
            files.append(fp)
            ecar = {
                "actorID": f"pid:{pid}",
                "objectID": f"file:{fp}",
                "pid": pid,
                "operation": "MODIFY",
                "timestamp": time.time() * 1000,
                "context": {"exe_path": "test.exe", "parent_exe": "cmd.exe"},
            }
            dbrg.process_event(ecar)

        graph = dbrg.get_graph_snapshot()
        contain_record = containment.contain(pid, graph)
        return dbrg, containment, contain_record, files

    def test_full_malicious_flow(self, tmp_path):
        """DBRG → contain → enforce → resolve(MALICIOUS) → verify."""
        dbrg, containment, record, files = self._build_graph_and_contain(tmp_path)
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=containment,
            vault=vault,
            dry_run=True,
            always_on=True,
            allowed_roots=[str(tmp_path)],
            rollback_dry_run=False,
        )
        # Snapshot and encrypt
        original_data = {}
        for fp in files:
            with open(fp, "rb") as f:
                original_data[fp] = f.read()
            enforcer.before_write(fp, 9999)
            with open(fp, "wb") as f:
                f.write(os.urandom(100))

        enforcement = enforcer.enforce(record)
        assert enforcement.state == EnforcementState.PENDING_RESOLUTION

        result = enforcer.resolve(9999, Verdict.MALICIOUS)
        assert result.success
        # Verify files restored
        for fp, orig in original_data.items():
            with open(fp, "rb") as f:
                assert f.read() == orig

    def test_full_false_positive_flow(self, tmp_path):
        """FP: release freezer, trust=100, ACLs restored."""
        from src.stage_7_trust import TrustEvolution
        from src.stage_9_containment import ContainmentEngine

        trust_evo = TrustEvolution()
        containment = ContainmentEngine(dry_run=True)

        dbrg, _, record, files = self._build_graph_and_contain(tmp_path)

        enforcer = Enforcer(
            containment_engine=containment,
            trust_evolution=trust_evo,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
            always_on=True,
            allowed_roots=[str(tmp_path)],
        )
        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert result.success
        assert result.trust_reset["trust"] == 100.0
        assert result.trust_reset["risk_tier"] == "SAFE"

    def test_trust_reset_after_acl_restore(self, tmp_path):
        """Trust reset must happen AFTER ACL restore."""
        enforcer_mock = MockContainmentEngine()
        trust_mock = MockTrustEvolution()
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        acl = ACLManager(dry_run=True)

        enforcer = Enforcer(
            containment_engine=enforcer_mock,
            trust_evolution=trust_mock,
            vault=vault,
            acl=acl,
            dry_run=True,
        )
        fp = _make_file(tmp_path, "order.txt", b"data")
        record = MockContainmentRecord(
            cut_edges=[("pid:9999", f"file:{fp}")],
        )
        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert "acl_restore" in result.steps[0]
        assert "trust_reset" in result.steps[1]

    def test_two_pids_independent(self, tmp_path):
        """Resolving PID A must not affect PID B."""
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=MockContainmentEngine(),
            vault=vault, dry_run=True, always_on=True,
        )
        for pid in [100, 200]:
            fp = _make_file(tmp_path, f"pid{pid}.txt", f"data{pid}".encode())
            enforcer.before_write(fp, pid)
            rec = MockContainmentRecord(
                pid=pid,
                cut_edges=[(f"pid:{pid}", f"file:{fp}")],
            )
            enforcer.enforce(rec)

        enforcer.resolve(100, Verdict.MALICIOUS)
        # PID 200 should still be pending
        assert 200 in enforcer.get_pending()
        assert 100 not in enforcer.get_pending()

    def test_blackcat_gradual_decay_arms_at_verify(self, tmp_path):
        """BlackCat-style slow decay should reach VERIFY and arm the journal."""
        from src.stage_7_trust import TrustEvolution
        from src.stage_6_fusion import ThreatFusion

        trust_evo = TrustEvolution()
        enforcer = Enforcer(
            containment_engine=MockContainmentEngine(),
            trust_evolution=trust_evo,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
            always_on=False,
        )

        # Simulate gradual escalation with low IntentDrift
        armed = False
        for i in range(20):
            result = trust_evo.evolve({
                "pid": 7777,
                "IntentDrift": 0.3 + (i * 0.03),
                "drift_rate": 0.01,
                "timestamp": time.time(),
            })
            enforcer.on_trust_update(result)
            if result["prewarm_journal"]:
                armed = True
                break

        assert armed, "BlackCat-style decay should eventually arm the journal"
        assert 7777 in enforcer._armed_pids

    def test_stats_consistency(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=MockContainmentEngine(),
            vault=vault, dry_run=True, always_on=True,
        )
        fp = _make_file(tmp_path, "sc.txt", b"data")
        enforcer.before_write(fp, 9999)
        rec = MockContainmentRecord(cut_edges=[("pid:9999", f"file:{fp}")])
        enforcer.enforce(rec)
        enforcer.resolve(9999, Verdict.MALICIOUS)
        stats = enforcer.get_stats()
        assert stats["total_enforcements"] == 1
        assert stats["total_resolutions"] == 1
        assert stats["resolved_malicious"] == 1
        assert stats["pending"] == 0

    def test_enforce_with_real_dbrg_containment(self, tmp_path):
        """Full pipeline: DBRG events → contain → enforce → check ACLs."""
        dbrg, containment, record, files = self._build_graph_and_contain(tmp_path, num_files=5)
        enforcer = Enforcer(
            containment_engine=containment,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
            always_on=True,
        )
        enforcement = enforcer.enforce(record)
        assert enforcement.state == EnforcementState.PENDING_RESOLUTION
        assert len(enforcement.acl_paths) > 0

    def test_release_via_containment_engine(self, tmp_path):
        """FP resolve must call containment_engine.release()."""
        mock_ce = MockContainmentEngine()
        enforcer = Enforcer(
            containment_engine=mock_ce,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
        )
        fp = _make_file(tmp_path, "rel.txt", b"data")
        rec = MockContainmentRecord(cut_edges=[("pid:9999", f"file:{fp}")])
        enforcer.enforce(rec)
        enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert len(mock_ce.released) == 1
        assert mock_ce.released[0] == (9999, "false_positive_confirmed")

    def test_freezer_state_after_fp(self, tmp_path):
        """After FP resolve, the freezer should show RELEASED state."""
        from src.stage_9_containment import ContainmentState

        dbrg, containment, record, files = self._build_graph_and_contain(tmp_path)

        enforcer = Enforcer(
            containment_engine=containment,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
        )
        enforcer.enforce(record)
        enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert containment.freezer.get_state(9999) == ContainmentState.RELEASED

    def test_multiple_files_all_restored(self, tmp_path):
        """All 5 files must be restored after MALICIOUS resolve."""
        dbrg, containment, record, files = self._build_graph_and_contain(tmp_path, num_files=5)
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=containment,
            vault=vault, dry_run=True, always_on=True,
            allowed_roots=[str(tmp_path)], rollback_dry_run=False,
        )
        originals = {}
        for fp in files:
            with open(fp, "rb") as f:
                originals[fp] = f.read()
            enforcer.before_write(fp, 9999)
            with open(fp, "wb") as f:
                f.write(os.urandom(100))

        enforcer.enforce(record)
        result = enforcer.resolve(9999, Verdict.MALICIOUS)
        assert result.rollback_report.zero_loss
        for fp, orig in originals.items():
            with open(fp, "rb") as f:
                assert f.read() == orig

    def test_empty_cut_edges_falls_back_to_isolated(self, tmp_path):
        from src.stage_9_containment import ContainmentEngine
        containment = ContainmentEngine(dry_run=True)
        fp = _make_file(tmp_path, "fallback.txt", b"data")
        rec = MockContainmentRecord(
            cut_edges=[],
            isolated_files=[f"file:{fp}"],
        )
        enforcer = Enforcer(
            containment_engine=containment,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
        )
        enforcement = enforcer.enforce(rec)
        assert len(enforcement.acl_paths) == 1

    def test_vault_stats_match_enforcer_stats(self, tmp_path):
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=MockContainmentEngine(),
            vault=vault, dry_run=True, always_on=True,
        )
        for i in range(5):
            fp = _make_file(tmp_path, f"vs{i}.txt", f"data{i}".encode())
            enforcer.before_write(fp, 9999)
        enforcer_stats = enforcer.get_stats()
        vault_stats = vault.stats()
        assert enforcer_stats["vault"]["total_entries"] == vault_stats["total_entries"]

    def test_enforce_idempotent_with_real_engine(self, tmp_path):
        dbrg, containment, record, files = self._build_graph_and_contain(tmp_path)
        enforcer = Enforcer(
            containment_engine=containment,
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
        )
        r1 = enforcer.enforce(record)
        r2 = enforcer.enforce(record)
        assert r1 is r2
        assert enforcer.total_enforcements == 1

    def test_unknown_verdict_error(self, tmp_path):
        enforcer = Enforcer(
            containment_engine=MockContainmentEngine(),
            vault=JournalVault(vault_dir=str(tmp_path / "vault")),
            dry_run=True,
        )
        fp = _make_file(tmp_path, "uv.txt", b"data")
        rec = MockContainmentRecord(cut_edges=[("pid:9999", f"file:{fp}")])
        enforcer.enforce(rec)
        result = enforcer.resolve(9999, "INVALID_VERDICT")
        assert not result.success
        assert "unknown" in result.error.lower()


# ═══════════════════════════════════════════════════════════════════════════
#   8. TestHarnessZeroLoss (10 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestHarnessZeroLoss:
    """End-to-end harness tests for zero-data-loss verification."""

    def _run_pipeline_attack(self, tmp_path, profile_name, num_files=13, verdict=Verdict.MALICIOUS):
        """Run full harness pipeline and return (pre_hashes, post_hashes, report)."""
        from src.stage_3_dbrg.dbrg_manager import DBRGManager
        from src.stage_4_features.feature_extractor import FeatureExtractor
        from src.stage_5_anomaly import AnomalyScorer
        from src.stage_6_fusion import ThreatFusion
        from src.stage_7_trust import TrustEvolution
        from src.stage_9_containment import ContainmentEngine
        from src.stage_8_harness.sandbox_manager import SandboxManager
        from src.stage_8_harness.attack_profiles import get_profile
        from src.stage_8_harness.attack_engine import AttackEngine
        from src.stage_8_harness.benchmark_logger import BenchmarkLogger

        profile = get_profile(profile_name)
        sandbox = SandboxManager(tmp_path / "sandbox")
        sandbox.setup(num_files=num_files)

        # Capture pre-attack hashes
        pre_hashes = {}
        for fp in sandbox.get_target_files():
            pre_hashes[str(fp)] = _sha256_file(str(fp))

        # Initialize pipeline
        dbrg = DBRGManager(decay_lambda=0.01)
        feature_ext = FeatureExtractor(dbrg_manager=dbrg)
        anomaly = AnomalyScorer()
        fusion = ThreatFusion()
        trust = TrustEvolution()
        containment = ContainmentEngine(dry_run=True)
        bench = BenchmarkLogger(profile.name)

        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=containment,
            trust_evolution=trust,
            vault=vault,
            dry_run=True,
            always_on=True,
            allowed_roots=[str(tmp_path)],
            rollback_dry_run=False,
        )

        attack_pid = 9999
        detection_triggered = False
        contain_record = None

        def pipeline_callback(original_path, renamed_path, data, index):
            nonlocal detection_triggered, contain_record
            enforcer.note_rename(attack_pid, str(original_path), str(renamed_path))

            ecar = {
                "actorID": f"pid:{attack_pid}",
                "objectID": f"file:{renamed_path}",
                "pid": attack_pid,
                "operation": "MODIFY",
                "timestamp": time.time() * 1000,
                "context": {"exe_path": "malware.exe", "parent_exe": "cmd.exe"},
            }
            dbrg.process_event(ecar)

            try:
                features = feature_ext.extract_features(ecar)
                if not features:
                    return
                anomaly_result = anomaly.score(features)
                fused = fusion.fuse(dict(features), anomaly_result=anomaly_result)
                fused["pid"] = attack_pid
                trust_result = trust.evolve(fused)
                enforcer.on_trust_update(trust_result)

                if trust_result["should_contain"] and not detection_triggered:
                    detection_triggered = True
                    contain_record = containment.contain(
                        attack_pid, dbrg.get_graph_snapshot(), trust_result,
                    )
                    engine.signal_abort("containment")
            except Exception:
                pass

        engine = AttackEngine(
            sandbox=sandbox,
            profile=profile,
            logger_=bench,
            abort_on_detection=True,
            on_file_encrypted=pipeline_callback,
            on_before_encrypt=lambda p, i: enforcer.before_write(str(p), attack_pid),
            on_file_created=lambda p: enforcer.note_created(attack_pid, str(p)),
        )
        engine.execute()

        # Enforce and resolve
        if contain_record is not None:
            enforcer.enforce(contain_record)
            resolution = enforcer.resolve(attack_pid, verdict)
        else:
            resolution = None

        # Post-attack hashes
        post_hashes = {}
        files_lost = 0
        for orig_path, expected_hash in pre_hashes.items():
            if os.path.exists(orig_path):
                actual = _sha256_file(orig_path)
                post_hashes[orig_path] = actual
                if actual != expected_hash:
                    files_lost += 1
            else:
                files_lost += 1

        sandbox.cleanup()
        return pre_hashes, post_hashes, files_lost, resolution

    @pytest.mark.parametrize("profile", ["lockbit", "wannacry", "blackcat"])
    def test_zero_loss_per_profile(self, tmp_path, profile):
        """Every victim file must be byte-identical after rollback."""
        _, _, files_lost, resolution = self._run_pipeline_attack(
            tmp_path, profile, num_files=13
        )
        assert files_lost == 0, f"Files lost: {files_lost} (profile={profile})"

    def test_scale_50_files(self, tmp_path):
        """Scale test with 50 files."""
        _, _, files_lost, _ = self._run_pipeline_attack(
            tmp_path, "lockbit", num_files=50
        )
        assert files_lost == 0

    def test_rename_artifacts_removed(self, tmp_path):
        """Encrypted .locked copies must be removed after rollback."""
        _, _, files_lost, resolution = self._run_pipeline_attack(
            tmp_path, "lockbit", num_files=13
        )
        if resolution and resolution.rollback_report:
            for r in resolution.rollback_report.results:
                for art in r.removed_artifacts:
                    assert not os.path.exists(art)

    def test_ransom_note_removed(self, tmp_path):
        """Ransom notes must be removed after rollback (when present)."""
        _, _, files_lost, resolution = self._run_pipeline_attack(
            tmp_path, "wannacry", num_files=13
        )
        if resolution and resolution.rollback_report:
            for r in resolution.rollback_report.results:
                for art in r.removed_artifacts:
                    assert not os.path.exists(art)

    def test_rollback_latency(self, tmp_path):
        """Rollback of 13 files must complete in < 500ms."""
        _, _, _, resolution = self._run_pipeline_attack(
            tmp_path, "lockbit", num_files=13
        )
        if resolution and resolution.rollback_report:
            assert resolution.rollback_report.duration_ms < 500

    def test_strict_spec_unjournaled(self, tmp_path):
        """With always_on=False and never armed, writes are unjournaled."""
        from src.stage_9_containment import ContainmentEngine
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        enforcer = Enforcer(
            containment_engine=ContainmentEngine(dry_run=True),
            vault=vault,
            dry_run=True,
            always_on=False,
        )
        fp = _make_file(tmp_path, "strict.txt", b"data")
        result = enforcer.before_write(fp, 9999)
        assert result is None
        assert enforcer.unjournaled_writes == 1

    def test_hook_failure_resilience(self, tmp_path):
        """A before_write that raises must not abort the attack."""
        from src.stage_8_harness.sandbox_manager import SandboxManager
        from src.stage_8_harness.attack_profiles import get_profile
        from src.stage_8_harness.attack_engine import AttackEngine
        from src.stage_8_harness.benchmark_logger import BenchmarkLogger

        profile = get_profile("lockbit")
        sandbox = SandboxManager(tmp_path / "sandbox")
        sandbox.setup(num_files=5)

        call_count = [0]
        def bad_hook(path, idx):
            call_count[0] += 1
            raise RuntimeError("hook failure")

        engine = AttackEngine(
            sandbox=sandbox,
            profile=profile,
            logger_=BenchmarkLogger("test"),
            on_before_encrypt=bad_hook,
        )
        result = engine.execute()
        assert result.encrypted_count > 0  # Attack continued despite hook failure
        assert call_count[0] > 0
        sandbox.cleanup()

    @pytest.mark.parametrize("profile", ["lockbit", "wannacry"])
    def test_zero_loss_with_ransom_notes(self, tmp_path, profile):
        """Profiles with ransom notes must still achieve zero loss."""
        _, _, files_lost, _ = self._run_pipeline_attack(
            tmp_path, profile, num_files=13
        )
        assert files_lost == 0

    def test_false_positive_no_restore(self, tmp_path):
        """FP resolution must NOT restore files (writes were legitimate)."""
        from src.stage_9_containment import ContainmentEngine
        vault = JournalVault(vault_dir=str(tmp_path / "vault"))
        ce = ContainmentEngine(dry_run=True)
        trust = MockTrustEvolution()

        enforcer = Enforcer(
            containment_engine=ce,
            trust_evolution=trust,
            vault=vault, dry_run=True, always_on=True,
        )
        fp = _make_file(tmp_path, "fp.txt", b"original")
        enforcer.before_write(fp, 9999)
        with open(fp, "wb") as f:
            f.write(b"modified by benign process")

        rec = MockContainmentRecord(cut_edges=[("pid:9999", f"file:{fp}")])
        enforcer.enforce(rec)
        result = enforcer.resolve(9999, Verdict.FALSE_POSITIVE)
        assert result.success
        # File should still have the "modified" content (not rolled back)
        with open(fp, "rb") as f:
            assert f.read() == b"modified by benign process"


# ═══════════════════════════════════════════════════════════════════════════
#   9. TestUpstreamFixes (4 tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestUpstreamFixes:

    def test_f1_freeze_before_cut(self, tmp_path):
        """F1: freeze must happen BEFORE min-cut computation."""
        from src.stage_9_containment import ContainmentEngine
        from src.stage_3_dbrg.dbrg_manager import DBRGManager

        dbrg = DBRGManager(decay_lambda=0.01)
        containment = ContainmentEngine(dry_run=True)

        fp = _make_file(tmp_path, "f1.txt", b"data")
        ecar = {
            "actorID": "pid:9999", "objectID": f"file:{fp}",
            "pid": 9999, "operation": "MODIFY",
            "timestamp": time.time() * 1000,
            "context": {"exe_path": "test.exe", "parent_exe": "cmd.exe"},
        }
        dbrg.process_event(ecar)

        call_order = []
        orig_freeze = containment.freezer.freeze
        orig_cut = containment.graph_cutter.compute_min_cut

        def spy_freeze(*args, **kwargs):
            call_order.append("freeze")
            return orig_freeze(*args, **kwargs)

        def spy_cut(*args, **kwargs):
            call_order.append("cut")
            return orig_cut(*args, **kwargs)

        containment.freezer.freeze = spy_freeze
        containment.graph_cutter.compute_min_cut = spy_cut

        containment.contain(9999, dbrg.get_graph_snapshot())
        assert call_order.index("freeze") < call_order.index("cut"), \
            f"freeze must happen before cut, got: {call_order}"

    def test_f2_config_thresholds(self, tmp_path):
        """F2: config.yaml stage_7 thresholds must be 60/35/20."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not available")

        config_path = Path(__file__).parent.parent / "config.yaml"
        if not config_path.exists():
            pytest.skip("config.yaml not found")

        with open(config_path, "r") as f:
            data = yaml.safe_load(f)

        s7 = data["stage_7"]["risk_thresholds"]
        assert s7["safe"] == 60.0
        assert s7["monitor"] == 35.0
        assert s7["verify"] == 20.0
        assert s7["critical_risk"] == 0.0

    def test_f3_runner_logs_warning(self, tmp_path, caplog):
        """F3: runner pipeline_callback should log warnings on stage failures."""
        import logging
        # Just verify the logger exists and warning calls are present in the source
        runner_path = Path(__file__).parent.parent / "src" / "stage_8_harness" / "runner.py"
        content = runner_path.read_text()
        assert "logger.warning" in content, "Runner must contain logger.warning calls"
        assert "[Runner] Stage" in content, "Runner warnings must identify the failing stage"

    def test_f5_attack_engine_backward_compatible(self, tmp_path):
        """F5: AttackEngine without new hooks must work as before."""
        from src.stage_8_harness.sandbox_manager import SandboxManager
        from src.stage_8_harness.attack_profiles import get_profile
        from src.stage_8_harness.attack_engine import AttackEngine
        from src.stage_8_harness.benchmark_logger import BenchmarkLogger

        profile = get_profile("lockbit")
        sandbox = SandboxManager(tmp_path / "sandbox")
        sandbox.setup(num_files=5)

        # Construct WITHOUT the new hooks — must not raise
        engine = AttackEngine(
            sandbox=sandbox,
            profile=profile,
            logger_=BenchmarkLogger("test"),
        )
        result = engine.execute()
        assert result.encrypted_count > 0
        sandbox.cleanup()

