"""
src/stage_10_enforcer/journal_rollback.py
============================================
Stage 10 — Write-Ahead Journaling Vault & Rollback Engine

Maintains pre-write file block backups in a dedicated memory-mapped
vault so that confirmed-malicious file modifications can be rolled
back byte-for-byte with zero data loss.

Data Flow:
    AttackEngine.on_before_encrypt  →  JournalVault.snapshot(path, pid)
    AttackEngine.on_file_created    →  JournalVault.note_created(pid, path)
    pipeline_callback rename        →  JournalVault.note_rename(pid, old, new)
    Enforcer.resolve(MALICIOUS)     →  RollbackEngine.rollback(pid)

Vault Layout:
    <vault_dir>/<pid>/<id>.blob          — raw file bytes
    <vault_dir>/<pid>/manifest.json      — entry metadata (atomic writes)

Security:
    Vault directory is created with 0o700 on POSIX. Symlinked vault
    paths and wrong ownership are rejected with VaultSecurityError.
"""

import hashlib
import json
import logging
import mmap
import os
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# SHA-256 of zero bytes (empty file)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class VaultSecurityError(Exception):
    """Raised when the vault directory fails security checks."""


# ---------------------------------------------------------------------------
#   Journal Entry
# ---------------------------------------------------------------------------

@dataclass
class JournalEntry:
    """Metadata for a single snapshotted file."""

    pid: int
    original_path: str        # os.path.realpath at snapshot time
    blob_name: str            # filename inside the vault's PID dir
    sha256: str
    size: int
    mode: int
    mtime_ns: int
    ts: float
    renamed_to: List[str] = field(default_factory=list)
    created_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "original_path": self.original_path,
            "blob_name": self.blob_name,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "mtime_ns": self.mtime_ns,
            "ts": self.ts,
            "renamed_to": list(self.renamed_to),
            "created_paths": list(self.created_paths),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "JournalEntry":
        return cls(
            pid=d["pid"],
            original_path=d["original_path"],
            blob_name=d["blob_name"],
            sha256=d["sha256"],
            size=d["size"],
            mode=d["mode"],
            mtime_ns=d["mtime_ns"],
            ts=d["ts"],
            renamed_to=list(d.get("renamed_to", [])),
            created_paths=list(d.get("created_paths", [])),
        )


# ---------------------------------------------------------------------------
#   Journal Vault
# ---------------------------------------------------------------------------

class JournalVault:
    """
    Memory-mapped write-ahead vault for pre-write file backups.

    Parameters
    ----------
    vault_dir : str
        Directory for blob storage. Defaults to a platform-appropriate
        temp location.
    block_size : int
        Copy chunk size for mmap reads (default 64 KB).
    max_vault_bytes : int
        Total vault size cap (default 512 MB). New snapshots are
        refused (never evicted) if this would be exceeded.
    max_file_bytes : int
        Per-file size cap (default 256 MB).
    """

    def __init__(
        self,
        vault_dir: Optional[str] = None,
        block_size: int = 65536,
        max_vault_bytes: int = 512 * 1024 * 1024,
        max_file_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        if vault_dir is None:
            vault_dir = os.path.join(tempfile.gettempdir(), ".journal_vault")
        self.vault_dir = vault_dir
        self.block_size = block_size
        self.max_vault_bytes = max_vault_bytes
        self.max_file_bytes = max_file_bytes

        self._lock = threading.Lock()
        # pid -> {realpath_key -> JournalEntry}
        self._entries: Dict[int, Dict[str, JournalEntry]] = {}
        self._total_bytes: int = 0
        self.skipped_over_cap: int = 0
        self.total_snapshots: int = 0

        self._init_vault_dir()
        self._load_all_manifests()

    # ------------------------------------------------------------------
    #   Vault directory security
    # ------------------------------------------------------------------

    def _init_vault_dir(self) -> None:
        """Create and validate the vault directory."""
        if os.path.islink(self.vault_dir):
            raise VaultSecurityError(
                f"Vault directory is a symlink (security risk): {self.vault_dir}"
            )

        if os.path.exists(self.vault_dir):
            # Ownership check on POSIX only
            if hasattr(os, "geteuid"):
                st = os.lstat(self.vault_dir)
                if st.st_uid != os.geteuid():
                    raise VaultSecurityError(
                        f"Vault directory owned by uid={st.st_uid}, "
                        f"expected uid={os.geteuid()}: {self.vault_dir}"
                    )
        else:
            if sys.platform == "win32":
                os.makedirs(self.vault_dir, exist_ok=True)
            else:
                os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)

        # Enforce mode on POSIX
        if sys.platform != "win32" and os.path.isdir(self.vault_dir):
            os.chmod(self.vault_dir, 0o700)

    # ------------------------------------------------------------------
    #   Manifest persistence
    # ------------------------------------------------------------------

    def _manifest_path(self, pid: int) -> str:
        return os.path.join(self.vault_dir, str(pid), "manifest.json")

    def _save_manifest(self, pid: int) -> None:
        """Atomically write the manifest for *pid*."""
        pid_dir = os.path.join(self.vault_dir, str(pid))
        os.makedirs(pid_dir, exist_ok=True)
        manifest_path = self._manifest_path(pid)
        entries = self._entries.get(pid, {})
        data = [e.to_dict() for e in entries.values()]
        # Atomic: write to temp then replace
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=pid_dir, prefix=".manifest_", suffix=".tmp"
        )
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, manifest_path)
        except Exception:
            # Clean up temp on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _load_all_manifests(self) -> None:
        """Reload entries from persisted manifests on construction."""
        if not os.path.isdir(self.vault_dir):
            return
        for name in os.listdir(self.vault_dir):
            pid_dir = os.path.join(self.vault_dir, name)
            if not os.path.isdir(pid_dir):
                continue
            try:
                pid = int(name)
            except ValueError:
                continue
            manifest = os.path.join(pid_dir, "manifest.json")
            if not os.path.isfile(manifest):
                continue
            try:
                with open(manifest, "r") as f:
                    data = json.load(f)
                entries: Dict[str, JournalEntry] = {}
                for d in data:
                    entry = JournalEntry.from_dict(d)
                    key = self._path_key(entry.original_path)
                    entries[key] = entry
                    blob_path = os.path.join(pid_dir, entry.blob_name)
                    if os.path.isfile(blob_path):
                        self._total_bytes += os.path.getsize(blob_path)
                    self.total_snapshots += 1
                self._entries[pid] = entries
            except Exception as exc:
                logger.warning("[Vault] Failed to load manifest for pid %s: %s", name, exc)

    # ------------------------------------------------------------------
    #   Key helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _path_key(path: str) -> str:
        """Deterministic key from a realpath (SHA-1 hex)."""
        return hashlib.sha1(path.encode("utf-8", errors="surrogateescape")).hexdigest()

    # ------------------------------------------------------------------
    #   snapshot
    # ------------------------------------------------------------------

    def snapshot(self, path: str, pid: int) -> Optional[JournalEntry]:
        """
        Capture a pre-write snapshot of *path* for *pid*.

        Returns the ``JournalEntry`` on success, or None on failure.
        First-copy-wins: a second snapshot of the same (pid, path) returns
        the existing entry without overwriting the blob.

        Never raises into the caller.
        """
        try:
            return self._snapshot_inner(path, pid)
        except Exception as exc:
            logger.warning("[Vault] snapshot failed for %s (pid=%d): %s", path, pid, exc)
            return None

    def _snapshot_inner(self, path: str, pid: int) -> Optional[JournalEntry]:
        rp = os.path.realpath(path)
        key = self._path_key(rp)

        # First-copy-wins check (under lock)
        with self._lock:
            pid_entries = self._entries.get(pid, {})
            if key in pid_entries:
                return pid_entries[key]

        # Validate target
        try:
            st = os.lstat(rp)
        except OSError:
            logger.debug("[Vault] File not found: %s", rp)
            return None

        if stat.S_ISDIR(st.st_mode):
            logger.debug("[Vault] Skipping directory: %s", rp)
            return None

        if stat.S_ISLNK(st.st_mode):
            logger.debug("[Vault] Skipping symlink: %s", rp)
            return None

        file_size = st.st_size

        # Size caps
        if file_size > self.max_file_bytes:
            logger.warning(
                "[Vault] File %s (%d bytes) exceeds max_file_bytes (%d)",
                rp, file_size, self.max_file_bytes,
            )
            self.skipped_over_cap += 1
            return None

        with self._lock:
            if self._total_bytes + file_size > self.max_vault_bytes:
                logger.warning(
                    "[Vault] Vault capacity exceeded (%d + %d > %d), skipping %s",
                    self._total_bytes, file_size, self.max_vault_bytes, rp,
                )
                self.skipped_over_cap += 1
                return None

        # Prepare blob destination and atomic temp file
        pid_dir = os.path.join(self.vault_dir, str(pid))
        os.makedirs(pid_dir, exist_ok=True)
        blob_name = f"{key}.blob"
        blob_path = os.path.join(pid_dir, blob_name)

        tmp_fd, tmp_blob_path = tempfile.mkstemp(
            dir=pid_dir, prefix=f".{key}_", suffix=".tmp"
        )

        # Copy via mmap
        hasher = hashlib.sha256()

        if file_size == 0:
            # Empty files cannot be mmapped
            with os.fdopen(tmp_fd, "wb") as bf:
                bf.flush()
                os.fsync(bf.fileno())
            sha = _EMPTY_SHA256
        else:
            fd = os.open(rp, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
                try:
                    bytes_copied = 0
                    with os.fdopen(tmp_fd, "wb") as bf:
                        while bytes_copied < file_size:
                            chunk_size = min(self.block_size, file_size - bytes_copied)
                            chunk = mm[bytes_copied:bytes_copied + chunk_size]
                            bf.write(chunk)
                            hasher.update(chunk)
                            bytes_copied += len(chunk)
                        bf.flush()
                        os.fsync(bf.fileno())
                finally:
                    mm.close()
            finally:
                os.close(fd)

            # Verify byte count on temp file
            actual_blob_size = os.path.getsize(tmp_blob_path)
            if actual_blob_size != file_size:
                logger.warning(
                    "[Vault] Size mismatch for %s: expected %d, got %d; discarding",
                    rp, file_size, actual_blob_size,
                )
                try:
                    os.unlink(tmp_blob_path)
                except OSError:
                    pass
                return None

            sha = hasher.hexdigest()

        entry = JournalEntry(
            pid=pid,
            original_path=rp,
            blob_name=blob_name,
            sha256=sha,
            size=file_size,
            mode=st.st_mode,
            mtime_ns=st.st_mtime_ns,
            ts=time.time(),
        )

        # Store under lock (second first-copy-wins check for concurrency)
        with self._lock:
            pid_entries = self._entries.setdefault(pid, {})
            if key in pid_entries:
                # Another thread won the race — discard our temp file
                try:
                    os.unlink(tmp_blob_path)
                except OSError:
                    pass
                return pid_entries[key]

            # Atomically place blob file
            try:
                os.replace(tmp_blob_path, blob_path)
            except Exception:
                try:
                    os.unlink(tmp_blob_path)
                except OSError:
                    pass
                raise

            pid_entries[key] = entry
            self._total_bytes += file_size
            self.total_snapshots += 1

        self._save_manifest(pid)
        logger.info("[Vault] Snapshot %s (%d bytes, sha=%s)", rp, file_size, sha[:12])
        return entry

    # ------------------------------------------------------------------
    #   rename / created tracking
    # ------------------------------------------------------------------

    def note_rename(self, pid: int, old: str, new: str) -> None:
        """
        Record that *old* was renamed to *new* by the attack.

        Finds the entry whose ``original_path == realpath(old)`` or
        whose ``renamed_to`` already contains ``old`` (chains: a→b→c),
        and appends *new*.
        """
        rp_old = os.path.realpath(old)
        rp_new = os.path.realpath(new) if os.path.exists(new) else new

        with self._lock:
            pid_entries = self._entries.get(pid, {})
            target_entry: Optional[JournalEntry] = None

            for entry in pid_entries.values():
                if entry.original_path == rp_old:
                    target_entry = entry
                    break
                if old in entry.renamed_to or rp_old in entry.renamed_to:
                    target_entry = entry
                    break

            if target_entry is None:
                logger.debug("[Vault] note_rename: no entry for %s (pid=%d)", old, pid)
                return

            if rp_new not in target_entry.renamed_to and new not in target_entry.renamed_to:
                target_entry.renamed_to.append(str(rp_new))

        self._save_manifest(pid)

    def note_created(self, pid: int, path: str) -> None:
        """Record that *path* was created by the attack (e.g. ransom note)."""
        rp = os.path.realpath(str(path)) if os.path.exists(str(path)) else str(path)

        with self._lock:
            pid_entries = self._entries.get(pid, {})
            if not pid_entries:
                logger.debug("[Vault] note_created: no entries for pid=%d", pid)
                return
            # Attach to the first entry for this PID
            first_entry = next(iter(pid_entries.values()))
            if rp not in first_entry.created_paths:
                first_entry.created_paths.append(rp)

        self._save_manifest(pid)

    # ------------------------------------------------------------------
    #   queries
    # ------------------------------------------------------------------

    def entries(self, pid: Optional[int] = None) -> List[JournalEntry]:
        """Return journal entries, optionally filtered by PID."""
        with self._lock:
            if pid is not None:
                return list(self._entries.get(pid, {}).values())
            result = []
            for pid_entries in self._entries.values():
                result.extend(pid_entries.values())
            return result

    def read_blob(self, entry: JournalEntry) -> bytes:
        """Read and return the stored blob bytes for an entry."""
        blob_path = os.path.join(self.vault_dir, str(entry.pid), entry.blob_name)
        with open(blob_path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------------
    #   purge
    # ------------------------------------------------------------------

    def purge(self, pid: int) -> int:
        """Delete all blobs and manifests for *pid*. Returns bytes freed."""
        freed = 0
        pid_dir = os.path.join(self.vault_dir, str(pid))

        with self._lock:
            pid_entries = self._entries.pop(pid, {})
            for entry in pid_entries.values():
                blob_path = os.path.join(pid_dir, entry.blob_name)
                if os.path.isfile(blob_path):
                    freed += os.path.getsize(blob_path)
                    try:
                        os.unlink(blob_path)
                    except OSError:
                        pass
            self._total_bytes = max(0, self._total_bytes - freed)

        # Remove manifest and directory
        manifest = self._manifest_path(pid)
        if os.path.isfile(manifest):
            try:
                os.unlink(manifest)
            except OSError:
                pass
        try:
            os.rmdir(pid_dir)
        except OSError:
            pass

        logger.info("[Vault] Purged pid=%d, freed %d bytes", pid, freed)
        return freed

    # ------------------------------------------------------------------
    #   stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total_entries = sum(len(e) for e in self._entries.values())
            pids_tracked = len(self._entries)
        return {
            "total_snapshots": self.total_snapshots,
            "total_entries": total_entries,
            "pids_tracked": pids_tracked,
            "total_bytes": self._total_bytes,
            "max_vault_bytes": self.max_vault_bytes,
            "max_file_bytes": self.max_file_bytes,
            "skipped_over_cap": self.skipped_over_cap,
            "vault_dir": self.vault_dir,
        }

    def __repr__(self) -> str:
        return (
            f"JournalVault(snapshots={self.total_snapshots}, "
            f"bytes={self._total_bytes}, dir={self.vault_dir!r})"
        )


# ---------------------------------------------------------------------------
#   File Restore Result / Rollback Report
# ---------------------------------------------------------------------------

@dataclass
class FileRestoreResult:
    """Result of restoring a single file."""

    original_path: str
    success: bool
    reason: str
    bytes_restored: int = 0
    sha256_ok: bool = False
    removed_artifacts: List[str] = field(default_factory=list)


@dataclass
class RollbackReport:
    """Aggregate result of rolling back all files for a PID."""

    pid: int
    results: List[FileRestoreResult]
    total: int
    restored: int
    failed: int
    deleted_artifacts: int
    duration_ms: float
    dry_run: bool

    @property
    def zero_loss(self) -> bool:
        """True when every journaled file was restored successfully."""
        return self.failed == 0 and self.restored == self.total


# ---------------------------------------------------------------------------
#   Rollback Engine
# ---------------------------------------------------------------------------

class RollbackEngine:
    """
    Restores files from the journal vault with zero-data-loss guarantees.

    Parameters
    ----------
    vault : JournalVault
        The vault holding pre-write snapshots.
    acl : ACLManager, optional
        If provided, writes are wrapped in ``temporarily_writable()``.
    dry_run : bool
        If True (default), plans the rollback but writes nothing.
    allowed_roots : sequence of str, optional
        If set, only files under these directories may be written or
        deleted. Paths outside are refused.
    """

    def __init__(
        self,
        vault: JournalVault,
        acl: Optional[Any] = None,
        dry_run: bool = True,
        allowed_roots: Optional[Sequence[str]] = None,
    ) -> None:
        self.vault = vault
        self.acl = acl
        self.dry_run = dry_run
        self.allowed_roots = (
            [os.path.realpath(str(r)) for r in allowed_roots]
            if allowed_roots is not None
            else None
        )

    def _is_allowed(self, path: str) -> bool:
        """Check if *path* is under one of the allowed roots."""
        if self.allowed_roots is None:
            return True
        rp = os.path.realpath(path)
        return any(
            rp.startswith(root + os.sep) or rp == root
            for root in self.allowed_roots
        )

    def rollback(self, pid: int) -> RollbackReport:
        """
        Restore all journaled files for *pid*.

        For each entry (in order):
          1. Check allowed_roots.
          2. Verify blob SHA-256 before touching the original.
          3. Atomic restore: temp file → fsync → os.replace → chmod → utime.
          4. Delete renamed copies (.locked etc.) and created artifacts.

        Continues after per-file failures and reports all results.
        Idempotent: a second rollback restores the same bytes again.
        """
        t_start = time.perf_counter()
        entries = self.vault.entries(pid=pid)
        results: List[FileRestoreResult] = []
        total_artifacts_deleted = 0

        for entry in entries:
            result = self._restore_one(entry)
            total_artifacts_deleted += len(result.removed_artifacts)
            results.append(result)

        duration_ms = (time.perf_counter() - t_start) * 1000.0
        restored = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)

        report = RollbackReport(
            pid=pid,
            results=results,
            total=len(results),
            restored=restored,
            failed=failed,
            deleted_artifacts=total_artifacts_deleted,
            duration_ms=duration_ms,
            dry_run=self.dry_run,
        )

        logger.info(
            "[Rollback] PID=%d: %d/%d restored, %d artifacts deleted, %.1fms%s",
            pid, restored, len(results), total_artifacts_deleted,
            duration_ms, " (DRY RUN)" if self.dry_run else "",
        )

        return report

    def _restore_one(self, entry: JournalEntry) -> FileRestoreResult:
        """Restore a single file from its journal entry."""
        path = entry.original_path

        # 1. Allowed roots check
        if not self._is_allowed(path):
            return FileRestoreResult(
                original_path=path, success=False,
                reason="outside_allowed_roots",
            )

        # Also check artifacts
        for art_path in entry.renamed_to + entry.created_paths:
            if not self._is_allowed(art_path):
                return FileRestoreResult(
                    original_path=path, success=False,
                    reason="outside_allowed_roots",
                )

        # 2. Read and verify blob
        try:
            blob_data = self.vault.read_blob(entry)
        except Exception as exc:
            return FileRestoreResult(
                original_path=path, success=False,
                reason=f"blob_read_error: {exc}",
            )

        blob_sha = hashlib.sha256(blob_data).hexdigest()
        if blob_sha != entry.sha256:
            return FileRestoreResult(
                original_path=path, success=False,
                reason="vault_corrupt",
            )

        # Dry run: plan only
        if self.dry_run:
            return FileRestoreResult(
                original_path=path, success=True,
                reason="dry_run",
                bytes_restored=len(blob_data),
                sha256_ok=True,
            )

        # 3 + 4. Atomic restore
        try:
            removed = self._do_restore(entry, blob_data)
        except Exception as exc:
            return FileRestoreResult(
                original_path=path, success=False,
                reason=f"restore_error: {exc}",
            )

        # Verify restored file hash
        try:
            with open(path, "rb") as f:
                restored_sha = hashlib.sha256(f.read()).hexdigest()
            sha256_ok = (restored_sha == entry.sha256)
        except OSError:
            sha256_ok = False

        return FileRestoreResult(
            original_path=path,
            success=True,
            reason="restored",
            bytes_restored=len(blob_data),
            sha256_ok=sha256_ok,
            removed_artifacts=removed,
        )

    def _do_restore(
        self, entry: JournalEntry, blob_data: bytes,
    ) -> List[str]:
        """Write bytes and clean up artifacts. Returns list of removed paths."""
        path = entry.original_path
        removed: List[str] = []

        # Ensure parent directory exists
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Write via ACL temporarily_writable if available
        def _write():
            tmp_fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".restore_")
            try:
                with os.fdopen(tmp_fd, "wb") as f:
                    f.write(blob_data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

            # Restore mode and mtime
            try:
                os.chmod(path, entry.mode & 0o7777)
            except OSError:
                pass
            try:
                os.utime(path, ns=(entry.mtime_ns, entry.mtime_ns))
            except OSError:
                pass

        if self.acl is not None:
            with self.acl.temporarily_writable(path):
                _write()
        else:
            _write()

        # Delete renamed copies (encrypted .locked files etc.)
        for renamed_path in entry.renamed_to:
            rp = os.path.realpath(renamed_path) if os.path.exists(renamed_path) else renamed_path
            if rp != os.path.realpath(path) and os.path.exists(rp):
                try:
                    if self.acl is not None:
                        with self.acl.temporarily_writable(rp):
                            os.unlink(rp)
                    else:
                        os.unlink(rp)
                    removed.append(rp)
                except OSError as exc:
                    logger.warning("[Rollback] Failed to remove artifact %s: %s", rp, exc)

        # Delete created paths (ransom notes)
        for created_path in entry.created_paths:
            cp = os.path.realpath(created_path) if os.path.exists(created_path) else created_path
            if os.path.exists(cp):
                try:
                    if self.acl is not None:
                        with self.acl.temporarily_writable(cp):
                            os.unlink(cp)
                    else:
                        os.unlink(cp)
                    removed.append(cp)
                except OSError as exc:
                    logger.warning("[Rollback] Failed to remove artifact %s: %s", cp, exc)

        return removed

