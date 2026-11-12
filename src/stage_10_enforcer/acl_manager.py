"""
src/stage_10_enforcer/acl_manager.py
=======================================
Stage 10 — ACL Access Manager

Revokes file-system write permissions strictly along C_min paths
(the minimum-cut boundary computed by Stage 9). Supports restore
for false-positive recovery and a ``temporarily_writable`` context
manager for rollback writes while keeping the revocations active.

Data Flow:
    Stage 9 (ContainmentRecord.cut_edges / isolated_files)
        → ACLManager.revoke(pid, file_paths)
            → writes are blocked on those paths
    Stage 10 resolve(MALICIOUS)
        → revocations remain active (quarantine)
    Stage 10 resolve(FALSE_POSITIVE)
        → ACLManager.restore_all(pid)

Backends:
    SimulatedACLBackend — in-memory tracking for dry_run / testing
    PosixACLBackend     — os.chmod to clear S_IW* bits
    WindowsACLBackend   — icacls /deny and /remove:d

Caveat: chmod does not restrict root on POSIX. Tests should assert
mode bits, not actual write failure.
"""

import logging
import os
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#   ACL Backend Protocol
# ---------------------------------------------------------------------------

class ACLBackend(Protocol):
    """Interface for OS-specific permission manipulation."""

    def get_mode(self, path: str) -> Optional[int]:
        """Return the permission bits (``st_mode``) or None on failure."""
        ...

    def revoke_write(self, path: str) -> bool:
        """Remove write permissions; return True on success."""
        ...

    def restore(self, path: str, original: int) -> bool:
        """Restore permissions to *original* mode; return True on success."""
        ...


# ---------------------------------------------------------------------------
#   Simulated Backend (dry-run / tests)
# ---------------------------------------------------------------------------

class SimulatedACLBackend:
    """
    In-memory backend that tracks permission state without touching
    the file system.  Used when ``dry_run=True`` (default).
    """

    def __init__(self) -> None:
        self._modes: Dict[str, int] = {}

    def get_mode(self, path: str) -> Optional[int]:
        if path in self._modes:
            return self._modes[path]
        # Try to read real mode as seed
        try:
            return os.lstat(path).st_mode
        except OSError:
            return 0o644  # default

    def revoke_write(self, path: str) -> bool:
        current = self.get_mode(path)
        if current is None:
            return False
        write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        self._modes[path] = current & ~write_bits
        return True

    def restore(self, path: str, original: int) -> bool:
        self._modes[path] = original
        return True


# ---------------------------------------------------------------------------
#   POSIX Backend
# ---------------------------------------------------------------------------

class PosixACLBackend:
    """Real permission changes via ``os.chmod``."""

    def get_mode(self, path: str) -> Optional[int]:
        try:
            return os.lstat(path).st_mode
        except OSError:
            return None

    def revoke_write(self, path: str) -> bool:
        try:
            current = os.lstat(path).st_mode
            write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
            os.chmod(path, current & ~write_bits)
            return True
        except OSError as exc:
            logger.warning("[ACL-Posix] revoke_write failed for %s: %s", path, exc)
            return False

    def restore(self, path: str, original: int) -> bool:
        try:
            os.chmod(path, original)
            return True
        except OSError as exc:
            logger.warning("[ACL-Posix] restore failed for %s: %s", path, exc)
            return False


# ---------------------------------------------------------------------------
#   Windows Backend
# ---------------------------------------------------------------------------

class WindowsACLBackend:
    """Permission changes via ``icacls`` on Windows."""

    def __init__(self) -> None:
        try:
            self._user = os.environ.get("USERNAME", os.getlogin())
        except OSError:
            self._user = "Everyone"

    def get_mode(self, path: str) -> Optional[int]:
        try:
            return os.lstat(path).st_mode
        except OSError:
            return None

    def revoke_write(self, path: str) -> bool:
        try:
            subprocess.run(
                ["icacls", path, "/deny", f"{self._user}:(W,WD,AD)"],
                capture_output=True, check=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            logger.warning("[ACL-Windows] revoke_write failed for %s: %s", path, exc)
            return False

    def restore(self, path: str, original: int) -> bool:
        try:
            subprocess.run(
                ["icacls", path, "/remove:d", self._user],
                capture_output=True, check=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            logger.warning("[ACL-Windows] restore failed for %s: %s", path, exc)
            return False


# ---------------------------------------------------------------------------
#   ACL Record
# ---------------------------------------------------------------------------

@dataclass
class ACLRecord:
    """Audit record for a single ACL revocation."""

    path: str
    pid: int
    original_mode: int
    revoked_at: float
    active: bool
    backend: str


# ---------------------------------------------------------------------------
#   ACL Manager
# ---------------------------------------------------------------------------

class ACLManager:
    """
    Manages write-permission revocations along C_min paths.

    Parameters
    ----------
    dry_run : bool
        If True (default), uses ``SimulatedACLBackend`` — no real
        permission changes.  If False, auto-selects the OS backend.
    backend : ACLBackend, optional
        Override the backend directly (useful for testing).
    """

    def __init__(
        self,
        dry_run: bool = True,
        backend: Optional[Any] = None,
    ) -> None:
        self.dry_run = dry_run
        if backend is not None:
            self._backend = backend
        elif dry_run:
            self._backend = SimulatedACLBackend()
        elif sys.platform == "win32":
            self._backend = WindowsACLBackend()
        else:
            self._backend = PosixACLBackend()

        self._backend_name = type(self._backend).__name__

        # path -> ACLRecord   (keyed by normalized path)
        self._records: Dict[str, ACLRecord] = {}
        # pid -> set of paths
        self._pid_paths: Dict[int, set] = {}
        self._lock = threading.Lock()

        # Counters
        self.total_revocations: int = 0
        self.total_restores: int = 0
        self.skipped_nonexistent: int = 0
        self.skipped_directories: int = 0
        self.skipped_symlinks: int = 0

    # ------------------------------------------------------------------
    #   Public API
    # ------------------------------------------------------------------

    def revoke(self, pid: int, paths: Iterable[str]) -> List[ACLRecord]:
        """
        Revoke write permissions on *paths* for the given *pid*.

        Skips directories, non-existent files, and symlinks.
        Idempotent: re-revoking a path keeps the original stored mode.
        """
        records: List[ACLRecord] = []

        for raw_path in paths:
            norm = os.path.normpath(raw_path)

            # --- guards ------------------------------------------------
            try:
                st = os.lstat(norm)
            except OSError:
                self.skipped_nonexistent += 1
                logger.debug("[ACL] Skipping non-existent path: %s", norm)
                continue

            if stat.S_ISDIR(st.st_mode):
                self.skipped_directories += 1
                logger.debug("[ACL] Skipping directory: %s", norm)
                continue

            if stat.S_ISLNK(st.st_mode):
                self.skipped_symlinks += 1
                logger.debug("[ACL] Skipping symlink: %s", norm)
                continue

            # --- idempotent check --------------------------------------
            with self._lock:
                existing = self._records.get(norm)
                if existing is not None and existing.active:
                    records.append(existing)
                    logger.debug("[ACL] Already revoked: %s", norm)
                    continue

            # --- capture original mode ---------------------------------
            original_mode = self._backend.get_mode(norm)
            if original_mode is None:
                self.skipped_nonexistent += 1
                continue

            # --- revoke ------------------------------------------------
            success = self._backend.revoke_write(norm)
            if not success:
                continue

            record = ACLRecord(
                path=norm,
                pid=pid,
                original_mode=original_mode,
                revoked_at=time.time(),
                active=True,
                backend=self._backend_name,
            )

            with self._lock:
                self._records[norm] = record
                self._pid_paths.setdefault(pid, set()).add(norm)
                self.total_revocations += 1

            records.append(record)
            logger.info("[ACL] Revoked write on %s (pid=%d)", norm, pid)

        return records

    def restore_all(self, pid: int) -> List[ACLRecord]:
        """Restore original permissions for all paths revoked for *pid*."""
        restored: List[ACLRecord] = []
        with self._lock:
            paths = list(self._pid_paths.get(pid, []))

        for norm in paths:
            with self._lock:
                record = self._records.get(norm)
            if record is None or not record.active:
                continue

            success = self._backend.restore(norm, record.original_mode)
            if success:
                with self._lock:
                    record.active = False
                    self.total_restores += 1
                restored.append(record)
                logger.info("[ACL] Restored %s (pid=%d)", norm, pid)

        return restored

    def restore(self, path: str) -> bool:
        """Restore a single path's original permissions."""
        norm = os.path.normpath(path)
        with self._lock:
            record = self._records.get(norm)
        if record is None or not record.active:
            return False

        success = self._backend.restore(norm, record.original_mode)
        if success:
            with self._lock:
                record.active = False
                self.total_restores += 1
        return success

    @contextmanager
    def temporarily_writable(self, path: str) -> Iterator[None]:
        """
        Context manager that lifts the write revocation on *path*,
        yields, and then **always** re-applies the revocation.

        Used by the rollback engine to write restored bytes while
        keeping ACL revocations active overall.
        """
        norm = os.path.normpath(path)
        with self._lock:
            record = self._records.get(norm)

        lifted = False
        if record is not None and record.active:
            self._backend.restore(norm, record.original_mode)
            lifted = True

        try:
            yield
        finally:
            if lifted and record is not None:
                self._backend.revoke_write(norm)

    def active_revocations(
        self, pid: Optional[int] = None
    ) -> List[ACLRecord]:
        """Return all active ACL revocations, optionally filtered by PID."""
        with self._lock:
            if pid is not None:
                paths = self._pid_paths.get(pid, set())
                return [
                    self._records[p]
                    for p in paths
                    if p in self._records and self._records[p].active
                ]
            return [r for r in self._records.values() if r.active]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics."""
        with self._lock:
            active = sum(1 for r in self._records.values() if r.active)
        return {
            "total_revocations": self.total_revocations,
            "total_restores": self.total_restores,
            "active_revocations": active,
            "skipped_nonexistent": self.skipped_nonexistent,
            "skipped_directories": self.skipped_directories,
            "skipped_symlinks": self.skipped_symlinks,
            "backend": self._backend_name,
            "dry_run": self.dry_run,
        }

    def __repr__(self) -> str:
        return (
            f"ACLManager(revocations={self.total_revocations}, "
            f"restores={self.total_restores}, "
            f"backend={self._backend_name}, "
            f"dry_run={self.dry_run})"
        )

