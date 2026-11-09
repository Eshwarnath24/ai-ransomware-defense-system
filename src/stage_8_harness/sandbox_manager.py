"""
src/stage_8_harness/sandbox_manager.py
=========================================
Manages the sandboxed victim file environment for Stage 8.

Creates a realistic mock user directory tree with low-entropy content
files (documents, spreadsheets, images) that mimic a real user's
workspace. Every file operation is guarded by a hard path-boundary
check to prevent any write/rename/delete outside the sandbox.

Safety Invariant:
    All paths are resolved to absolute form and verified with
    ``Path.is_relative_to(sandbox_root)`` before ANY filesystem
    mutation. Violations raise ``SandboxEscapeError``.
"""

import logging
import random
import shutil
from pathlib import Path
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

# ── Project root (used for default sandbox location) ─────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# ── Default sandbox location — inside the project tree ───────────────
DEFAULT_SANDBOX_DIR = PROJECT_ROOT / "sandbox_env"

# ── Known ransomware extensions (for dirty-sandbox filtering) ────────
_RANSOMWARE_EXTENSIONS: Set[str] = {".locked", ".WNCRY", ".encrypted"}
_RANSOM_NOTE_NAMES: Set[str] = {
    "Restore-My-Files.txt",
    "@Please_Read_Me@.txt",
    "README_RESTORE_FILES.txt",
}


class SandboxEscapeError(Exception):
    """Raised when a file operation would escape the sandbox boundary."""


# ── File templates ───────────────────────────────────────────────────
# Low-entropy, realistic content that will produce noticeably different
# entropy statistics once overwritten with os.urandom().

_FILE_TEMPLATES = {
    "Documents/finance/quarterly_report_Q3.xlsx": (
        b"PK\x03\x04" + b"Revenue,Expenses,Profit\n"
        b"150000,120000,30000\n" * 40
        + b"Total,Annual,Summary\n" * 10
    ),
    "Documents/finance/invoice_2024_0451.pdf": (
        b"%PDF-1.4 Invoice\n"
        b"Bill To: Acme Corp\nAmount: $12,450.00\n"
        b"Payment Terms: Net 30\nDue Date: 2024-12-01\n" * 30
    ),
    "Documents/finance/budget_forecast.csv": (
        b"Month,Department,Budget,Actual,Variance\n"
        + b"".join(
            f"2024-{m:02d},{d},50000,{48000 + m * 100},{2000 - m * 100}\n".encode()
            for m in range(1, 13)
            for d in ["Engineering", "Sales", "Marketing", "HR"]
        )
    ),
    "Documents/projects/thesis_draft_v3.docx": (
        b"PK\x03\x04" + (
            b"Chapter 1: Introduction to Behavioral Ransomware Detection\n"
            b"This thesis presents a novel approach to detecting ransomware "
            b"through behavioral intent recognition using dynamic trust scores "
            b"and multi-signal corroboration engines.\n"
        ) * 20
    ),
    "Documents/projects/meeting_notes_nov.txt": (
        b"Meeting Notes - November 2024\n"
        b"Attendees: Alice, Bob, Charlie, Diana\n"
        b"Agenda:\n"
        b"1. Review Q3 performance metrics\n"
        b"2. Discuss deployment timeline for v2.0\n"
        b"3. Security audit findings\n"
        b"Action Items:\n"
        b"- Alice: Update threat model documentation\n"
        b"- Bob: Fix memory leak in trust engine\n" * 10
    ),
    "Documents/projects/requirements_spec.docx": (
        b"PK\x03\x04"
        b"Software Requirements Specification\n"
        b"Version 2.1 - Last Updated: 2024-10-15\n"
        b"1. System shall detect ransomware within 500ms of first write.\n"
        b"2. False positive rate shall not exceed 2%.\n"
        b"3. Recovery shall restore files to pre-attack state.\n" * 15
    ),
    "Desktop/reports/annual_review_2024.pdf": (
        b"%PDF-1.4 Annual Review\n"
        b"Employee: John Smith\nDepartment: Security Research\n"
        b"Performance Rating: Exceeds Expectations\n"
        b"Key Achievements: Deployed BIRF v1.0 to production.\n" * 20
    ),
    "Desktop/reports/expense_claim.xlsx": (
        b"PK\x03\x04"
        b"Date,Description,Amount,Category\n"
        b"2024-11-01,Conference Travel,1250.00,Travel\n"
        b"2024-11-02,Hotel Stay,890.00,Accommodation\n"
        b"2024-11-03,Team Dinner,156.50,Meals\n" * 15
    ),
    "Desktop/todo_list.txt": (
        b"TODO List - Week 45\n"
        b"[x] Submit Stage 7 pull request\n"
        b"[ ] Review Stage 8 harness design\n"
        b"[ ] Update architecture documentation\n"
        b"[ ] Prepare demo for stakeholder meeting\n" * 8
    ),
    "Pictures/vacation_photo_001.png": (
        # Simulated PNG header + low-entropy pixel data
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x80\xff\x40\x20\xc0\xa0\x60" * 512
    ),
    "Pictures/screenshot_dashboard.png": (
        b"\x89PNG\r\n\x1a\n"
        + b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8" * 512
    ),
    "Downloads/setup_installer.exe": (
        b"MZ\x90\x00" + b"This program cannot be run in DOS mode.\r\n" * 30
    ),
    "Downloads/data_export.csv": (
        b"id,name,email,created_at,status\n"
        + b"".join(
            f"{i},user_{i},user_{i}@example.com,2024-01-{(i % 28)+1:02d},active\n".encode()
            for i in range(1, 51)
        )
    ),
}

# ── Dynamic file generation helpers ──────────────────────────────────
# Directory → extension pools for generating realistic extra files.
_DYNAMIC_DIR_POOLS = [
    ("Documents/finance", [".xlsx", ".csv", ".pdf"]),
    ("Documents/projects", [".docx", ".txt", ".md"]),
    ("Documents/personal", [".docx", ".txt", ".pdf"]),
    ("Desktop/reports", [".pdf", ".xlsx"]),
    ("Desktop/notes", [".txt", ".md"]),
    ("Pictures/photos", [".png", ".jpg"]),
    ("Pictures/screenshots", [".png"]),
    ("Downloads", [".csv", ".pdf", ".exe", ".zip"]),
    ("Music", [".mp3", ".wav"]),
    ("Videos", [".mp4", ".avi"]),
]

# Low-entropy content generators keyed by extension
_CONTENT_GENERATORS = {
    ".xlsx": lambda i: b"PK\x03\x04" + f"Row,Col_A,Col_B,Col_C\n{i},{i*10},{i*100},{i*1000}\n".encode() * 40,
    ".csv": lambda i: (b"id,value,label,timestamp\n" +
                        f"{i},{i*3.14:.2f},item_{i},2024-{(i%12)+1:02d}-{(i%28)+1:02d}\n".encode() * 50),
    ".pdf": lambda i: b"%PDF-1.4 Document\n" + f"Page {i}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n".encode() * 30,
    ".docx": lambda i: b"PK\x03\x04" + f"Section {i}: Analysis of system performance metrics.\n".encode() * 25,
    ".txt": lambda i: f"Notes - Entry {i}\nCreated: 2024-11-{(i%28)+1:02d}\nContent: Detailed notes about topic {i}.\n".encode() * 15,
    ".md": lambda i: f"# Document {i}\n\n## Overview\n\nThis document describes item {i} in detail.\n".encode() * 10,
    ".png": lambda i: b"\x89PNG\r\n\x1a\n" + bytes([(i * 7 + j) % 256 for j in range(512)]) * 8,
    ".jpg": lambda i: b"\xff\xd8\xff\xe0" + bytes([(i * 11 + j) % 256 for j in range(512)]) * 8,
    ".exe": lambda i: b"MZ\x90\x00" + f"Program module {i} stub.\r\n".encode() * 20,
    ".zip": lambda i: b"PK\x03\x04" + f"archive_entry_{i}.dat\n".encode() * 30,
    ".mp3": lambda i: b"ID3\x03\x00" + bytes([(i * 13 + j) % 200 for j in range(1024)]),
    ".wav": lambda i: b"RIFF" + bytes([(i * 17 + j) % 200 for j in range(1024)]),
    ".mp4": lambda i: b"\x00\x00\x00\x1cftypisom" + bytes([(i * 19 + j) % 200 for j in range(1024)]),
    ".avi": lambda i: b"RIFF" + bytes([(i * 23 + j) % 200 for j in range(1024)]),
}


def _generate_extra_files(count: int, seed: int = 42) -> dict:
    """
    Dynamically generate *count* additional victim files with realistic
    low-entropy content spread across diverse directories and extensions.

    Parameters
    ----------
    count : int
        Number of additional files to generate.
    seed : int
        Random seed for reproducible file distribution.

    Returns
    -------
    dict
        {relative_path_str: bytes_content} suitable for setup(extra_files=...).
    """
    rng = random.Random(seed)
    extra: dict = {}
    for i in range(count):
        dir_name, ext_pool = rng.choice(_DYNAMIC_DIR_POOLS)
        ext = rng.choice(ext_pool)
        filename = f"file_{i+1:04d}{ext}"
        rel_path = f"{dir_name}/{filename}"
        generator = _CONTENT_GENERATORS.get(ext, _CONTENT_GENERATORS[".txt"])
        extra[rel_path] = generator(i + 1)
    return extra


class SandboxManager:
    """
    Creates and manages a sandboxed victim file environment.

    Parameters
    ----------
    sandbox_dir : Path, optional
        Root directory for the sandbox. Defaults to ``PROJECT_ROOT/sandbox_env``.
    """

    def __init__(self, sandbox_dir: Optional[Path] = None) -> None:
        self._sandbox_dir = (sandbox_dir or DEFAULT_SANDBOX_DIR).resolve()
        self._created_files: List[Path] = []
        self._is_setup = False

    @property
    def sandbox_dir(self) -> Path:
        return self._sandbox_dir

    @property
    def is_setup(self) -> bool:
        return self._is_setup

    # ── Safety Guard ─────────────────────────────────────────────────

    def verify_path_safety(self, path: Path) -> Path:
        """
        Resolve *path* and assert it is inside the sandbox.

        Returns the resolved path on success; raises SandboxEscapeError
        if the path would escape the sandbox boundary.
        """
        resolved = path.resolve()
        if not resolved.is_relative_to(self._sandbox_dir):
            raise SandboxEscapeError(
                f"SECURITY VIOLATION: Path '{resolved}' escapes sandbox "
                f"boundary '{self._sandbox_dir}'. Operation blocked."
            )
        return resolved

    # ── Setup / Teardown ─────────────────────────────────────────────

    def setup(
        self,
        extra_files: Optional[dict] = None,
        num_files: Optional[int] = None,
    ) -> List[Path]:
        """
        Create the victim file tree inside the sandbox.

        Parameters
        ----------
        extra_files : dict, optional
            Additional {relative_path_str: bytes_content} entries to create.
        num_files : int, optional
            Target number of victim files. If greater than the base
            template count (13), additional files are dynamically
            generated with realistic low-entropy content. If less than
            the template count, only the first *num_files* templates
            are created.

        Returns
        -------
        list of Path
            All created file paths (absolute).
        """
        self._created_files.clear()
        self._sandbox_dir.mkdir(parents=True, exist_ok=True)

        templates = dict(_FILE_TEMPLATES)
        if extra_files:
            templates.update(extra_files)

        # Dynamic scaling: generate extra files if num_files > template count
        if num_files is not None and num_files > len(templates):
            dynamic_extras = _generate_extra_files(num_files - len(templates))
            templates.update(dynamic_extras)

        # Optionally limit to num_files
        items = list(templates.items())
        if num_files is not None and num_files < len(items):
            items = items[:num_files]

        for rel_path_str, content in items:
            file_path = self._sandbox_dir / rel_path_str
            safe_path = self.verify_path_safety(file_path)
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            safe_path.write_bytes(content)
            self._created_files.append(safe_path)

        self._is_setup = True
        logger.info(
            "Sandbox setup complete: %d files in %s",
            len(self._created_files), self._sandbox_dir,
        )
        return list(self._created_files)

    def cleanup(self) -> None:
        """Remove the entire sandbox directory tree."""
        if self._sandbox_dir.exists():
            shutil.rmtree(self._sandbox_dir, ignore_errors=True)
            logger.info("Sandbox cleaned up: %s", self._sandbox_dir)
        self._created_files.clear()
        self._is_setup = False

    def reset(self, num_files: Optional[int] = None) -> List[Path]:
        """Cleanup then re-setup the sandbox from scratch."""
        self.cleanup()
        return self.setup(num_files=num_files)

    # ── Query ────────────────────────────────────────────────────────

    def get_target_files(self) -> List[Path]:
        """
        Return attackable files currently in the sandbox (live scan).

        Filters out already-encrypted files (ransomware extensions) and
        ransom notes so that re-running an attack on a dirty sandbox
        does not produce double-extension artifacts.
        """
        if not self._sandbox_dir.exists():
            return []
        return sorted(
            p for p in self._sandbox_dir.rglob("*")
            if p.is_file()
            and p.suffix not in _RANSOMWARE_EXTENSIONS
            and p.name not in _RANSOM_NOTE_NAMES
        )

    def get_all_files(self) -> List[Path]:
        """Return ALL files in the sandbox (no filtering)."""
        if not self._sandbox_dir.exists():
            return []
        return sorted(p for p in self._sandbox_dir.rglob("*") if p.is_file())

    def get_created_files(self) -> List[Path]:
        """Return the list of files created during the last setup()."""
        return list(self._created_files)

    def file_count(self) -> int:
        """Return the number of files currently in the sandbox."""
        return len(self.get_target_files())

    def __repr__(self) -> str:
        return (
            f"SandboxManager(dir='{self._sandbox_dir}', "
            f"setup={self._is_setup}, files={len(self._created_files)})"
        )
