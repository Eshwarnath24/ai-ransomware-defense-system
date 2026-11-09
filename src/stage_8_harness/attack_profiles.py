"""
src/stage_8_harness/attack_profiles.py
=========================================
Attack speed presets modelled after real ransomware families.

Each profile controls:
  - interval_ms    : delay between file encryption operations
  - batch_size     : number of files to encrypt per batch
  - rename_ext     : extension appended to encrypted files
  - drop_ransom_note : whether to drop a ransom note in each directory
  - note_filename  : name of the ransom note file
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttackProfile:
    """Defines the speed and behavioral characteristics of a simulated attack."""

    name: str
    interval_ms: float          # milliseconds between batches
    batch_size: int             # files encrypted per batch
    rename_ext: str             # extension appended (.locked, .WNCRY, etc.)
    drop_ransom_note: bool      # whether ransom notes are dropped
    note_filename: str = "README_RESTORE_FILES.txt"
    note_content: str = (
        "YOUR FILES HAVE BEEN ENCRYPTED!\n"
        "To recover your files, send 0.5 BTC to the following address:\n"
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
        "Contact: restore_files@onionmail.org\n"
    )

    def __post_init__(self) -> None:
        if self.interval_ms < 0:
            raise ValueError("interval_ms must be >= 0")
        if self.batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if not self.rename_ext.startswith("."):
            raise ValueError("rename_ext must start with '.'")


# ── Preset Profiles ──────────────────────────────────────────────────

LOCKBIT_AGGRESSIVE = AttackProfile(
    name="LockBit-Aggressive",
    interval_ms=20,
    batch_size=5,
    rename_ext=".locked",
    drop_ransom_note=True,
    note_filename="Restore-My-Files.txt",
)

WANNACRY_BURST = AttackProfile(
    name="WannaCry-Burst",
    interval_ms=50,
    batch_size=3,
    rename_ext=".WNCRY",
    drop_ransom_note=True,
    note_filename="@Please_Read_Me@.txt",
)

BLACKCAT_STEALTH = AttackProfile(
    name="BlackCat-Stealth",
    interval_ms=250,
    batch_size=1,
    rename_ext=".encrypted",
    drop_ransom_note=False,
)


def get_profile(name: str) -> AttackProfile:
    """Look up a profile by name (case-insensitive)."""
    _PROFILES = {
        "lockbit": LOCKBIT_AGGRESSIVE,
        "wannacry": WANNACRY_BURST,
        "blackcat": BLACKCAT_STEALTH,
    }
    key = name.lower().split("-")[0].split("_")[0]
    if key not in _PROFILES:
        raise ValueError(
            f"Unknown profile '{name}'. Choose from: {list(_PROFILES.keys())}"
        )
    return _PROFILES[key]
