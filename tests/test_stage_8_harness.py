"""
tests/test_stage_8_harness.py
================================
Comprehensive test suite for Stage 8 — Synthetic Ransomware Test Harness.

Test Categories:
  1. SandboxManager    — setup, cleanup, path safety, dynamic scaling, dirty filtering
  2. AttackProfiles    — dataclass validation, preset profiles
  3. AttackEngine      — encryption, renaming, ransom notes, callbacks, safety guards
  4. BenchmarkLogger   — event recording, latency, report generation
  5. Integration       — full attack + pipeline stages 3-7 + runner orchestrator
"""

import math
import os
import time
import pytest
from pathlib import Path
from collections import Counter

from src.stage_8_harness.sandbox_manager import (
    SandboxManager,
    SandboxEscapeError,
)
from src.stage_8_harness.attack_profiles import (
    AttackProfile,
    LOCKBIT_AGGRESSIVE,
    WANNACRY_BURST,
    BLACKCAT_STEALTH,
    get_profile,
)
from src.stage_8_harness.attack_engine import AttackEngine, AttackResult
from src.stage_8_harness.benchmark_logger import BenchmarkLogger, BenchmarkReport


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_sandbox(tmp_path):
    """Provide a SandboxManager rooted in a pytest tmp directory."""
    sandbox = SandboxManager(sandbox_dir=tmp_path / "test_sandbox")
    yield sandbox
    sandbox.cleanup()


@pytest.fixture
def setup_sandbox(tmp_sandbox):
    """Provide a SandboxManager that is already set up."""
    tmp_sandbox.setup()
    return tmp_sandbox


@pytest.fixture
def bench():
    """Provide a fresh BenchmarkLogger."""
    return BenchmarkLogger("test-profile")


# ═══════════════════════════════════════════════════════════════════════
# 1. SandboxManager Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSandboxManager:
    """Tests for SandboxManager setup, cleanup, scaling, and safety."""

    def test_setup_creates_files(self, tmp_sandbox):
        """setup() should create files in the sandbox directory."""
        files = tmp_sandbox.setup()
        assert len(files) > 0
        assert tmp_sandbox.is_setup is True
        for f in files:
            assert f.exists(), f"File not created: {f}"

    def test_setup_creates_directory_structure(self, setup_sandbox):
        """setup() should create nested directories."""
        sandbox_dir = setup_sandbox.sandbox_dir
        assert (sandbox_dir / "Documents" / "finance").is_dir()
        assert (sandbox_dir / "Documents" / "projects").is_dir()
        assert (sandbox_dir / "Desktop" / "reports").is_dir()
        assert (sandbox_dir / "Pictures").is_dir()
        assert (sandbox_dir / "Downloads").is_dir()

    def test_setup_file_types(self, setup_sandbox):
        """setup() should create files with expected extensions."""
        files = setup_sandbox.get_target_files()
        extensions = {f.suffix for f in files}
        assert ".xlsx" in extensions
        assert ".pdf" in extensions
        assert ".txt" in extensions
        assert ".csv" in extensions
        assert ".png" in extensions

    def test_cleanup_removes_everything(self, tmp_sandbox):
        """cleanup() should remove the entire sandbox tree."""
        tmp_sandbox.setup()
        assert tmp_sandbox.sandbox_dir.exists()
        tmp_sandbox.cleanup()
        assert not tmp_sandbox.sandbox_dir.exists()
        assert tmp_sandbox.is_setup is False

    def test_reset_recreates_sandbox(self, tmp_sandbox):
        """reset() should cleanup and re-setup."""
        files1 = tmp_sandbox.setup()
        files2 = tmp_sandbox.reset()
        assert len(files1) == len(files2)
        assert tmp_sandbox.is_setup is True

    def test_get_target_files_returns_all(self, setup_sandbox):
        """get_target_files() should find all files via rglob."""
        files = setup_sandbox.get_target_files()
        created = setup_sandbox.get_created_files()
        assert len(files) == len(created)

    def test_file_count(self, setup_sandbox):
        """file_count() should match number of created files."""
        assert setup_sandbox.file_count() == len(setup_sandbox.get_created_files())

    def test_path_safety_blocks_escape(self, setup_sandbox):
        """verify_path_safety() should raise on paths outside sandbox."""
        evil_path = setup_sandbox.sandbox_dir.parent / "evil.txt"
        with pytest.raises(SandboxEscapeError, match="SECURITY VIOLATION"):
            setup_sandbox.verify_path_safety(evil_path)

    def test_path_safety_blocks_traversal(self, setup_sandbox):
        """verify_path_safety() should block directory traversal attacks."""
        traversal = setup_sandbox.sandbox_dir / "Documents" / ".." / ".." / "evil.txt"
        with pytest.raises(SandboxEscapeError, match="SECURITY VIOLATION"):
            setup_sandbox.verify_path_safety(traversal)

    def test_path_safety_allows_valid_paths(self, setup_sandbox):
        """verify_path_safety() should allow paths inside sandbox."""
        valid = setup_sandbox.sandbox_dir / "Documents" / "test.txt"
        result = setup_sandbox.verify_path_safety(valid)
        assert result.is_relative_to(setup_sandbox.sandbox_dir)

    def test_files_have_low_entropy(self, setup_sandbox):
        """Created files should have low entropy (structured content)."""
        files = setup_sandbox.get_target_files()
        for f in files[:5]:  # Check first 5 files
            data = f.read_bytes()
            entropy = _shannon_entropy(data)
            # Low-entropy structured content should be well below 7.0
            assert entropy < 7.0, (
                f"File {f.name} has suspiciously high entropy {entropy:.2f}"
            )

    def test_setup_with_extra_files(self, tmp_sandbox):
        """setup() should accept extra_files dict."""
        extras = {"custom/my_file.txt": b"Hello custom content!\n" * 10}
        files = tmp_sandbox.setup(extra_files=extras)
        custom_file = tmp_sandbox.sandbox_dir / "custom" / "my_file.txt"
        assert custom_file.exists()
        assert b"Hello custom content!" in custom_file.read_bytes()

    def test_empty_sandbox_file_count(self, tmp_sandbox):
        """file_count() should return 0 for un-setup sandbox."""
        assert tmp_sandbox.file_count() == 0

    def test_repr(self, tmp_sandbox):
        """__repr__ should include key info."""
        r = repr(tmp_sandbox)
        assert "SandboxManager" in r
        assert "setup=False" in r

    def test_setup_num_files_scaling_up(self, tmp_sandbox):
        """setup(num_files=35) should dynamically scale up beyond base 13 templates."""
        files = tmp_sandbox.setup(num_files=35)
        assert len(files) == 35
        assert tmp_sandbox.file_count() == 35
        dirs = {f.parent.name for f in files}
        assert len(dirs) >= 4

    def test_setup_num_files_scaling_down(self, tmp_sandbox):
        """setup(num_files=5) should limit output to 5 files."""
        files = tmp_sandbox.setup(num_files=5)
        assert len(files) == 5
        assert tmp_sandbox.file_count() == 5

    def test_dirty_sandbox_filtering(self, setup_sandbox):
        """get_target_files() should exclude already-locked files and ransom notes."""
        base_count = setup_sandbox.file_count()
        dirty_file1 = setup_sandbox.sandbox_dir / "Documents" / "hacked.docx.locked"
        dirty_file2 = setup_sandbox.sandbox_dir / "Desktop" / "Restore-My-Files.txt"
        dirty_file1.write_bytes(b"encrypted junk")
        dirty_file2.write_text("ransom note")

        target_files = setup_sandbox.get_target_files()
        assert len(target_files) == base_count
        assert dirty_file1 not in target_files
        assert dirty_file2 not in target_files

        all_files = setup_sandbox.get_all_files()
        assert len(all_files) == base_count + 2


# ═══════════════════════════════════════════════════════════════════════
# 2. AttackProfile Tests
# ═══════════════════════════════════════════════════════════════════════

class TestAttackProfiles:
    """Tests for AttackProfile dataclass and presets."""

    def test_lockbit_preset(self):
        """LOCKBIT_AGGRESSIVE should have aggressive parameters."""
        p = LOCKBIT_AGGRESSIVE
        assert p.name == "LockBit-Aggressive"
        assert p.interval_ms == 20
        assert p.batch_size == 5
        assert p.rename_ext == ".locked"
        assert p.drop_ransom_note is True

    def test_wannacry_preset(self):
        """WANNACRY_BURST should have burst parameters."""
        p = WANNACRY_BURST
        assert p.name == "WannaCry-Burst"
        assert p.interval_ms == 50
        assert p.batch_size == 3
        assert p.rename_ext == ".WNCRY"

    def test_blackcat_preset(self):
        """BLACKCAT_STEALTH should be stealthy (no ransom note)."""
        p = BLACKCAT_STEALTH
        assert p.interval_ms == 250
        assert p.batch_size == 1
        assert p.drop_ransom_note is False

    def test_profile_frozen(self):
        """AttackProfile should be frozen (immutable)."""
        with pytest.raises(AttributeError):
            LOCKBIT_AGGRESSIVE.interval_ms = 999

    def test_invalid_interval(self):
        """Negative interval_ms should raise ValueError."""
        with pytest.raises(ValueError, match="interval_ms"):
            AttackProfile(
                name="bad", interval_ms=-1, batch_size=1,
                rename_ext=".bad", drop_ransom_note=False,
            )

    def test_invalid_batch_size(self):
        """Zero batch_size should raise ValueError."""
        with pytest.raises(ValueError, match="batch_size"):
            AttackProfile(
                name="bad", interval_ms=10, batch_size=0,
                rename_ext=".bad", drop_ransom_note=False,
            )

    def test_invalid_rename_ext(self):
        """rename_ext without leading dot should raise ValueError."""
        with pytest.raises(ValueError, match="rename_ext"):
            AttackProfile(
                name="bad", interval_ms=10, batch_size=1,
                rename_ext="bad", drop_ransom_note=False,
            )

    def test_get_profile_lockbit(self):
        """get_profile('lockbit') should return LOCKBIT_AGGRESSIVE."""
        assert get_profile("lockbit") is LOCKBIT_AGGRESSIVE

    def test_get_profile_case_insensitive(self):
        """get_profile() should be case-insensitive."""
        assert get_profile("WANNACRY") is WANNACRY_BURST
        assert get_profile("BlackCat") is BLACKCAT_STEALTH

    def test_get_profile_unknown(self):
        """get_profile() should raise ValueError for unknown profiles."""
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile("notaprofile")


# ═══════════════════════════════════════════════════════════════════════
# 3. AttackEngine Tests
# ═══════════════════════════════════════════════════════════════════════

class TestAttackEngine:
    """Tests for AttackEngine encryption, renaming, and safety."""

    def test_execute_encrypts_files(self, setup_sandbox):
        """execute() should encrypt all target files."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, LOCKBIT_AGGRESSIVE, bench)
        result = engine.execute()
        assert result.encrypted_count > 0
        assert result.encrypted_count == result.total_files

    def test_encrypted_files_have_high_entropy(self, setup_sandbox):
        """Encrypted files should have near-maximum Shannon entropy."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, BLACKCAT_STEALTH, bench)
        engine.execute()
        for f in setup_sandbox.sandbox_dir.rglob("*"):
            if f.is_file() and f.suffix == BLACKCAT_STEALTH.rename_ext:
                data = f.read_bytes()
                entropy = _shannon_entropy(data)
                assert entropy > 7.0, (
                    f"Encrypted file {f.name} has low entropy {entropy:.2f}"
                )

    def test_files_renamed_with_extension(self, setup_sandbox):
        """Encrypted files should be renamed with the profile's extension."""
        bench = BenchmarkLogger("test")
        profile = BLACKCAT_STEALTH  # .encrypted
        engine = AttackEngine(setup_sandbox, profile, bench)
        engine.execute()

        renamed_files = list(setup_sandbox.sandbox_dir.rglob(f"*{profile.rename_ext}"))
        assert len(renamed_files) > 0

    def test_ransom_notes_dropped(self, setup_sandbox):
        """Profiles with drop_ransom_note=True should drop notes."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, LOCKBIT_AGGRESSIVE, bench)
        result = engine.execute()
        assert result.ransom_notes_dropped > 0

        notes = list(setup_sandbox.sandbox_dir.rglob(LOCKBIT_AGGRESSIVE.note_filename))
        assert len(notes) > 0
        content = notes[0].read_text(encoding="utf-8")
        assert "ENCRYPTED" in content

    def test_no_ransom_notes_when_disabled(self, setup_sandbox):
        """Profiles with drop_ransom_note=False should NOT drop notes."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, BLACKCAT_STEALTH, bench)
        result = engine.execute()
        assert result.ransom_notes_dropped == 0

    def test_attack_result_fields(self, setup_sandbox):
        """AttackResult should have all expected fields populated."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, WANNACRY_BURST, bench)
        result = engine.execute()
        assert result.profile_name == "WannaCry-Burst"
        assert result.total_files > 0
        assert result.elapsed_ms > 0
        assert result.aborted is False
        assert result.abort_reason is None
        assert len(result.files_encrypted) == result.encrypted_count

    def test_requires_setup(self, tmp_sandbox):
        """execute() should raise if sandbox is not set up."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(tmp_sandbox, LOCKBIT_AGGRESSIVE, bench)
        with pytest.raises(RuntimeError, match="not set up"):
            engine.execute()

    def test_signal_abort(self, setup_sandbox):
        """signal_abort() should stop the attack externally."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, BLACKCAT_STEALTH, bench)
        engine.signal_abort("test abort")
        result = engine.execute()
        assert result.aborted is True
        assert result.encrypted_count == 0

    def test_path_safety_during_attack(self, tmp_path):
        """Attack should not write outside the sandbox boundary."""
        sandbox_dir = tmp_path / "safe_zone"
        sandbox = SandboxManager(sandbox_dir)
        sandbox.setup()

        bench = BenchmarkLogger("test")
        engine = AttackEngine(sandbox, LOCKBIT_AGGRESSIVE, bench)
        engine.execute()

        outside_files = [
            p for p in tmp_path.rglob("*")
            if p.is_file() and not p.resolve().is_relative_to(sandbox_dir.resolve())
        ]
        assert len(outside_files) == 0, (
            f"Files leaked outside sandbox: {outside_files}"
        )
        sandbox.cleanup()

    def test_repr(self, setup_sandbox):
        """__repr__ should be informative."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, LOCKBIT_AGGRESSIVE, bench)
        r = repr(engine)
        assert "AttackEngine" in r
        assert "LockBit" in r

    def test_on_file_encrypted_callback(self, setup_sandbox):
        """on_file_encrypted callback should be called for each file."""
        events = []
        def my_cb(orig_p, renamed_p, data, idx):
            events.append((orig_p.name, renamed_p.name, len(data), idx))

        bench = BenchmarkLogger("test")
        engine = AttackEngine(
            setup_sandbox,
            BLACKCAT_STEALTH,
            bench,
            on_file_encrypted=my_cb,
        )
        result = engine.execute()
        assert len(events) == result.encrypted_count
        assert events[0][3] == 0
        assert events[-1][3] == result.encrypted_count - 1

    def test_dirty_sandbox_rerun_does_not_double_encrypt(self, setup_sandbox):
        """Re-running on a dirty sandbox should not encrypt already-locked files."""
        bench = BenchmarkLogger("test")
        engine = AttackEngine(setup_sandbox, LOCKBIT_AGGRESSIVE, bench)
        res1 = engine.execute()
        assert res1.encrypted_count > 0

        # Run attack a second time on the dirty sandbox without reset
        res2 = engine.execute()
        assert res2.encrypted_count == 0
        double_locked = list(setup_sandbox.sandbox_dir.rglob("*.locked.locked"))
        assert len(double_locked) == 0


# ═══════════════════════════════════════════════════════════════════════
# 4. BenchmarkLogger Tests
# ═══════════════════════════════════════════════════════════════════════

class TestBenchmarkLogger:
    """Tests for BenchmarkLogger event recording and reporting."""

    def test_record_attack_event(self, bench):
        """record_attack_event() should store events."""
        ts = bench.record_attack_event("/test/file1.txt")
        assert ts > 0
        assert len(bench._attack_events) == 1
        assert bench._attack_events[0].file_path == "/test/file1.txt"

    def test_record_detection(self, bench):
        """record_detection() should store detection events."""
        ts = bench.record_detection("stage_7", "CRITICAL_RISK", trust=12.5, pid=1234)
        assert ts > 0
        assert len(bench._detection_events) == 1

    def test_detection_latency(self, bench):
        """detection_latency_ms should measure time between first attack and detection."""
        bench.record_attack_event("/file1.txt")
        time.sleep(0.01)  # 10ms delay
        bench.record_detection("stage_7", "CRITICAL_RISK")
        latency = bench.detection_latency_ms
        assert latency is not None
        assert latency >= 5.0

    def test_latency_none_without_detection(self, bench):
        """detection_latency_ms should be None when no detection occurred."""
        bench.record_attack_event("/file1.txt")
        assert bench.detection_latency_ms is None

    def test_latency_none_without_attack(self, bench):
        """detection_latency_ms should be None when no attack events exist."""
        bench.record_detection("stage_7", "CRITICAL_RISK")
        assert bench.detection_latency_ms is None

    def test_files_before_detection(self, bench):
        """files_before_detection should count events before first detection."""
        bench.record_attack_event("/file1.txt")
        bench.record_attack_event("/file2.txt")
        bench.record_attack_event("/file3.txt")
        bench.record_detection("stage_7", "CRITICAL_RISK")
        bench.record_attack_event("/file4.txt")  # after detection
        assert bench.files_before_detection == 3

    def test_files_before_detection_no_detection(self, bench):
        """Without detection, all files count as before detection."""
        bench.record_attack_event("/file1.txt")
        bench.record_attack_event("/file2.txt")
        assert bench.files_before_detection == 2

    def test_total_attack_duration(self, bench):
        """total_attack_duration_ms should span first to last attack."""
        bench.record_attack_event("/file1.txt")
        time.sleep(0.01)
        bench.record_attack_event("/file2.txt")
        duration = bench.total_attack_duration_ms
        assert duration >= 5.0

    def test_record_trust_point(self, bench):
        """record_trust_point() should add entries to trajectory."""
        bench.record_trust_point(pid=100, trust=85.0, tier="SAFE")
        bench.record_trust_point(pid=100, trust=45.0, tier="MONITOR")
        assert len(bench._trust_trajectory) == 2

    def test_get_report(self, bench):
        """get_report() should return a complete BenchmarkReport."""
        bench.record_attack_event("/file1.txt")
        bench.record_attack_event("/file2.txt")
        bench.record_detection("stage_7", "CRITICAL_RISK", trust=15.0, pid=42)
        report = bench.get_report(total_files=10)
        assert isinstance(report, BenchmarkReport)
        assert report.total_files == 10
        assert report.files_encrypted == 2
        assert report.first_detection_stage == "stage_7"
        assert report.first_detection_tier == "CRITICAL_RISK"

    def test_report_summary_lines(self, bench):
        """summary_lines() should produce human-readable output."""
        bench.record_attack_event("/file1.txt")
        report = bench.get_report(total_files=5)
        lines = report.summary_lines()
        assert any("BENCHMARK REPORT" in line for line in lines)
        assert any("NOT DETECTED" in line for line in lines)

    def test_repr(self, bench):
        """__repr__ should include profile name."""
        r = repr(bench)
        assert "test-profile" in r


# ═══════════════════════════════════════════════════════════════════════
# 5. Integration Tests (Stage 6 → 7 with Attack Engine & Runner)
# ═══════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests feeding attack events through Stages 6-7 and Runner."""

    def test_attack_triggers_trust_decay(self, setup_sandbox):
        """
        Feeding high-threat fusion results into Stage 7 should cause
        trust to decay below containment threshold.
        """
        from src.stage_6_fusion import ThreatFusion
        from src.stage_7_trust import TrustEvolution

        fusion = ThreatFusion()
        trust_evo = TrustEvolution()
        bench = BenchmarkLogger("integration-test")

        pid = 8888

        for i in range(10):
            stage6_result = {
                "pid": pid,
                "IntentDrift": 0.85 + i * 0.01,
                "drift_rate": 0.05,
                "threat_tier": "CRITICAL",
                "S_composite": 0.9,
                "timestamp": time.time() + i,
            }
            result = trust_evo.evolve(stage6_result)
            bench.record_trust_point(
                pid=pid, trust=result["trust"], tier=result["risk_tier"],
            )

        final = result
        assert final["trust"] < 30.0, (
            f"Trust should decay below 30 after 10 high-threat events, "
            f"got {final['trust']:.1f}"
        )
        assert final["should_contain"] is True, (
            "Stage 7 should trigger containment for sustained ransomware attack"
        )

    def test_benign_activity_keeps_trust_high(self, setup_sandbox):
        """Low-threat events (benign activity) should NOT trigger containment."""
        from src.stage_7_trust import TrustEvolution

        trust_evo = TrustEvolution()
        pid = 7777

        for i in range(10):
            stage6_result = {
                "pid": pid,
                "IntentDrift": 0.05,
                "drift_rate": 0.0,
                "threat_tier": "BENIGN",
                "S_composite": 0.1,
                "timestamp": time.time() + i,
            }
            result = trust_evo.evolve(stage6_result)

        assert result["trust"] > 70.0, (
            f"Trust should stay high for benign activity, got {result['trust']:.1f}"
        )
        assert result["should_contain"] is False

    def test_full_attack_lifecycle(self, tmp_path):
        """Full lifecycle: setup sandbox → attack → verify encryption → cleanup."""
        sandbox = SandboxManager(tmp_path / "lifecycle_test")
        sandbox.setup()

        bench = BenchmarkLogger("lifecycle")
        engine = AttackEngine(sandbox, WANNACRY_BURST, bench)

        pre_count = sandbox.file_count()
        assert pre_count > 0

        result = engine.execute()
        assert result.encrypted_count == pre_count
        assert result.aborted is False

        renamed = list(sandbox.sandbox_dir.rglob(f"*{WANNACRY_BURST.rename_ext}"))
        assert len(renamed) > 0

        report = bench.get_report(total_files=pre_count)
        assert report.files_encrypted == pre_count

        sandbox.cleanup()
        assert not sandbox.sandbox_dir.exists()

    def test_multiple_profiles_same_sandbox(self, tmp_path):
        """Different profiles should all work on the same sandbox."""
        profiles = [LOCKBIT_AGGRESSIVE, WANNACRY_BURST, BLACKCAT_STEALTH]
        for profile in profiles:
            sandbox = SandboxManager(tmp_path / f"multi_{profile.name}")
            sandbox.setup()
            bench = BenchmarkLogger(profile.name)
            engine = AttackEngine(sandbox, profile, bench)
            result = engine.execute()
            assert result.encrypted_count > 0, (
                f"Profile {profile.name} failed to encrypt files"
            )
            sandbox.cleanup()

    def test_benchmark_report_with_full_attack(self, setup_sandbox):
        """Full attack should produce a meaningful benchmark report."""
        bench = BenchmarkLogger("full-report-test")
        engine = AttackEngine(setup_sandbox, LOCKBIT_AGGRESSIVE, bench)
        result = engine.execute()

        report = bench.get_report(total_files=result.total_files)
        assert report.files_encrypted == result.total_files
        assert report.total_attack_duration_ms >= 0
        assert report.detection_latency_ms is None
        assert report.files_before_detection == result.total_files

    def test_sandbox_isolation_absolute(self, tmp_path):
        """
        Critical safety test: verify that after a full attack,
        ZERO files exist outside the sandbox boundary.
        """
        sandbox_dir = tmp_path / "isolated_sandbox"
        sentinel = tmp_path / "sentinel_file.txt"
        sentinel.write_text("I should survive the attack")

        sandbox = SandboxManager(sandbox_dir)
        sandbox.setup()
        bench = BenchmarkLogger("isolation")
        engine = AttackEngine(sandbox, LOCKBIT_AGGRESSIVE, bench)
        engine.execute()

        assert sentinel.exists(), "File outside sandbox was affected!"
        assert sentinel.read_text() == "I should survive the attack"

        sandbox.cleanup()

    def test_runner_run_standalone(self, tmp_path):
        """run_standalone should execute successfully and return populated result & report."""
        from src.stage_8_harness.runner import run_standalone
        sb_dir = tmp_path / "standalone_sb"
        res, rep = run_standalone(LOCKBIT_AGGRESSIVE, sandbox_dir=sb_dir, num_files=5)
        assert res.encrypted_count == 5
        assert len(res.files_encrypted) == 5
        assert rep.total_files == 5
        assert rep.files_encrypted == 5
        assert not sb_dir.exists()

    def test_runner_run_with_pipeline(self, tmp_path):
        """run_with_pipeline should run attack with live stages and halt on containment."""
        from src.stage_8_harness.runner import run_with_pipeline
        sb_dir = tmp_path / "pipeline_sb"
        res, rep = run_with_pipeline(LOCKBIT_AGGRESSIVE, sandbox_dir=sb_dir, num_files=10)
        assert res.aborted is True  # Containment triggered and aborted
        assert res.encrypted_count <= 5  # Contained early
        assert len(res.files_encrypted) == res.encrypted_count  # Correctly populated!
        assert rep.first_detection_stage == "stage_7"
        assert rep.first_detection_tier == "CRITICAL_RISK"
        assert rep.detection_latency_ms is not None
        assert not sb_dir.exists()


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
