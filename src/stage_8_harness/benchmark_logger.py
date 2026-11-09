"""
src/stage_8_harness/benchmark_logger.py
==========================================
Millisecond-precision latency and damage tracker for Stage 8.

Records the timeline of attack events and detection events so that
the runner can compute:
  - detection_latency_ms : time from first malicious write to first detection
  - files_before_detection : how many files were encrypted before detection
  - total_files_encrypted : total files encrypted during the attack
  - trust_trajectory : list of (timestamp, pid, trust, tier) tuples
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AttackEvent:
    """A single file encryption event."""
    file_path: str
    timestamp: float       # time.perf_counter() value
    wall_clock: float      # time.time() value


@dataclass
class DetectionEvent:
    """A detection/alert from the pipeline."""
    stage: str             # e.g. "stage_6", "stage_7"
    tier: str              # e.g. "CRITICAL", "CRITICAL_RISK"
    trust: Optional[float]
    pid: int
    timestamp: float       # time.perf_counter() value
    wall_clock: float


@dataclass
class BenchmarkReport:
    """Final report summarizing attack vs. detection performance."""
    profile_name: str
    total_files: int
    files_encrypted: int
    files_before_detection: int
    detection_latency_ms: Optional[float]     # None if never detected
    total_attack_duration_ms: float
    first_detection_stage: Optional[str]
    first_detection_tier: Optional[str]
    trust_trajectory: List[Dict[str, Any]]
    attack_events: List[Dict[str, Any]]

    def summary_lines(self) -> List[str]:
        """Return a human-readable summary as a list of lines."""
        lines = [
            "=" * 65,
            f"  BENCHMARK REPORT — {self.profile_name}",
            "=" * 65,
            f"  Total victim files        : {self.total_files}",
            f"  Files encrypted           : {self.files_encrypted}",
            f"  Files before detection     : {self.files_before_detection}",
            f"  Detection latency         : "
            + (f"{self.detection_latency_ms:.1f} ms" if self.detection_latency_ms is not None else "NOT DETECTED"),
            f"  Attack duration           : {self.total_attack_duration_ms:.1f} ms",
            f"  First detection stage     : {self.first_detection_stage or 'N/A'}",
            f"  First detection tier      : {self.first_detection_tier or 'N/A'}",
            f"  Trust trajectory points   : {len(self.trust_trajectory)}",
            "=" * 65,
        ]
        return lines

    def print_report(self) -> None:
        """Print the benchmark report to stdout."""
        for line in self.summary_lines():
            print(line)


class BenchmarkLogger:
    """
    Records attack and detection events with perf_counter precision.

    Usage
    -----
    >>> bl = BenchmarkLogger("LockBit-Aggressive")
    >>> bl.record_attack_event("/sandbox/file1.docx")
    >>> bl.record_detection("stage_7", "CRITICAL_RISK", trust=12.3, pid=1234)
    >>> report = bl.get_report(total_files=50)
    """

    def __init__(self, profile_name: str = "unknown") -> None:
        self.profile_name = profile_name
        self._attack_events: List[AttackEvent] = []
        self._detection_events: List[DetectionEvent] = []
        self._trust_trajectory: List[Dict[str, Any]] = []

    # ── Recording ────────────────────────────────────────────────────

    def record_attack_event(self, file_path: str) -> float:
        """
        Record that a file was encrypted. Returns the perf_counter timestamp.
        """
        ts = time.perf_counter()
        wc = time.time()
        self._attack_events.append(AttackEvent(
            file_path=str(file_path),
            timestamp=ts,
            wall_clock=wc,
        ))
        logger.debug("Attack event: %s at %.6f", file_path, ts)
        return ts

    def record_detection(
        self,
        stage: str,
        tier: str,
        trust: Optional[float] = None,
        pid: int = -1,
    ) -> float:
        """
        Record a detection/alert event. Returns the perf_counter timestamp.
        """
        ts = time.perf_counter()
        wc = time.time()
        self._detection_events.append(DetectionEvent(
            stage=stage,
            tier=tier,
            trust=trust,
            pid=pid,
            timestamp=ts,
            wall_clock=wc,
        ))
        logger.debug(
            "Detection event: stage=%s tier=%s trust=%s pid=%d at %.6f",
            stage, tier, trust, pid, ts,
        )
        return ts

    def record_trust_point(
        self,
        pid: int,
        trust: float,
        tier: str,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record a trust trajectory data point for reporting."""
        self._trust_trajectory.append({
            "pid": pid,
            "trust": trust,
            "tier": tier,
            "timestamp": timestamp or time.perf_counter(),
        })

    # ── Computed Metrics ─────────────────────────────────────────────

    @property
    def first_attack_time(self) -> Optional[float]:
        """perf_counter of the first attack event, or None."""
        return self._attack_events[0].timestamp if self._attack_events else None

    @property
    def last_attack_time(self) -> Optional[float]:
        """perf_counter of the last attack event, or None."""
        return self._attack_events[-1].timestamp if self._attack_events else None

    @property
    def first_detection_time(self) -> Optional[float]:
        """perf_counter of the first detection event, or None."""
        return self._detection_events[0].timestamp if self._detection_events else None

    @property
    def detection_latency_ms(self) -> Optional[float]:
        """
        Milliseconds from the first malicious write to the first detection.
        Returns None if either event is missing.
        """
        t0 = self.first_attack_time
        t1 = self.first_detection_time
        if t0 is None or t1 is None:
            return None
        return max(0.0, (t1 - t0) * 1000.0)

    @property
    def files_before_detection(self) -> int:
        """Number of files encrypted before the first detection event."""
        t_detect = self.first_detection_time
        if t_detect is None:
            return len(self._attack_events)
        return sum(1 for e in self._attack_events if e.timestamp < t_detect)

    @property
    def total_attack_duration_ms(self) -> float:
        """Total duration of the attack in milliseconds."""
        t0 = self.first_attack_time
        t1 = self.last_attack_time
        if t0 is None or t1 is None:
            return 0.0
        return (t1 - t0) * 1000.0

    # ── Report ───────────────────────────────────────────────────────

    def get_report(self, total_files: int) -> BenchmarkReport:
        """Build the final benchmark report."""
        first_det = self._detection_events[0] if self._detection_events else None
        return BenchmarkReport(
            profile_name=self.profile_name,
            total_files=total_files,
            files_encrypted=len(self._attack_events),
            files_before_detection=self.files_before_detection,
            detection_latency_ms=self.detection_latency_ms,
            total_attack_duration_ms=self.total_attack_duration_ms,
            first_detection_stage=first_det.stage if first_det else None,
            first_detection_tier=first_det.tier if first_det else None,
            trust_trajectory=list(self._trust_trajectory),
            attack_events=[
                {"file": e.file_path, "timestamp": e.wall_clock}
                for e in self._attack_events
            ],
        )

    def __repr__(self) -> str:
        return (
            f"BenchmarkLogger(profile='{self.profile_name}', "
            f"attacks={len(self._attack_events)}, "
            f"detections={len(self._detection_events)})"
        )
