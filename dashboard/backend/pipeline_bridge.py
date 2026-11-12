"""
dashboard/backend/pipeline_bridge.py
=======================================
Bridges existing Stages 1-10 Python modules to WebSocket and REST output.

This is integration glue — all underlying stage logic stays untouched.
The bridge wraps:
  - Stage 1: FileMonitor / ProcessMonitor / QueueJoiner
  - Stage 2: RarityEngine (parent-child S_rel scoring)
  - Stage 3: DBRGManager (Time-Decaying Edge Weight graph)
  - Stage 4: FeatureExtractor
  - Stage 5: AnomalyScorer (IF + OC-SVM)
  - Stage 6: ThreatFusion (IntentDrift & threat tier)
  - Stage 7: TrustEvolution (adaptive trust decay & risk state machine)
  - Stage 8: AttackEngine / SandboxManager (on-demand simulated attacks)
  - Stage 9: ContainmentEngine (Edmonds-Karp min-cut + process freeze)
  - Stage 10: Enforcer (write-ahead JournalVault + ACLs + selective rollback)
"""

import asyncio
import hashlib
import json
import logging
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.file_monitor import FileMonitor
from collector.process_monitor import ProcessMonitor
from collector.queue_joiner import QueueJoiner
from lineage.rarity_engine import RarityEngine
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_4_features.feature_extractor import FeatureExtractor
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer
from src.stage_6_fusion.threat_fusion import ThreatFusion
from src.stage_7_trust import TrustEvolution
from src.stage_9_containment import ContainmentEngine
from src.stage_10_enforcer import Enforcer, JournalVault, Verdict

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class PipelineBridge:
    """
    Runs the full Stages 1-10 pipeline in background threads and broadcasts
    results to WebSocket clients via the WebSocketManager.

    Parameters
    ----------
    watch_paths : list of str
        Directories to monitor for file I/O events.
    ws_manager : WebSocketManager
        The WebSocket connection pool to broadcast events to.
    """

    def __init__(self, watch_paths: List[str], ws_manager):
        self.ws_manager = ws_manager
        self.watch_paths = watch_paths

        # ── Stage 2: Lineage Rarity Engine ──
        try:
            self.rarity: Optional[RarityEngine] = RarityEngine()
        except Exception:
            self.rarity = None

        # ── Stage 3: DBRG Graph ──
        self.dbrg = DBRGManager(decay_lambda=0.01)

        # ── Stage 4: Feature Extraction ──
        self.extractor = FeatureExtractor(dbrg_manager=self.dbrg)

        # ── Stage 5: Anomaly Scoring ──
        self.scorer = AnomalyScorer(
            model_dir=str(PROJECT_ROOT / "models")
        )

        # ── Stage 6: Threat Fusion ──
        self.fusion = ThreatFusion()

        # ── Stage 7: Trust State Evolution ──
        self.trust_evolution = TrustEvolution()

        # ── Stage 9: Kernel Containment (dry_run=True for OS safety) ──
        self.containment_engine = ContainmentEngine(dry_run=True)

        # ── Stage 10: Enforcement & Rollback ──
        # Dedicated session-scoped vault avoids cross-run pollution with CLI/pytest
        self._vault_dir = os.path.join(
            tempfile.gettempdir(), f"ards_dashboard_vault_{os.getpid()}"
        )
        self.vault = JournalVault(vault_dir=self._vault_dir)
        self.enforcer = Enforcer(
            containment_engine=self.containment_engine,
            trust_evolution=self.trust_evolution,
            vault=self.vault,
            dry_run=True,
            always_on=True,
            rollback_dry_run=False,
        )

        # Track containment, attacks, and resolutions
        self._contained_pids: Dict[int, Dict[str, Any]] = {}
        self._pending_resolutions: Dict[int, Dict[str, Any]] = {}
        self._attack_sessions: Dict[str, Dict[str, Any]] = {}
        self._pid_to_attack_id: Dict[int, str] = {}
        self._resolution_history: List[Dict[str, Any]] = []
        self._attack_counter = 0

        # ── Stage 1: Telemetry Collection ──
        self.raw_queue = queue.Queue(maxsize=10000)
        self.file_monitor = FileMonitor(paths=watch_paths, recursive=True)
        self.process_monitor = ProcessMonitor(
            poll_interval_sec=1.0, hash_timeout_sec=2.0
        )
        self.queue_joiner = None

        # Internal state
        self._event_count = 0
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

        # Recent events buffer for REST API queries
        self._recent_events: List[Dict[str, Any]] = []
        self._max_recent = 50

    def _broadcast(self, payload: Dict[str, Any]) -> None:
        """Broadcast a JSON payload to all connected WebSocket clients."""
        if self._loop and self.ws_manager.client_count > 0:
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast(json.dumps(payload, default=str)),
                self._loop,
            )

    def _compute_s_rel(self, ecar_event: dict, fv: dict) -> float:
        """Compute Stage 2 lineage rarity score S_rel if RarityEngine is available."""
        if self.rarity is None:
            return float(fv.get("S_rel", 0.0))
        context = ecar_event.get("context", {})
        parent = context.get("parent_exe", "")
        child = context.get("exe_path", "")
        if parent and child:
            s_rel = float(self.rarity.calculate_s_rel(parent, child))
            fv["S_rel"] = s_rel
            return s_rel
        return float(fv.get("S_rel", 0.0))

    def _on_ecar_event(self, ecar_event: dict):
        """
        Callback invoked by QueueJoiner for each enriched eCAR event.
        Runs the full Stage 2 → 3 → 4 → 5 → 6 → 7 → 9 → 10 pipeline and broadcasts.
        """
        try:
            # ──── Stage 3: Update DBRG graph ────
            self.dbrg.process_event(ecar_event)

            # ──── Stage 4: Extract feature vector ────
            fv = self.extractor.extract_features(ecar_event)
            if fv is None:
                return

            # ──── Stage 2: Populate Rarity score before Fusion ────
            self._compute_s_rel(ecar_event, fv)

            # ──── Stage 5: Anomaly scoring ────
            anomaly_result = self.scorer.score(fv)

            # ──── Stage 6: Threat fusion ────
            fusion_result = self.fusion.fuse(fv, anomaly_result)

            # ──── Stage 7 → 9 → 10: Trust evolution & containment ────
            trust_result = None
            contain_record = None
            enforce_record = None
            try:
                pid = ecar_event.get("pid", -1)
                fusion_result_for_trust = dict(fusion_result)
                fusion_result_for_trust["pid"] = pid
                trust_result = self.trust_evolution.evolve(fusion_result_for_trust)
                self.enforcer.on_trust_update(trust_result)

                if trust_result.get("should_contain") and pid not in self._contained_pids:
                    contain_record = self.containment_engine.contain(
                        pid=pid,
                        dbrg_graph=self.dbrg.get_graph_snapshot(),
                        trust_state=trust_result,
                    )
                    enforce_record = self.enforcer.enforce(contain_record)
                    context = ecar_event.get("context", {})
                    exe_name = os.path.basename(context.get("exe_path", "UNKNOWN"))
                    info = {
                        "pid": pid,
                        "exe_name": exe_name,
                        "status": "PENDING_RESOLUTION",
                        "trust": round(trust_result["trust"], 2),
                        "risk_tier": trust_result["risk_tier"],
                        "cut_edges": len(contain_record.cut_edges),
                        "cut_value": round(contain_record.cut_value, 2),
                        "isolated_files": len(contain_record.isolated_files),
                        "acl_revoked": len(enforce_record.acl_records) if enforce_record else 0,
                        "latency_ms": round(contain_record.latency_ms, 3),
                        "process_state": self.containment_engine.freezer.get_state(pid).value,
                        "timestamp": time.time(),
                    }
                    with self._lock:
                        self._contained_pids[pid] = {
                            **info,
                            "contain_record": contain_record,
                            "enforce_record": enforce_record,
                        }
                        self._pending_resolutions[pid] = info

                    self._broadcast({
                        "type": "containment_event",
                        "data": info,
                        "server_time": time.time(),
                    })
            except Exception as e:
                logger.debug("[PipelineBridge] Stage 7-10 processing error: %s", e)

            with self._lock:
                self._event_count += 1
                event_id = self._event_count

            # ──── Build per-stage WebSocket message ────
            ws_message = self._build_ws_message(
                event_id,
                ecar_event,
                fv,
                anomaly_result,
                fusion_result,
                trust_result=trust_result,
                contain_record=contain_record,
                enforce_record=enforce_record,
            )

            # Store in recent buffer
            with self._lock:
                self._recent_events.insert(0, ws_message)
                if len(self._recent_events) > self._max_recent:
                    self._recent_events = self._recent_events[:self._max_recent]

            # Push to all connected browser clients
            self._broadcast(ws_message)

        except Exception as e:
            logger.debug("[PipelineBridge] Event processing error: %s", e)

    def _build_ws_message(
        self,
        event_id: int,
        ecar: dict,
        fv: dict,
        anomaly: dict,
        fusion: dict,
        trust_result: Optional[dict] = None,
        contain_record=None,
        enforce_record=None,
    ) -> Dict[str, Any]:
        """Build a structured WebSocket message with all stage data."""
        context = ecar.get("context", {})
        file_path_raw = ecar.get("objectID", "")
        file_path = file_path_raw[5:] if file_path_raw.startswith("file:") else file_path_raw
        pid = ecar.get("pid", -1)

        vault_stats = self.vault.stats()

        return {
            "type": "pipeline_event",
            "event_id": event_id,
            "server_time": time.time(),

            # ── Stage 1: Raw telemetry ──
            "stage_1": {
                "pid": pid,
                "operation": ecar.get("operation", ""),
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "exe_path": context.get("exe_path", "UNKNOWN"),
                "exe_name": os.path.basename(context.get("exe_path", "UNKNOWN")),
                "principal": ecar.get("principal", ""),
                "timestamp_ms": ecar.get("timestamp", 0),
                "sha256": context.get("sha256", ""),
            },

            # ── Stage 2: Lineage ──
            "stage_2": {
                "ppid": context.get("ppid", -1),
                "parent_exe": context.get("parent_exe", ""),
                "parent_exe_name": os.path.basename(
                    context.get("parent_exe", "UNKNOWN")
                ),
                "S_rel": fv.get("S_rel", 0.0),
            },

            # ── Stage 3: DBRG graph summary ──
            "stage_3": {
                "graph_nodes": self.dbrg.get_node_count(),
                "graph_edges": self.dbrg.get_edge_count(),
                "events_processed": self.dbrg.events_processed,
            },

            # ── Stage 4: Feature vector ──
            "stage_4": {
                "S_entropy": fv.get("S_entropy", 0.0),
                "S_ETD": fv.get("S_ETD", 0.0),
                "S_dist": fv.get("S_dist", 0.0),
                "S_dev": fv.get("S_dev", 0.0),
                "S_stab": fv.get("S_stab", 0.0),
                "lambda_norm": fv.get("lambda_norm", 0.0),
                "branching_n": fv.get("branching_n", 0.0),
                "is_superheated": fv.get("is_superheated", False),
                "entropy_raw": fv.get("entropy_raw", 0.0),
                "hist_variance": fv.get("hist_variance", 0.0),
                "hist_kurtosis": fv.get("hist_kurtosis", 0.0),
            },

            # ── Stage 5: Anomaly scoring ──
            "stage_5": {
                "anomaly_score": anomaly.get("anomaly_score", 0.0),
                "isolation_score": anomaly.get("isolation_score"),
                "svm_score": anomaly.get("svm_score"),
                "confidence": anomaly.get("confidence", 0.0),
                "scoring_mode": anomaly.get("scoring_mode", "heuristic"),
                "risk_tier": anomaly.get("risk_tier", "SAFE"),
                "is_anomaly": anomaly.get("is_anomaly", False),
            },

            # ── Stage 6: Threat fusion ──
            "stage_6": {
                "S_composite": fusion.get("S_composite", 0.0),
                "IntentDrift": fusion.get("IntentDrift", 0.0),
                "drift_rate": fusion.get("drift_rate", 0.0),
                "threat_tier": fusion.get("threat_tier", "BENIGN"),
                "signals": fusion.get("signals", {}),
                "weights": fusion.get("weights", {}),
                "is_first_observation": fusion.get("is_first_observation", True),
            },

            # ── Stage 7: Trust evolution ──
            "stage_7": {
                "trust": round(trust_result.get("trust", 100.0), 2),
                "delta_trust": round(trust_result.get("delta_trust", 0.0), 2),
                "risk_tier": trust_result.get("risk_tier", "SAFE"),
                "should_contain": trust_result.get("should_contain", False),
                "prewarm_journal": trust_result.get("prewarm_journal", False),
                "escalated": trust_result.get("escalated", False),
                "sampling_multiplier": trust_result.get("sampling_multiplier", 1.0),
            } if trust_result else {
                "trust": None,
                "risk_tier": None,
                "should_contain": False,
            },

            # ── Stage 9: Containment ──
            "stage_9": {
                "contained": True,
                "pid": pid,
                "cut_edges": len(contain_record.cut_edges),
                "cut_value": round(contain_record.cut_value, 2),
                "isolated_files": len(contain_record.isolated_files),
                "freeze_latency_ms": round(contain_record.latency_ms, 3),
                "process_state": self.containment_engine.freezer.get_state(pid).value,
            } if contain_record else {"contained": False},

            # ── Stage 10: Enforcement ──
            "stage_10": {
                "enforced": True,
                "acl_revoked": len(enforce_record.acl_records) if enforce_record else 0,
                "vault_snapshots": vault_stats.get("total_snapshots", 0),
                "pending_resolution": True,
            } if enforce_record else {
                "enforced": False,
                "vault_snapshots": vault_stats.get("total_snapshots", 0),
                "pending_resolution": bool(self._pending_resolutions),
            },
        }

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self, loop: asyncio.AbstractEventLoop):
        """Start the live pipeline in background threads."""
        self._loop = loop
        self._running = True

        for p in self.watch_paths:
            Path(p).mkdir(parents=True, exist_ok=True)

        self.process_monitor.start()

        self.queue_joiner = QueueJoiner(
            raw_queue=self.raw_queue,
            process_monitor=self.process_monitor,
            db_writer=None,
            on_event_callback=self._on_ecar_event,
        )

        self.file_monitor.start(self.raw_queue)
        self.queue_joiner.start()

        logger.info(
            "[PipelineBridge] Pipeline started. Watching: %s",
            self.watch_paths,
        )

    def stop(self):
        """Gracefully stop all pipeline threads and clean up temporary state."""
        self._running = False
        try:
            self.file_monitor.stop()
        except Exception:
            pass
        try:
            self.process_monitor.stop()
        except Exception:
            pass
        try:
            if self.queue_joiner:
                self.queue_joiner.stop()
        except Exception:
            pass

        # Clean up any open attack sandboxes
        for session in list(self._attack_sessions.values()):
            sandbox = session.get("sandbox")
            if sandbox is not None:
                try:
                    sandbox.cleanup()
                except Exception:
                    pass
                session["sandbox"] = None

        # Clean up session-scoped vault dir
        try:
            if os.path.exists(self._vault_dir):
                shutil.rmtree(self._vault_dir, ignore_errors=True)
        except Exception:
            pass

        logger.info("[PipelineBridge] Pipeline stopped.")

    # ── REST API Data Providers ──────────────────────────────────────────

    def get_graph_json(self) -> Dict[str, Any]:
        """
        Serialize the DBRG graph for Cytoscape/Canvas rendering in the frontend.
        Returns {nodes: [...], edges: [...]}.
        """
        snapshot = self.dbrg.get_graph_snapshot()
        nodes = []
        for node_id, attrs in snapshot.nodes(data=True):
            node_type = attrs.get("node_type", "unknown")
            if node_type == "process":
                label = os.path.basename(attrs.get("exe_path", "unknown"))
                pid = attrs.get("pid", "?")
                label = f"{label} (PID {pid})"
            else:
                label = os.path.basename(attrs.get("file_path", node_id))

            nodes.append({
                "data": {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "pid": attrs.get("pid"),
                    "exe_path": attrs.get("exe_path"),
                    "file_path": attrs.get("file_path"),
                }
            })

        edges = []
        for src, tgt, attrs in snapshot.edges(data=True):
            edges.append({
                "data": {
                    "id": f"{src}__{tgt}",
                    "source": src,
                    "target": tgt,
                    "weight": round(attrs.get("weight", 1.0), 4),
                    "op_count": attrs.get("op_count", 1),
                    "last_seen": attrs.get("last_seen"),
                }
            })

        return {"nodes": nodes, "edges": edges}

    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Aggregate statistics from all pipeline stages."""
        scorer_stats = self.scorer.get_stats()
        fusion_stats = self.fusion.get_stats()
        trust_stats = self.trust_evolution.get_stats()
        enforcer_stats = self.enforcer.get_stats()

        return {
            "stage_1": {
                "total_events_processed": self._event_count,
                "watch_paths": self.watch_paths,
            },
            "stage_3": {
                "graph_nodes": self.dbrg.get_node_count(),
                "graph_edges": self.dbrg.get_edge_count(),
                "events_ingested": self.dbrg.events_processed,
            },
            "stage_5": {
                "scoring_mode": scorer_stats.get("scoring_mode", "heuristic"),
                "is_ml_mode": scorer_stats.get("is_ml_mode", False),
                "total_scored": scorer_stats.get("total_scored", 0),
                "total_anomalies": scorer_stats.get("total_anomalies", 0),
                "anomaly_rate": scorer_stats.get("anomaly_rate", 0.0),
            },
            "stage_6": {
                "total_fused": fusion_stats.get("total_fused", 0),
                "total_benign": fusion_stats.get("total_benign", 0),
                "total_elevated": fusion_stats.get("total_elevated", 0),
                "total_high": fusion_stats.get("total_high", 0),
                "total_critical": fusion_stats.get("total_critical", 0),
                "critical_rate": fusion_stats.get("critical_rate", 0.0),
                "pids_tracked": fusion_stats.get("pids_tracked", 0),
            },
            "stage_7": {
                "trust_engine_active": True,
                "pids_tracked": trust_stats.get("pids_tracked", 0),
                "total_evolved": trust_stats.get("total_evolved", 0),
                "containment_triggers": trust_stats.get("total_containment_triggers", 0),
            },
            "stage_9": {
                "containment_engine_active": True,
                "total_contained": self.containment_engine.total_containments,
                "total_releases": self.containment_engine.total_releases,
                "active_contained": len(self._contained_pids),
                "dry_run": True,
            },
            "stage_10": {
                "enforcer_active": True,
                "pending_resolutions": len(self._pending_resolutions),
                "total_enforcements": enforcer_stats.get("total_enforcements", 0),
                "total_resolutions": enforcer_stats.get("total_resolutions", 0),
                "resolved_malicious": enforcer_stats.get("resolved_malicious", 0),
                "resolved_false_positive": enforcer_stats.get("resolved_false_positive", 0),
                "vault_snapshots": enforcer_stats.get("vault", {}).get("total_snapshots", 0),
            },
            "ws_clients": self.ws_manager.client_count,
        }

    def get_recent_events(
        self, limit: int = 50, tier_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return recent pipeline events, optionally filtered by tier."""
        with self._lock:
            events = self._recent_events[:limit]

        if tier_filter:
            tier_upper = tier_filter.upper()
            events = [
                e for e in events
                if e.get("stage_6", {}).get("threat_tier") == tier_upper
            ]

        return events

    # ── Threat Resolution (Stage 10) ─────────────────────────────────────

    def _verify_and_cleanup_session(
        self, pid: int, verdict: Verdict, rollback_report=None
    ) -> Dict[str, Any]:
        """Verify pre-attack SHA-256 hashes on restored/untouched files and clean up sandbox."""
        attack_id = self._pid_to_attack_id.get(pid)
        session = self._attack_sessions.get(attack_id) if attack_id else None
        if not session:
            return {}

        pre_hashes: Dict[str, str] = session.get("pre_hashes", {})
        sandbox = session.get("sandbox")
        sandbox_dir = Path(session["sandbox_dir"]) if session.get("sandbox_dir") else None

        restored_paths = set()
        if rollback_report is not None:
            for r in rollback_report.results:
                if r.success:
                    restored_paths.add(os.path.realpath(r.original_path))

        files_lost = 0
        files_restored_verified = 0
        files_protected_untouched = 0
        file_verification: List[Dict[str, Any]] = []

        if verdict == Verdict.MALICIOUS and pre_hashes:
            for orig_str, expected_sha in pre_hashes.items():
                orig_path = Path(orig_str)
                try:
                    rel_name = (
                        str(orig_path.relative_to(sandbox_dir)).replace("\\", "/")
                        if sandbox_dir
                        else orig_path.name
                    )
                except ValueError:
                    rel_name = orig_path.name

                was_restored = os.path.realpath(orig_str) in restored_paths
                if orig_path.exists():
                    try:
                        actual_sha = _sha256_file(orig_path)
                        matched = actual_sha == expected_sha
                    except OSError:
                        actual_sha = ""
                        matched = False
                else:
                    actual_sha = ""
                    matched = False

                if not matched:
                    files_lost += 1
                    status = "LOST"
                elif was_restored:
                    files_restored_verified += 1
                    status = "RESTORED"
                else:
                    files_protected_untouched += 1
                    status = "PROTECTED_UNTOUCHED"

                file_verification.append({
                    "file": rel_name,
                    "status": status,
                    "sha256_match": matched,
                    "sha256_prefix": expected_sha[:12],
                })

        # Now safe to clean up sandbox directory
        if sandbox is not None:
            try:
                sandbox.cleanup()
            except Exception as exc:
                logger.warning("[PipelineBridge] Sandbox cleanup failed: %s", exc)
            session["sandbox"] = None

        session["status"] = f"RESOLVED_{verdict.value}"
        session["resolved_at"] = time.time()

        return {
            "attack_id": attack_id,
            "profile": session.get("profile"),
            "total_victim_files": len(pre_hashes),
            "files_restored_verified": files_restored_verified,
            "files_protected_untouched": files_protected_untouched,
            "files_lost": files_lost,
            "zero_data_loss": files_lost == 0,
            "file_verification": file_verification,
        }

    def resolve_threat(self, pid: int, verdict_str: str) -> Dict[str, Any]:
        """
        Resolve a contained threat by PID with a given verdict.
        Returns resolution data including rollback report and SHA-256 verification.
        """
        with self._lock:
            if pid not in self._contained_pids:
                return {"error": f"PID {pid} is not currently pending containment"}

        try:
            verdict = Verdict(verdict_str.upper())
        except ValueError:
            return {"error": f"Invalid verdict: {verdict_str}. Use MALICIOUS or FALSE_POSITIVE"}

        resolution = self.enforcer.resolve(pid, verdict)
        if not resolution.success and resolution.error:
            return {"error": resolution.error}

        verification = self._verify_and_cleanup_session(
            pid, verdict, rollback_report=resolution.rollback_report
        )

        result: Dict[str, Any] = {
            "pid": pid,
            "verdict": verdict.value,
            "success": resolution.success,
            "duration_ms": round(resolution.duration_ms, 2),
            "steps": list(resolution.steps),
            "process_state": self.containment_engine.freezer.get_state(pid).value,
            "timestamp": time.time(),
            **verification,
        }

        if verdict == Verdict.MALICIOUS and resolution.rollback_report is not None:
            rb = resolution.rollback_report
            zero_loss = verification.get("zero_data_loss", rb.failed == 0)
            result["rollback"] = {
                "restored": rb.restored,
                "total": rb.total,
                "failed": rb.failed,
                "deleted_artifacts": rb.deleted_artifacts,
                "duration_ms": round(rb.duration_ms, 2),
                "zero_data_loss": zero_loss,
            }

        if verdict == Verdict.FALSE_POSITIVE:
            self.fusion.sigmoid.reset_pid(pid)
            result["acl_restored"] = resolution.acl_restored
            result["trust_reset"] = resolution.trust_reset or {"pid": pid, "trust": 100.0, "risk_tier": "SAFE"}
            result["drift_reset"] = {"pid": pid, "IntentDrift": 0.0, "drift_rate": 0.0, "threat_tier": "BENIGN"}

        with self._lock:
            self._contained_pids.pop(pid, None)
            self._pending_resolutions.pop(pid, None)
            self._resolution_history.insert(0, result)
            self._resolution_history = self._resolution_history[:20]

        self._broadcast({
            "type": "resolution_event",
            "pid": pid,
            "verdict": verdict.value,
            "resolution": result,
            "server_time": time.time(),
        })

        return result

    def get_containment_status(self) -> Dict[str, Any]:
        """Return current containment state, latest metrics, and resolution history."""
        with self._lock:
            contained = {
                str(pid): {
                    k: v
                    for k, v in info.items()
                    if k not in ("contain_record", "enforce_record")
                }
                for pid, info in self._contained_pids.items()
            }
            pending = {
                str(pid): info
                for pid, info in self._pending_resolutions.items()
            }
            history = list(self._resolution_history[:10])

        return {
            "contained_pids": contained,
            "pending_resolutions": pending,
            "total_contained": self.containment_engine.total_containments,
            "total_pending": len(pending),
            "pending_count": len(pending),
            "recent_resolutions": history,
            "enforcer_stats": self.enforcer.get_stats(),
        }

    # ── Benign Workload Simulation (Stage 1 Live OS Telemetry) ───────────

    def simulate_benign(self, num_files: int = 5) -> Dict[str, Any]:
        """
        Create and update benign low-entropy workspace files in WATCH_DIR
        so Stage 1 FileMonitor captures real OS file events flowing cleanly
        through Stages 1-7 as BENIGN / SAFE.
        """
        watch_dir = Path(self.watch_paths[0])
        watch_dir.mkdir(parents=True, exist_ok=True)

        def _write_benign():
            benign_dir = watch_dir / "benign_activity"
            benign_dir.mkdir(parents=True, exist_ok=True)
            for i in range(num_files):
                fpath = benign_dir / f"report_draft_{i + 1}.txt"
                content = (
                    f"Quarterly Engineering Status Report #{i + 1}\n"
                    "Status: Normal workspace document save.\n"
                    "All modules operating within nominal thresholds.\n"
                ) * 12
                fpath.write_text(content, encoding="utf-8")
                time.sleep(0.15)

        threading.Thread(
            target=_write_benign, daemon=True, name="benign-sim"
        ).start()
        return {"status": "STARTED", "num_files": num_files, "watch_dir": str(watch_dir)}

    # ── Stage 8 Attack Simulation ────────────────────────────────────────

    def launch_attack(
        self,
        profile_name: str = "lockbit",
        num_files: int = 13,
        auto_resolve: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Launch a simulated ransomware attack via Stage 8 harness.
        Runs in a background thread, streaming real-time events through
        Stages 2 → 3 → 4 → 5 → 6 → 7 → 9 → 10.

        Note: Sandbox stays intact after Stage 9 freeze so Stage 10 rollback
        can perform real file restoration and SHA-256 zero-data-loss verification
        when the analyst clicks Resolve (or when auto_resolve executes).
        """
        from src.stage_8_harness.sandbox_manager import SandboxManager
        from src.stage_8_harness.attack_engine import AttackEngine
        from src.stage_8_harness.attack_profiles import get_profile

        try:
            profile = get_profile(profile_name)
        except Exception:
            return {"error": f"Unknown profile: {profile_name}"}

        with self._lock:
            self._attack_counter += 1
            attack_num = self._attack_counter
            attack_id = f"attack_{attack_num}"
            attack_pid = 9000 + attack_num

        # Clean up any prior unresolved/abandoned sandboxes older than latest 3
        old_sessions = list(self._attack_sessions.values())[:-3]
        for old in old_sessions:
            if old.get("sandbox") is not None and old.get("pid") not in self._pending_resolutions:
                try:
                    old["sandbox"].cleanup()
                except Exception:
                    pass
                old["sandbox"] = None

        sandbox_dir = Path(tempfile.gettempdir()) / f"ards_ui_sandbox_{os.getpid()}_{attack_id}"
        sandbox = SandboxManager(sandbox_dir)
        sandbox.setup(num_files=num_files)
        total_files = sandbox.file_count()

        # Capture pre-attack SHA-256 ground truth for Zero-Data-Loss verification
        pre_hashes: Dict[str, str] = {}
        for target_path in sandbox.get_target_files():
            try:
                pre_hashes[str(target_path)] = _sha256_file(target_path)
            except OSError:
                pass

        # Clean slate for this PID in vault
        self.vault.purge(attack_pid)

        session: Dict[str, Any] = {
            "attack_id": attack_id,
            "profile": profile_name,
            "profile_display": profile.name,
            "pid": attack_pid,
            "num_files": total_files,
            "total_files": total_files,
            "auto_resolve": auto_resolve,
            "status": "STARTING",
            "started_at": time.time(),
            "sandbox": sandbox,
            "sandbox_dir": str(sandbox.sandbox_dir),
            "pre_hashes": pre_hashes,
            "events": [],
            "files_encrypted": 0,
            "detection_triggered": False,
            "containment_triggered": False,
            "detection_at": None,
            "error": None,
        }
        with self._lock:
            self._attack_sessions[attack_id] = session
            self._pid_to_attack_id[attack_pid] = attack_id

        def _run_attack():
            engine_ref: List[Optional[AttackEngine]] = [None]
            try:
                session["status"] = "RUNNING"
                self._broadcast({
                    "type": "attack_event",
                    "event": "started",
                    "attack_id": attack_id,
                    "profile": profile_name,
                    "profile_display": profile.name,
                    "pid": attack_pid,
                    "total_files": total_files,
                    "files_encrypted": 0,
                    "status": "RUNNING",
                    "server_time": time.time(),
                })

                def on_file_encrypted(original_path, renamed_path, data, index):
                    self.enforcer.note_rename(attack_pid, str(original_path), str(renamed_path))

                    exe_name = f"{profile_name}_sim.exe"
                    ecar_event = {
                        "actorID": f"pid:{attack_pid}",
                        "objectID": f"file:{renamed_path}",
                        "pid": attack_pid,
                        "operation": "MODIFY",
                        "timestamp": time.time() * 1000,
                        "principal": "SYSTEM",
                        "context": {
                            "exe_path": exe_name,
                            "parent_exe": "cmd.exe",
                            "sha256": "",
                        },
                    }

                    # Stage 3
                    self.dbrg.process_event(ecar_event)

                    # Stage 4
                    try:
                        features = self.extractor.extract_features(ecar_event)
                    except Exception:
                        features = None
                    if not features:
                        return

                    # Stage 2 rarity before Stage 6 fusion
                    self._compute_s_rel(ecar_event, features)

                    # Stage 5
                    try:
                        anomaly_result = self.scorer.score(features)
                    except Exception:
                        return

                    # Stage 6
                    try:
                        fusion_result = self.fusion.fuse(dict(features), anomaly_result)
                        fusion_result["pid"] = attack_pid
                    except Exception:
                        return

                    # Stage 7
                    try:
                        trust_result = self.trust_evolution.evolve(fusion_result)
                        self.enforcer.on_trust_update(trust_result)
                    except Exception:
                        return

                    session["files_encrypted"] = index + 1
                    trust_val = trust_result.get("trust", 100.0)
                    risk_tier = trust_result.get("risk_tier", "SAFE")
                    should_contain = trust_result.get("should_contain", False)

                    contain_record = None
                    enforce_record = None

                    # Stage 9 + 10
                    if should_contain and attack_pid not in self._contained_pids:
                        session["containment_triggered"] = True
                        session["detection_triggered"] = True
                        session["detection_at"] = index + 1
                        try:
                            contain_record = self.containment_engine.contain(
                                pid=attack_pid,
                                dbrg_graph=self.dbrg.get_graph_snapshot(),
                                trust_state=trust_result,
                            )
                            enforce_record = self.enforcer.enforce(contain_record)
                            info = {
                                "pid": attack_pid,
                                "attack_id": attack_id,
                                "profile": profile_name,
                                "exe_name": exe_name,
                                "status": "PENDING_RESOLUTION",
                                "trust": round(trust_val, 2),
                                "risk_tier": risk_tier,
                                "cut_edges": len(contain_record.cut_edges),
                                "cut_value": round(contain_record.cut_value, 2),
                                "isolated_files": len(contain_record.isolated_files),
                                "acl_revoked": len(enforce_record.acl_records) if enforce_record else 0,
                                "latency_ms": round(contain_record.latency_ms, 3),
                                "process_state": self.containment_engine.freezer.get_state(attack_pid).value,
                                "files_encrypted_before_freeze": index + 1,
                                "total_victim_files": total_files,
                                "timestamp": time.time(),
                            }
                            with self._lock:
                                self._contained_pids[attack_pid] = {
                                    **info,
                                    "contain_record": contain_record,
                                    "enforce_record": enforce_record,
                                }
                                self._pending_resolutions[attack_pid] = info

                            self._broadcast({
                                "type": "containment_event",
                                "data": info,
                                "server_time": time.time(),
                            })
                        except Exception as exc:
                            logger.warning("[PipelineBridge] Attack Stage 9-10 error: %s", exc)

                    with self._lock:
                        self._event_count += 1
                        eid = self._event_count

                    ws_msg = self._build_ws_message(
                        eid,
                        ecar_event,
                        features,
                        anomaly_result,
                        fusion_result,
                        trust_result=trust_result,
                        contain_record=contain_record,
                        enforce_record=enforce_record,
                    )
                    ws_msg["attack_id"] = attack_id

                    with self._lock:
                        self._recent_events.insert(0, ws_msg)
                        if len(self._recent_events) > self._max_recent:
                            self._recent_events = self._recent_events[:self._max_recent]

                    session["events"].append({
                        "event_id": eid,
                        "file": str(original_path),
                        "trust": trust_val,
                        "risk_tier": risk_tier,
                        "contained": contain_record is not None,
                    })

                    self._broadcast(ws_msg)

                    if should_contain and engine_ref[0] is not None:
                        engine_ref[0].signal_abort("Pipeline containment triggered")

                engine = AttackEngine(
                    sandbox=sandbox,
                    profile=profile,
                    abort_on_detection=True,
                    on_file_encrypted=on_file_encrypted,
                    on_before_encrypt=lambda p, i: self.enforcer.before_write(str(p), attack_pid),
                    on_file_created=lambda p: self.enforcer.note_created(attack_pid, str(p)),
                )
                engine_ref[0] = engine
                engine.execute()

                session["status"] = (
                    "CONTAINED" if session["containment_triggered"] else "COMPLETED"
                )
                session["finished_at"] = time.time()

                self._broadcast({
                    "type": "attack_event",
                    "event": "complete",
                    "attack_id": attack_id,
                    "profile": profile_name,
                    "profile_display": profile.name,
                    "pid": attack_pid,
                    "files_encrypted": session["files_encrypted"],
                    "total_files": total_files,
                    "detection_at": session["detection_at"],
                    "containment_triggered": session["containment_triggered"],
                    "status": session["status"],
                    "server_time": time.time(),
                })

                # Full Auto-Mitigation Demo mode: brief pause so UI displays Stage 9 freeze,
                # then automatically runs Stage 10 enforcement + vault rollback.
                if (
                    auto_resolve
                    and auto_resolve.upper() in ("MALICIOUS", "FALSE_POSITIVE")
                    and session["containment_triggered"]
                ):
                    time.sleep(1.2)
                    self.resolve_threat(attack_pid, auto_resolve.upper())

            except Exception as exc:
                session["status"] = "ERROR"
                session["error"] = str(exc)
                logger.error("[PipelineBridge] Attack error: %s", exc, exc_info=True)
                self._broadcast({
                    "type": "attack_event",
                    "event": "error",
                    "attack_id": attack_id,
                    "error": str(exc),
                    "status": "ERROR",
                    "server_time": time.time(),
                })

        thread = threading.Thread(
            target=_run_attack, daemon=True, name=f"attack-{attack_id}"
        )
        thread.start()

        return {
            "attack_id": attack_id,
            "profile": profile_name,
            "profile_display": profile.name,
            "pid": attack_pid,
            "num_files": total_files,
            "auto_resolve": auto_resolve,
            "status": "STARTING",
        }

    def get_attack_status(self, attack_id: str) -> Dict[str, Any]:
        """Return the current status of an attack session."""
        session = self._attack_sessions.get(attack_id)
        if session is None:
            return {"error": f"Unknown attack_id: {attack_id}"}

        return {
            "attack_id": session["attack_id"],
            "profile": session["profile"],
            "profile_display": session.get("profile_display"),
            "pid": session["pid"],
            "status": session["status"],
            "files_encrypted": session["files_encrypted"],
            "total_files": session["total_files"],
            "detection_at": session["detection_at"],
            "detection_triggered": session["detection_triggered"],
            "containment_triggered": session["containment_triggered"],
            "events_count": len(session["events"]),
            "started_at": session.get("started_at"),
            "finished_at": session.get("finished_at"),
            "error": session.get("error"),
        }
