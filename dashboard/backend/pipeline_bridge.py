"""
dashboard/backend/pipeline_bridge.py
=======================================
Bridges existing Stages 1-6 Python modules to WebSocket output.

This is the ONLY new integration code — all stage logic stays untouched.
The bridge wraps the existing pipeline (FileMonitor → QueueJoiner → DBRG →
FeatureExtractor → AnomalyScorer → ThreatFusion) and pushes structured
per-stage JSON messages to all connected WebSocket clients.
"""

import asyncio
import json
import logging
import os
import queue
import sys
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
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_4_features.feature_extractor import FeatureExtractor
from src.stage_5_anomaly.anomaly_scorer import AnomalyScorer
from src.stage_6_fusion.threat_fusion import ThreatFusion

logger = logging.getLogger(__name__)


class PipelineBridge:
    """
    Runs the full Stages 1-6 pipeline in background threads and broadcasts
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

    def _on_ecar_event(self, ecar_event: dict):
        """
        Callback invoked by QueueJoiner for each enriched eCAR event.
        Runs the full Stage 3 → 4 → 5 → 6 pipeline and broadcasts.
        """
        try:
            # ──── Stage 3: Update DBRG graph ────
            self.dbrg.process_event(ecar_event)

            # ──── Stage 4: Extract feature vector ────
            fv = self.extractor.extract_features(ecar_event)
            if fv is None:
                return

            # ──── Stage 5: Anomaly scoring ────
            anomaly_result = self.scorer.score(fv)

            # ──── Stage 6: Threat fusion ────
            fusion_result = self.fusion.fuse(fv, anomaly_result)

            with self._lock:
                self._event_count += 1
                event_id = self._event_count

            # ──── Build per-stage WebSocket message ────
            ws_message = self._build_ws_message(
                event_id, ecar_event, fv, anomaly_result, fusion_result
            )

            # Store in recent buffer
            with self._lock:
                self._recent_events.insert(0, ws_message)
                if len(self._recent_events) > self._max_recent:
                    self._recent_events = self._recent_events[:self._max_recent]

            # Push to all connected browser clients
            if self._loop and self.ws_manager.client_count > 0:
                asyncio.run_coroutine_threadsafe(
                    self.ws_manager.broadcast(json.dumps(ws_message, default=str)),
                    self._loop,
                )

        except Exception as e:
            logger.debug("[PipelineBridge] Event processing error: %s", e)

    def _build_ws_message(
        self,
        event_id: int,
        ecar: dict,
        fv: dict,
        anomaly: dict,
        fusion: dict,
    ) -> Dict[str, Any]:
        """Build a structured WebSocket message with all stage data."""
        context = ecar.get("context", {})
        file_path_raw = ecar.get("objectID", "")
        file_path = file_path_raw[5:] if file_path_raw.startswith("file:") else file_path_raw

        return {
            "type": "pipeline_event",
            "event_id": event_id,
            "server_time": time.time(),

            # ── Stage 1: Raw telemetry ──
            "stage_1": {
                "pid": ecar.get("pid", -1),
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
        }

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self, loop: asyncio.AbstractEventLoop):
        """Start the live pipeline in background threads."""
        self._loop = loop
        self._running = True

        # Ensure watch directories exist
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
        """Gracefully stop all pipeline threads."""
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
        logger.info("[PipelineBridge] Pipeline stopped.")

    # ── REST API Data Providers ──────────────────────────────────────────

    def get_graph_json(self) -> Dict[str, Any]:
        """
        Serialize the DBRG graph for Cytoscape.js in the frontend.
        Returns Cytoscape-compatible {nodes: [...], edges: [...]}.
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
