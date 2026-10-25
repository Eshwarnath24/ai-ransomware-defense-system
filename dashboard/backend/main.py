"""
dashboard/backend/main.py
============================
FastAPI application for the SOC Dashboard.

Serves:
  - WebSocket /ws/live  → Real-time pipeline event stream
  - REST /api/graph     → DBRG graph snapshot (Cytoscape.js format)
  - REST /api/stats     → Pipeline statistics from all stages
  - REST /api/events    → Recent events with optional tier filter
  - REST /api/health    → Backend health check
  - Static files        → Built React frontend (production)

Usage:
  uvicorn dashboard.backend.main:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
from contextlib import asynccontextmanager
import logging
import os
import sys
import warnings
from pathlib import Path
from typing import Optional

# Suppress scikit-learn version mismatch warnings on unpickling
warnings.filterwarnings("ignore", message="Trying to unpickle estimator")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Ensure project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.backend.websocket_manager import WebSocketManager
from dashboard.backend.pipeline_bridge import PipelineBridge

# Suppress verbose debug logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Shared instances & Lifecycle ──────────────────────────────────────────

ws_manager = WebSocketManager()

# Default watch directory
WATCH_DIR = PROJECT_ROOT / "monitored_test_dir"
bridge = PipelineBridge(
    watch_paths=[str(WATCH_DIR.resolve())],
    ws_manager=ws_manager,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    loop = asyncio.get_running_loop()
    bridge.start(loop)
    logger.info("SOC Dashboard backend started. Watching: %s", WATCH_DIR)
    yield
    bridge.stop()
    logger.info("SOC Dashboard backend stopped.")


# ── FastAPI Application ──────────────────────────────────────────────────

app = FastAPI(
    title="AI Ransomware Defense — SOC Dashboard",
    description="Real-time SOC Dashboard for the 12-Stage Ransomware Defense Pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: allow React dev server at localhost:5173
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket: Real-time pipeline events ─────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    WebSocket endpoint for real-time pipeline event streaming.
    Each connected browser client receives pipeline_event JSON messages
    as events flow through Stages 1–6.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive: wait for client messages (ping/pong or close)
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ── REST: DBRG Graph Snapshot ────────────────────────────────────────────

@app.get("/api/graph")
async def get_graph():
    """
    Returns the current DBRG graph in Cytoscape.js-compatible format.
    Used by the DBRGGraph component to render the interactive graph.

    Returns: {nodes: [{data: {id, label, type, ...}}], edges: [{data: {source, target, weight, ...}}]}
    """
    return bridge.get_graph_json()


# ── REST: Pipeline Statistics ────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """
    Returns aggregate statistics from all pipeline stages.
    Used by the StatsPanel and Sidebar components.

    Returns: {stage_1: {...}, stage_3: {...}, stage_5: {...}, stage_6: {...}, ws_clients: int}
    """
    return bridge.get_pipeline_stats()


# ── REST: Recent Events ─────────────────────────────────────────────────

@app.get("/api/events")
async def get_events(
    limit: int = Query(default=50, ge=1, le=500),
    tier: Optional[str] = Query(default=None),
):
    """
    Returns recent pipeline events, optionally filtered by threat tier.

    Query params:
      limit: Max events to return (1–500, default 50)
      tier: Filter by threat tier (BENIGN, ELEVATED, HIGH, CRITICAL)
    """
    return bridge.get_recent_events(limit=limit, tier_filter=tier)


# ── REST: Health Check ───────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Backend health check endpoint."""
    return {
        "status": "ok",
        "stages_active": [1, 2, 3, 4, 5, 6],
        "ws_clients": ws_manager.client_count,
        "pipeline_running": bridge._running,
    }


# ── Serve React Frontend (production build) ──────────────────────────────

FRONTEND_BUILD = PROJECT_ROOT / "dashboard" / "frontend" / "dist"
if FRONTEND_BUILD.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=str(FRONTEND_BUILD / "assets")),
        name="static-assets",
    )

    @app.get("/")
    async def serve_frontend():
        return FileResponse(str(FRONTEND_BUILD / "index.html"))

    @app.get("/{full_path:path}")
    async def serve_frontend_fallback(full_path: str):
        """SPA fallback: serve index.html for client-side routing."""
        file_path = FRONTEND_BUILD / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_BUILD / "index.html"))


# ── Direct Execution Entry Point ─────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    # Pass app instance directly so 'python main.py' works reliably from any working directory
    uvicorn.run(app, host="0.0.0.0", port=8000)


