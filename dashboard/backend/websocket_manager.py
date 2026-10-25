"""
dashboard/backend/websocket_manager.py
========================================
WebSocket connection manager for the SOC Dashboard.

Manages multiple concurrent browser connections and broadcasts
pipeline events to all connected clients.
"""

import logging
from typing import List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections for real-time pipeline event streaming.

    Methods
    -------
    connect(websocket)
        Accept and register a new WebSocket connection.
    disconnect(websocket)
        Remove a disconnected WebSocket from the pool.
    broadcast(message)
        Send a text message to all connected clients.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "[WS-Manager] Client connected. Total: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected WebSocket from the pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            "[WS-Manager] Client disconnected. Total: %d",
            len(self.active_connections),
        )

    async def broadcast(self, message: str):
        """Send a text message to all connected WebSocket clients."""
        disconnected = []
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            if ws in self.active_connections:
                self.active_connections.remove(ws)

    @property
    def client_count(self) -> int:
        """Return the number of active WebSocket connections."""
        return len(self.active_connections)
