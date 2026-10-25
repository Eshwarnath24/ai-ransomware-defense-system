import { useEffect, useRef, useState, useCallback } from 'react';

/**
 * Custom hook for WebSocket connection to the pipeline backend.
 * Auto-reconnects on disconnect, maintains event buffer.
 * On mount, fetches recent events from REST so data survives page refresh.
 */
export function useWebSocket(url, apiBase) {
  const [events, setEvents] = useState([]);
  const [latestEvent, setLatestEvent] = useState(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectRef = useRef(null);
  const eventCountRef = useRef(0);
  const seenIdsRef = useRef(new Set());

  // ── Helper: add _uid to an event for unique React keys ──
  const enrichEvent = useCallback((data) => {
    eventCountRef.current += 1;
    return {
      ...data,
      _uid: `${Date.now()}-${eventCountRef.current}-${Math.random().toString(36).slice(2, 8)}`,
    };
  }, []);

  // ── Fetch buffered events from REST API on mount ──
  useEffect(() => {
    if (!apiBase) return;
    const controller = new AbortController();

    (async () => {
      try {
        const res = await fetch(`${apiBase}/api/events?limit=50`, {
          signal: controller.signal,
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) return;

        const enriched = data.map(evt => enrichEvent(evt));

        // Track seen event_ids to avoid duplicates when WS reconnects
        enriched.forEach(evt => {
          if (evt.event_id != null) seenIdsRef.current.add(evt.event_id);
        });

        setEvents(enriched);
        setLatestEvent(enriched[0]);
        console.log(`[REST] Loaded ${enriched.length} buffered events`);
      } catch (e) {
        if (e.name !== 'AbortError') {
          console.warn('[REST] Failed to fetch recent events:', e);
        }
      }
    })();

    return () => controller.abort();
  }, [apiBase, enrichEvent]);

  // ── WebSocket connection ──
  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);

      ws.onopen = () => {
        setConnected(true);
        console.log('[WS] Connected to pipeline backend');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Skip if we already loaded this event from REST
          if (data.event_id != null && seenIdsRef.current.has(data.event_id)) {
            return;
          }
          if (data.event_id != null) {
            seenIdsRef.current.add(data.event_id);
          }

          const enriched = enrichEvent(data);
          setLatestEvent(enriched);
          setEvents(prev => {
            const updated = [enriched, ...prev];
            return updated.length > 50 ? updated.slice(0, 50) : updated;
          });
        } catch (e) {
          console.warn('[WS] Invalid JSON:', e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        console.log('[WS] Disconnected. Reconnecting in 2s...');
        reconnectRef.current = setTimeout(connect, 2000);
      };

      ws.onerror = () => {
        ws.close();
      };

      wsRef.current = ws;
    } catch (e) {
      console.error('[WS] Connection failed:', e);
      reconnectRef.current = setTimeout(connect, 3000);
    }
  }, [url, enrichEvent]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectRef.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  // Send keepalive ping every 30s
  useEffect(() => {
    const interval = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return { events, latestEvent, connected, eventCount: eventCountRef.current };
}
