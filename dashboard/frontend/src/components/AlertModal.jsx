/**
 * AlertModal.jsx — CRITICAL threat tier alert popup
 * Appears when IntentDrift crosses the CRITICAL threshold.
 * Shows process details and action buttons (Stage 7-10 placeholders).
 */
import { useState, useEffect } from 'react';

export default function AlertModal({ latestEvent }) {
  const [show, setShow] = useState(false);
  const [alertEvent, setAlertEvent] = useState(null);
  const [dismissed, setDismissed] = useState(new Set());

  useEffect(() => {
    if (!latestEvent) return;
    const tier = latestEvent.stage_6?.threat_tier;
    const pid = latestEvent.stage_1?.pid;
    const eventId = latestEvent.event_id;

    if (tier === 'CRITICAL' && !dismissed.has(pid)) {
      setAlertEvent(latestEvent);
      setShow(true);
    }
  }, [latestEvent, dismissed]);

  const handleDismiss = () => {
    if (alertEvent) {
      setDismissed(prev => new Set([...prev, alertEvent.stage_1?.pid]));
    }
    setShow(false);
  };

  if (!show || !alertEvent) return null;

  const s1 = alertEvent.stage_1 || {};
  const s6 = alertEvent.stage_6 || {};

  return (
    <div className="alert-overlay" onClick={handleDismiss}>
      <div className="alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="alert-title">
          🚨 CRITICAL THREAT DETECTED
        </div>
        <div className="alert-detail">
          <p>
            <strong>Process:</strong> {s1.exe_name} (PID {s1.pid})<br />
            <strong>File:</strong> {s1.file_name}<br />
            <strong>Operation:</strong> {s1.operation}<br />
            <strong>IntentDrift:</strong>{' '}
            <span style={{ color: 'var(--tier-critical)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {(s6.IntentDrift ?? 0).toFixed(4)}
            </span><br />
            <strong>Drift Velocity:</strong> {(s6.drift_rate ?? 0).toFixed(6)}/s<br />
            <strong>Composite Score:</strong> {(s6.S_composite ?? 0).toFixed(4)}
          </p>
          <p style={{ marginTop: '12px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
            Multi-signal convergence detected. This process exhibits high entropy writes,
            rapid file targeting, and anomalous behavioral patterns consistent with
            ransomware encryption activity.
          </p>
        </div>
        <div className="alert-actions">
          <button className="alert-btn alert-btn--danger" onClick={handleDismiss}>
            🔒 Isolate & Restore
          </button>
          <button className="alert-btn alert-btn--secondary" onClick={handleDismiss}>
            ✅ Authorize & Resume
          </button>
        </div>
        <div style={{ marginTop: '10px', fontSize: '0.68rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Containment actions will be available when Stages 7–10 are implemented
        </div>
      </div>
    </div>
  );
}
