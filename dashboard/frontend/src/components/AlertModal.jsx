/**
 * AlertModal.jsx — CRITICAL threat / containment alert popup
 * Appears when IntentDrift hits CRITICAL or Stage 9 containment triggers.
 * Wires directly to Stage 10 /api/resolve (MALICIOUS / FALSE_POSITIVE).
 */
import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function AlertModal({ latestEvent, latestResolution }) {
  const [show, setShow] = useState(false);
  const [alertEvent, setAlertEvent] = useState(null);
  const [dismissedPids, setDismissedPids] = useState(new Set());
  const [resolving, setResolving] = useState(false);
  const [resolutionResult, setResolutionResult] = useState(null);

  useEffect(() => {
    if (!latestEvent) return;
    const tier = latestEvent.stage_6?.threat_tier;
    const shouldContain = latestEvent.stage_7?.should_contain;
    const pid = latestEvent.stage_1?.pid;

    if ((tier === 'CRITICAL' || shouldContain) && pid != null && !dismissedPids.has(pid)) {
      setAlertEvent(latestEvent);
      setResolutionResult(null);
      setShow(true);
    }
  }, [latestEvent, dismissedPids]);

  // Reflect resolution if resolved externally (e.g., ResolutionPanel or Auto-Demo)
  useEffect(() => {
    if (!latestResolution || !alertEvent) return;
    const alertPid = alertEvent.stage_1?.pid;
    if (latestResolution.pid === alertPid && show) {
      setResolutionResult(latestResolution);
    }
  }, [latestResolution, alertEvent, show]);

  const handleDismiss = () => {
    if (alertEvent?.stage_1?.pid != null) {
      setDismissedPids(prev => new Set([...prev, alertEvent.stage_1.pid]));
    }
    setShow(false);
    setResolutionResult(null);
  };

  const handleResolve = async (verdict) => {
    const pid = alertEvent?.stage_1?.pid;
    if (pid == null) return;
    setResolving(true);
    try {
      const res = await fetch(`${API_BASE}/api/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid, verdict }),
      });
      const data = await res.json();
      setResolutionResult(data);
    } catch (e) {
      setResolutionResult({ error: e.message });
    }
    setResolving(false);
  };

  if (!show || !alertEvent) return null;

  const s1 = alertEvent.stage_1 || {};
  const s6 = alertEvent.stage_6 || {};
  const s7 = alertEvent.stage_7 || {};
  const s9 = alertEvent.stage_9 || {};

  return (
    <div className="alert-overlay" onClick={handleDismiss}>
      <div className="alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="alert-title">
          🚨 CRITICAL THREAT CONTAINED
        </div>
        <div className="alert-detail">
          <p>
            <strong>Process:</strong> {s1.exe_name} (PID {s1.pid})<br />
            <strong>Target File:</strong> {s1.file_name}<br />
            <strong>IntentDrift (S6):</strong>{' '}
            <span style={{ color: 'var(--tier-critical)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {(s6.IntentDrift ?? 0).toFixed(4)}
            </span>{' '}
            | <strong>Trust (S7):</strong>{' '}
            <span style={{ color: 'var(--tier-critical)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {s7.trust != null ? s7.trust.toFixed(1) : '0.0'}
            </span><br />
            {s9.contained && (
              <>
                <strong>Stage 9 Freeze:</strong> {s9.process_state || 'FROZEN'} in {s9.freeze_latency_ms}ms
                {' '}| Min-Cut: {s9.cut_edges} edges, {s9.isolated_files} files isolated
              </>
            )}
          </p>
          <p style={{ marginTop: '10px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
            Process suspended and write ACLs revoked along min-cut boundary.
            Write-ahead snapshots are armed in Stage 10 Journal Vault. Choose analyst verdict:
          </p>
        </div>

        {resolutionResult ? (
          <div className={`resolution-result ${resolutionResult.error ? 'error' : 'success'}`} style={{ marginBottom: '14px' }}>
            {resolutionResult.error ? (
              <div>❌ {resolutionResult.error}</div>
            ) : resolutionResult.verdict === 'MALICIOUS' ? (
              <div>
                <strong>🔒 MALICIOUS CONFIRMED — ZERO-DATA-LOSS ROLLBACK COMPLETE</strong>
                <div style={{ marginTop: '6px', fontSize: '0.78rem', lineHeight: 1.5 }}>
                  Restored: {resolutionResult.rollback?.restored ?? 0}/{resolutionResult.rollback?.total ?? 0} encrypted files |
                  Untouched Protected: {resolutionResult.files_protected_untouched ?? 0} |
                  Lost: {resolutionResult.files_lost ?? 0}<br />
                  Rollback Latency: {resolutionResult.rollback?.duration_ms ?? resolutionResult.duration_ms}ms |
                  Zero Data Loss: {resolutionResult.zero_data_loss !== false ? '✅ YES (SHA-256 Verified)' : '❌ NO'}
                </div>
              </div>
            ) : (
              <div>
                <strong>✅ FALSE POSITIVE — PROCESS RESUMED</strong>
                <div style={{ marginTop: '6px', fontSize: '0.78rem' }}>
                  ACLs Restored: {resolutionResult.acl_restored ?? 0} | Trust Reset: 100.0 | State: {resolutionResult.process_state}
                </div>
              </div>
            )}
          </div>
        ) : null}

        <div className="alert-actions">
          {!resolutionResult ? (
            <>
              <button
                className="alert-btn alert-btn--danger"
                onClick={() => handleResolve('MALICIOUS')}
                disabled={resolving}
              >
                {resolving ? '⏳ Rolling Back...' : '🔒 Isolate & Restore'}
              </button>
              <button
                className="alert-btn alert-btn--secondary"
                onClick={() => handleResolve('FALSE_POSITIVE')}
                disabled={resolving}
              >
                {resolving ? '⏳ Resuming...' : '✅ Authorize & Resume'}
              </button>
            </>
          ) : (
            <button className="alert-btn alert-btn--secondary" onClick={handleDismiss}>
              Close Summary
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
