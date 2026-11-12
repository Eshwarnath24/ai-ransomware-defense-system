/**
 * ResolutionPanel.jsx — Stage 10 Enforcement, Resolution & Zero-Data-Loss Verification
 * Shows pending contained threats with analyst verdict buttons (MALICIOUS / FALSE_POSITIVE),
 * and renders the complete real-time rollback & SHA-256 verification proof.
 */
import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function ResolutionPanel({ latestResolution, latestContainment }) {
  const [containment, setContainment] = useState(null);
  const [resolvingPid, setResolvingPid] = useState(null);
  const [displayResolution, setDisplayResolution] = useState(null);

  const fetchContainment = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/containment`);
      if (res.ok) setContainment(await res.json());
    } catch (e) { /* ignore */ }
  };

  useEffect(() => {
    fetchContainment();
    const interval = setInterval(fetchContainment, 2000);
    return () => clearInterval(interval);
  }, [latestContainment, latestResolution]);

  // Immediately show WebSocket resolution broadcast (e.g. from AlertModal or Auto-Demo)
  useEffect(() => {
    if (latestResolution) {
      setDisplayResolution(latestResolution);
    }
  }, [latestResolution]);

  const resolveThreat = async (pid, verdict) => {
    setResolvingPid(pid);
    try {
      const res = await fetch(`${API_BASE}/api/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: parseInt(pid, 10), verdict }),
      });
      const data = await res.json();
      setDisplayResolution(data);
      fetchContainment();
    } catch (e) {
      setDisplayResolution({ error: e.message });
    }
    setResolvingPid(null);
  };

  const pendingEntries = containment?.pending_resolutions
    ? Object.entries(containment.pending_resolutions)
    : [];

  return (
    <div className="card card--resolution">
      <div className="card-header">
        <span className="card-title">
          Enforcement &amp; Rollback Output <span className="card-stage-tag">S10</span>
        </span>
        {displayResolution && !displayResolution.error && (
          <span className={`tier-badge ${displayResolution.verdict === 'MALICIOUS' ? 'SAFE' : 'BENIGN'}`}>
            {displayResolution.verdict === 'MALICIOUS' ? 'ZERO LOSS VERIFIED' : 'RESUMED'}
          </span>
        )}
      </div>

      <div className="resolution-content">
        {pendingEntries.length > 0 && (
          <div className="pending-list">
            {pendingEntries.map(([pid, info]) => (
              <div key={pid} className="resolution-item">
                <div className="resolution-info">
                  <span className="resolution-pid">PID {pid} ({info.exe_name || 'malware'})</span>
                  <span className={`tier-badge ${info.risk_tier}`}>{info.risk_tier}</span>
                  <span className="resolution-trust">
                    Trust: {(info.trust ?? 0).toFixed(1)} | Encrypted before freeze: {info.files_encrypted_before_freeze ?? '?'}/{info.total_victim_files ?? '?'}
                  </span>
                </div>
                <div className="resolution-actions">
                  <button
                    type="button"
                    className="alert-btn alert-btn--danger"
                    onClick={() => resolveThreat(pid, 'MALICIOUS')}
                    disabled={resolvingPid === pid}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    {resolvingPid === pid ? '⏳...' : '🔒 Confirm Malicious & Rollback'}
                  </button>
                  <button
                    type="button"
                    className="alert-btn alert-btn--secondary"
                    onClick={() => resolveThreat(pid, 'FALSE_POSITIVE')}
                    disabled={resolvingPid === pid}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    ✅ False Positive
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {displayResolution ? (
          <div className={`resolution-result ${displayResolution.error ? 'error' : 'success'}`}>
            {displayResolution.error ? (
              `❌ ${displayResolution.error}`
            ) : displayResolution.verdict === 'MALICIOUS' ? (
              <div>
                <div className="resolution-summary-header">
                  <strong>
                    🔒 PID {displayResolution.pid} Terminated &amp; Rolled Back ({displayResolution.profile || 'live telemetry'})
                  </strong>
                  <span className="mono">{displayResolution.duration_ms}ms total</span>
                </div>
                <div className="resolution-kpis">
                  <div className="resolution-kpi">
                    <span>Restored</span>
                    <strong>{displayResolution.rollback?.restored ?? 0}/{displayResolution.rollback?.total ?? 0}</strong>
                  </div>
                  <div className="resolution-kpi">
                    <span>Protected Untouched</span>
                    <strong>{displayResolution.files_protected_untouched ?? 0}</strong>
                  </div>
                  <div className="resolution-kpi">
                    <span>Files Lost</span>
                    <strong style={{ color: (displayResolution.files_lost ?? 0) === 0 ? 'var(--tier-benign)' : 'var(--tier-critical)' }}>
                      {displayResolution.files_lost ?? 0}
                    </strong>
                  </div>
                  <div className="resolution-kpi">
                    <span>Artifacts Purged</span>
                    <strong>{displayResolution.rollback?.deleted_artifacts ?? 0}</strong>
                  </div>
                  <div className="resolution-kpi">
                    <span>Zero Data Loss</span>
                    <strong>{displayResolution.zero_data_loss !== false ? '✅ YES' : '❌ NO'}</strong>
                  </div>
                </div>

                {Array.isArray(displayResolution.file_verification) && displayResolution.file_verification.length > 0 && (
                  <div className="file-verify-list">
                    {displayResolution.file_verification.map((fv, idx) => (
                      <div key={idx} className="file-verify-row">
                        <span className="mono file-verify-name" title={fv.file}>{fv.file}</span>
                        <span className={`file-verify-status ${fv.status}`}>
                          {fv.status === 'RESTORED' ? '♻️ RESTORED' : fv.status === 'PROTECTED_UNTOUCHED' ? '🛡️ SAVED' : '❌ LOST'}
                        </span>
                        <span className="mono file-verify-hash">
                          {fv.sha256_match ? `✓ ${fv.sha256_prefix}` : 'MISMATCH'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div>
                <strong>✅ FALSE POSITIVE CONFIRMED — PID {displayResolution.pid} RESUMED</strong>
                <div style={{ marginTop: '6px', fontSize: '0.76rem' }}>
                  ACLs Restored: {displayResolution.acl_restored ?? 0} |
                  Process State: {displayResolution.process_state || 'RELEASED'} |
                  Trust Score Reset: 100.0 (SAFE) |
                  Duration: {displayResolution.duration_ms}ms
                </div>
              </div>
            )}
          </div>
        ) : (
          pendingEntries.length === 0 && (
            <div className="empty-state" style={{ padding: '18px 0' }}>
              <div className="empty-state-icon">⚖️</div>
              <div>No pending threats — launch an attack or run Auto-Mitigate Demo</div>
            </div>
          )
        )}
      </div>
    </div>
  );
}
