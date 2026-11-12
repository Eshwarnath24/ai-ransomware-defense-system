/**
 * ContainmentPanel.jsx — Stage 9 Kernel Containment & Min-Cut Status
 * Displays live freeze status, Edmonds-Karp graph-cut metrics,
 * isolated files, and Stage 10 ACL/Vault enforcement counts.
 */
import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function ContainmentPanel({ latestEvent, latestContainment, latestResolution }) {
  const [containment, setContainment] = useState(null);

  useEffect(() => {
    const fetchContainment = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/containment`);
        if (res.ok) setContainment(await res.json());
      } catch (e) { /* ignore */ }
    };
    fetchContainment();
    const interval = setInterval(fetchContainment, 2000);
    return () => clearInterval(interval);
  }, [latestContainment, latestResolution]);

  const s9Evt = latestEvent?.stage_9 || {};
  const s10Evt = latestEvent?.stage_10 || {};
  const pendingList = containment?.pending_resolutions
    ? Object.values(containment.pending_resolutions)
    : [];

  // Active record: prefer pending list from server, or live WS containment event if unresolved
  const activeRecord =
    pendingList.length > 0
      ? pendingList[0]
      : (latestContainment && latestResolution?.pid !== latestContainment.pid ? latestContainment : null);

  const totalContained = containment?.total_contained ?? 0;
  const pendingCount = containment?.total_pending ?? pendingList.length;
  const vaultSnapshots =
    containment?.enforcer_stats?.vault?.total_snapshots ?? s10Evt.vault_snapshots ?? 0;

  return (
    <div className="card card--containment">
      <div className="card-header">
        <span className="card-title">
          Kernel Containment <span className="card-stage-tag">S9</span>
        </span>
        {activeRecord ? (
          <span className="tier-badge CRITICAL">FROZEN</span>
        ) : (
          <span className="tier-badge SAFE">READY</span>
        )}
      </div>
      <div className="containment-content">
        {activeRecord ? (
          <>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              Target: <strong>{activeRecord.exe_name || 'process'}</strong> (PID {activeRecord.pid})
            </div>
            <div className="containment-active">
              <div className="containment-metric">
                <span className="containment-metric-label">Min-Cut Edges</span>
                <span className="containment-metric-value">{activeRecord.cut_edges ?? s9Evt.cut_edges ?? 0}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Cut Cost</span>
                <span className="containment-metric-value">{(activeRecord.cut_value ?? s9Evt.cut_value ?? 0).toFixed(2)}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Isolated Files</span>
                <span className="containment-metric-value">{activeRecord.isolated_files ?? s9Evt.isolated_files ?? 0}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Freeze Latency</span>
                <span className="containment-metric-value">{(activeRecord.latency_ms ?? s9Evt.freeze_latency_ms ?? 0).toFixed(2)}ms</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">ACLs Revoked (S10)</span>
                <span className="containment-metric-value">{activeRecord.acl_revoked ?? s10Evt.acl_revoked ?? 0}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Vault Snapshots</span>
                <span className="containment-metric-value">{vaultSnapshots}</span>
              </div>
            </div>
          </>
        ) : (
          <div className="containment-idle">
            <div className="containment-active">
              <div className="containment-metric">
                <span className="containment-metric-label">Total Contained</span>
                <span className="containment-metric-value">{totalContained}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Pending Review</span>
                <span className="containment-metric-value">{pendingCount}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Vault Backups</span>
                <span className="containment-metric-value">{vaultSnapshots}</span>
              </div>
              <div className="containment-metric">
                <span className="containment-metric-label">Mode</span>
                <span className="containment-metric-value" style={{ fontSize: '0.85rem' }}>MIN-CUT</span>
              </div>
            </div>
            <div className="empty-state" style={{ padding: '14px 0 4px' }}>
              <span style={{ fontSize: '1.3rem', opacity: 0.4 }}>🛡️</span>
              <span>Armed — watching Trust &lt; 20</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
