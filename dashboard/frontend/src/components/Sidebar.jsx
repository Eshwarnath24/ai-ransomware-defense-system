/**
 * Sidebar.jsx — Pipeline stage indicators and live cross-stage statistics
 * Shows all active stages (1-11) and Stage 12 offline evaluation sweep.
 */
import { useState, useEffect } from 'react';

const STAGES = [
  { id: 1, name: 'Telemetry Collection', active: true },
  { id: 2, name: 'Lineage Analysis', active: true },
  { id: 3, name: 'DBRG Graph Engine', active: true },
  { id: 4, name: 'Feature Extraction', active: true },
  { id: 5, name: 'Anomaly Scoring', active: true },
  { id: 6, name: 'Threat Fusion', active: true },
  { id: 7, name: 'Trust State Engine', active: true },
  { id: 8, name: 'Synthetic Harness', active: true },
  { id: 9, name: 'Kernel Containment', active: true },
  { id: 10, name: 'Journaling & Rollback', active: true },
  { id: 11, name: 'SOC Dashboard', active: true },
  { id: 12, name: 'Eval Sweep (CLI)', active: false },
];

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function Sidebar({ latestEvent }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/stats`);
        if (res.ok) setStats(await res.json());
      } catch (e) { /* ignore */ }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 2500);
    return () => clearInterval(interval);
  }, []);

  const s6 = stats?.stage_6 || {};
  const s5 = stats?.stage_5 || {};
  const s7 = latestEvent?.stage_7 || {};
  const s9 = stats?.stage_9 || {};
  const s10 = stats?.stage_10 || {};

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">🛡️ ARDS</div>
        <div className="sidebar-subtitle">Defense Pipeline</div>
      </div>

      <div className="sidebar-section">
        <div className="sidebar-section-title">Pipeline Stages</div>
        <ul className="stage-list">
          {STAGES.map(stage => (
            <li key={stage.id} className="stage-item">
              <span className={`stage-dot ${stage.active ? 'active' : 'inactive'}`} />
              <span className="stage-name">S{stage.id}: {stage.name}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="sidebar-stats">
        <div className="sidebar-section-title">Live Statistics</div>
        <div className="stat-row">
          <span className="stat-label">Events</span>
          <span className="stat-value">{stats?.stage_1?.total_events_processed ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Graph Nodes</span>
          <span className="stat-value">{stats?.stage_3?.graph_nodes ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Graph Edges</span>
          <span className="stat-value">{stats?.stage_3?.graph_edges ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Scorer Mode</span>
          <span className="stat-value">{s5.scoring_mode ?? '—'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Anomalies</span>
          <span className="stat-value">{s5.total_anomalies ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🟢 Benign</span>
          <span className="stat-value text-benign">{s6.total_benign ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🟡 Elevated</span>
          <span className="stat-value text-elevated">{s6.total_elevated ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🟠 High</span>
          <span className="stat-value text-high">{s6.total_high ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🔴 Critical</span>
          <span className="stat-value text-critical">{s6.total_critical ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🔐 Trust Score</span>
          <span className="stat-value">{s7.trust != null ? s7.trust.toFixed(1) : '—'}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">🛡️ Contained</span>
          <span className="stat-value">{s9.total_contained ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">💾 Vault Backups</span>
          <span className="stat-value">{s10.vault_snapshots ?? 0}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">⚖️ Resolutions</span>
          <span className="stat-value">{s10.total_resolutions ?? 0}</span>
        </div>
      </div>
    </aside>
  );
}
