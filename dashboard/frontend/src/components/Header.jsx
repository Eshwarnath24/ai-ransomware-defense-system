/**
 * Header.jsx — Top navigation bar
 * Shows system title, connection status, and current threat level
 */
export default function Header({ connected, latestEvent, totalEvents }) {
  const threatTier = latestEvent?.stage_6?.threat_tier || 'BENIGN';
  const eventCount = totalEvents ?? (latestEvent?.event_id || 0);

  return (
    <header className="header">
      <div className="header-title">
        <span className="shield-icon">🛡️</span>
        AI Ransomware Defense — SOC Dashboard
      </div>
      <div className="header-status">
        <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Events: {eventCount}
        </span>
        <span className={`threat-level-badge ${threatTier}`}>
          {threatTier}
        </span>
        <span className={`status-badge ${connected ? 'connected' : 'disconnected'}`}>
          <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`} />
          {connected ? 'LIVE' : 'OFFLINE'}
        </span>
      </div>
    </header>
  );
}
