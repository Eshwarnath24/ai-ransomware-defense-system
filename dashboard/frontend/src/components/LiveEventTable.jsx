/**
 * LiveEventTable.jsx — Stage 1 live telemetry event log
 * Scrolling table showing real-time eCAR events flowing through the pipeline.
 */
export default function LiveEventTable({ events }) {
  const displayEvents = events;

  const formatTime = (ms) => {
    if (!ms) return '—';
    const d = new Date(ms > 1e12 ? ms : ms * 1000);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const truncate = (s, max = 20) => {
    if (!s) return '—';
    return s.length > max ? s.slice(0, max - 3) + '...' : s;
  };

  return (
    <div className="card card--events">
      <div className="card-header">
        <span className="card-title">
          Live Event Log
          <span className="card-stage-tag">S1</span>
        </span>
        <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          {events.length} {events.length === 1 ? 'entry' : 'entries'}
        </span>
      </div>
      <div className="event-table-container">
        {displayEvents.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📡</div>
            <div>Waiting for telemetry events...</div>
            <div style={{ fontSize: '0.7rem' }}>Run: python src/simulate_live_activity.py --mode mixed</div>
          </div>
        ) : (
          <table className="event-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Time</th>
                <th>PID</th>
                <th>Operation</th>
                <th>File</th>
                <th>S_entropy</th>
                <th>Anomaly</th>
                <th>Drift</th>
                <th>Tier</th>
              </tr>
            </thead>
            <tbody>
              {displayEvents.map((evt, i) => {
                const s1 = evt.stage_1 || {};
                const s4 = evt.stage_4 || {};
                const s5 = evt.stage_5 || {};
                const s6 = evt.stage_6 || {};
                const tier = s6.threat_tier || 'BENIGN';

                return (
                  <tr key={evt._uid || `evt-${evt.server_time || ''}-${i}`} className={`tier-${tier}`}>
                    <td title={`Pipeline Event ID: ${evt.event_id ?? i + 1}`}>{i + 1}</td>
                    <td>{formatTime(s1.timestamp_ms)}</td>
                    <td>{s1.pid}</td>
                    <td>{s1.operation?.replace('FILE_', '')}</td>
                    <td title={s1.file_path}>{truncate(s1.file_name, 18)}</td>
                    <td>{(s4.S_entropy ?? 0).toFixed(3)}</td>
                    <td>{(s5.anomaly_score ?? 0).toFixed(3)}</td>
                    <td>{(s6.IntentDrift ?? 0).toFixed(3)}</td>
                    <td><span className={`tier-badge ${tier}`}>{tier}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
