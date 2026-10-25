/**
 * AnomalyPanel.jsx — Stage 5 Anomaly Scoring display
 * Shows IF score, SVM score, fused anomaly score, confidence, and risk tier.
 */
export default function AnomalyPanel({ latestEvent }) {
  const s5 = latestEvent?.stage_5 || {};
  const anomalyScore = s5.anomaly_score ?? 0;
  const ifScore = s5.isolation_score;
  const svmScore = s5.svm_score;
  const confidence = s5.confidence ?? 0;
  const riskTier = s5.risk_tier ?? 'SAFE';
  const mode = s5.scoring_mode ?? 'heuristic';

  const getBarColor = (score) => {
    if (score < 0.25) return 'var(--tier-benign)';
    if (score < 0.50) return 'var(--tier-elevated)';
    if (score < 0.75) return 'var(--tier-high)';
    return 'var(--tier-critical)';
  };

  return (
    <div className="card card--anomaly">
      <div className="card-header">
        <span className="card-title">
          Anomaly Scoring
          <span className="card-stage-tag">S5</span>
        </span>
        <span className={`tier-badge ${riskTier}`}>{riskTier}</span>
      </div>
      <div className="anomaly-scores">
        {/* Fused score */}
        <div className="anomaly-score-row">
          <span className="anomaly-score-label">Fused (DAC-OCF)</span>
          <div className="anomaly-score-bar">
            <div className="anomaly-score-fill" style={{
              width: `${anomalyScore * 100}%`,
              background: getBarColor(anomalyScore),
            }} />
          </div>
          <span className="anomaly-score-value" style={{ color: getBarColor(anomalyScore) }}>
            {anomalyScore.toFixed(3)}
          </span>
        </div>

        {/* Isolation Forest */}
        <div className="anomaly-score-row">
          <span className="anomaly-score-label">Isolation Forest</span>
          <div className="anomaly-score-bar">
            <div className="anomaly-score-fill" style={{
              width: `${(ifScore ?? 0) * 100}%`,
              background: 'var(--signal-entropy)',
            }} />
          </div>
          <span className="anomaly-score-value">
            {ifScore != null ? ifScore.toFixed(3) : '—'}
          </span>
        </div>

        {/* One-Class SVM */}
        <div className="anomaly-score-row">
          <span className="anomaly-score-label">One-Class SVM</span>
          <div className="anomaly-score-bar">
            <div className="anomaly-score-fill" style={{
              width: `${(svmScore ?? 0) * 100}%`,
              background: 'var(--signal-dist)',
            }} />
          </div>
          <span className="anomaly-score-value">
            {svmScore != null ? svmScore.toFixed(3) : '—'}
          </span>
        </div>

        {/* Confidence */}
        <div className="anomaly-score-row">
          <span className="anomaly-score-label">Confidence</span>
          <div className="anomaly-score-bar">
            <div className="anomaly-score-fill" style={{
              width: `${confidence * 100}%`,
              background: 'var(--accent-primary)',
            }} />
          </div>
          <span className="anomaly-score-value">{confidence.toFixed(3)}</span>
        </div>

        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '4px' }}>
          Mode: <span className="mono" style={{ color: 'var(--text-accent)' }}>{mode.toUpperCase()}</span>
        </div>
      </div>
    </div>
  );
}
