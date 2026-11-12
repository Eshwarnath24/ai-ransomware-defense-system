/**
 * TrustGauge.jsx — Stage 7 Trust Score & Risk Tier Display
 * Shows real-time trust score (0-100) with animated arc gauge,
 * risk tier state machine, and Stage 10 prewarm status.
 */
import { useMemo } from 'react';

export default function TrustGauge({ latestEvent, latestResolution }) {
  const s7 = latestEvent?.stage_7 || {};
  const s1 = latestEvent?.stage_1 || {};

  // If the latest resolved false positive matches this PID, reflect Trust=100 reset
  const isResetFP =
    latestResolution?.verdict === 'FALSE_POSITIVE' &&
    latestResolution?.pid != null &&
    latestResolution.pid === s1.pid;

  const trust = isResetFP ? 100 : (s7.trust ?? 100);
  const tier = isResetFP ? 'SAFE' : (s7.risk_tier ?? 'SAFE');
  const shouldContain = isResetFP ? false : (s7.should_contain ?? false);
  const prewarm = isResetFP ? false : (s7.prewarm_journal ?? false);
  const samplingMult = isResetFP ? 1 : (s7.sampling_multiplier ?? 1);

  const tierColor = useMemo(() => {
    if (tier === 'CRITICAL_RISK') return 'var(--tier-critical)';
    if (tier === 'VERIFY') return 'var(--tier-high)';
    if (tier === 'MONITOR') return 'var(--tier-elevated)';
    return 'var(--tier-benign)';
  }, [tier]);

  // SVG arc gauge (180° semicircle across r=60)
  const radius = 60;
  const circumference = Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, trust));
  const progress = (clamped / 100) * circumference;

  return (
    <div className="card card--trust">
      <div className="card-header">
        <span className="card-title">
          Trust State <span className="card-stage-tag">S7</span>
        </span>
        <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          {samplingMult}x rate {prewarm ? '· WAL ARMED' : ''}
        </span>
      </div>
      <div className="gauge-container">
        <svg className="gauge-svg" viewBox="0 0 160 90">
          <path
            d="M 20 80 A 60 60 0 0 1 140 80"
            fill="none"
            stroke="rgba(148, 163, 184, 0.1)"
            strokeWidth="10"
            strokeLinecap="round"
          />
          <path
            d="M 20 80 A 60 60 0 0 1 140 80"
            fill="none"
            stroke={tierColor}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{ transition: 'stroke-dasharray 0.35s ease, stroke 0.25s ease' }}
          />
        </svg>
        <div className="gauge-value" style={{ color: tierColor }}>
          {trust !== null ? trust.toFixed(1) : '—'}
        </div>
        <div className="gauge-label">Trust Score</div>
        <span className={`tier-badge ${tier}`}>{tier.replace('_', ' ')}</span>
        {shouldContain && (
          <div style={{ marginTop: '4px', color: 'var(--tier-critical)', fontSize: '0.7rem', fontWeight: 700 }}>
            ⚠️ CONTAINMENT TRIGGERED
          </div>
        )}
      </div>
    </div>
  );
}
