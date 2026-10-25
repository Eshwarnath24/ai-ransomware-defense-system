/**
 * ThreatGauge.jsx — Stage 6 IntentDrift radial gauge
 * Shows the current IntentDrift value (0.0–1.0) with an animated
 * semi-circular gauge colored by threat tier zones.
 */
import { useMemo } from 'react';

function getTierColor(drift) {
  if (drift < 0.10) return 'var(--tier-benign)';
  if (drift < 0.40) return 'var(--tier-elevated)';
  if (drift < 0.75) return 'var(--tier-high)';
  return 'var(--tier-critical)';
}

function getTierName(drift) {
  if (drift < 0.10) return 'BENIGN';
  if (drift < 0.40) return 'ELEVATED';
  if (drift < 0.75) return 'HIGH';
  return 'CRITICAL';
}

export default function ThreatGauge({ latestEvent }) {
  const drift = latestEvent?.stage_6?.IntentDrift ?? 0;
  const driftRate = latestEvent?.stage_6?.drift_rate ?? 0;
  const color = getTierColor(drift);
  const tier = getTierName(drift);

  // SVG arc parameters
  const cx = 80, cy = 80, r = 65;
  const startAngle = Math.PI;
  const endAngle = 0;
  const totalAngle = Math.PI;
  const angle = startAngle - drift * totalAngle;

  const arcPath = useMemo(() => {
    // Background arc (full semicircle)
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy - r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle);
    const y2 = cy - r * Math.sin(endAngle);
    return `M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2}`;
  }, []);

  const valuePath = useMemo(() => {
    if (drift <= 0.001) return '';
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy - r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(angle);
    const y2 = cy - r * Math.sin(angle);
    const largeArc = drift > 0.5 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`;
  }, [drift, angle]);

  return (
    <div className="card card--gauge">
      <div className="card-header">
        <span className="card-title">
          IntentDrift Gauge
          <span className="card-stage-tag">S6</span>
        </span>
        <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          d/dt: {driftRate >= 0 ? '+' : ''}{driftRate.toFixed(4)}
        </span>
      </div>
      <div className="gauge-container">
        <svg className="gauge-svg" viewBox="0 0 160 100" overflow="visible">
          {/* Tier zone arcs */}
          <path d={arcPath} fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth="10" strokeLinecap="round" />
          {/* Value arc */}
          {valuePath && (
            <path d={valuePath} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'all 0.3s ease' }} />
          )}
          {/* Needle dot */}
          <circle cx={cx + r * Math.cos(angle)} cy={cy - r * Math.sin(angle)}
            r="5" fill={color} style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'all 0.3s ease' }} />
        </svg>
        <div className="gauge-value" style={{ color }}>{drift.toFixed(3)}</div>
        <div className="gauge-label">IntentDrift</div>
        <div className="gauge-tier" style={{ background: `${color}15`, color, border: `1px solid ${color}40` }}>
          {tier}
        </div>
      </div>
    </div>
  );
}
