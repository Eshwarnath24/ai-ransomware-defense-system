/**
 * SignalDecomposition.jsx — Stage 6 weighted signal breakdown
 * Shows the 5 sub-signals (S_entropy, S_dist, S_dev, S_rel, 1-S_stab)
 * as horizontal bars with their contribution weights.
 */
const SIGNAL_CONFIG = [
  { key: 'S_entropy', label: 'S_entropy', color: 'var(--signal-entropy)', weight: 0.35 },
  { key: 'S_dist',    label: 'S_dist',    color: 'var(--signal-dist)',    weight: 0.30 },
  { key: 'S_dev',     label: 'S_dev',     color: 'var(--signal-dev)',     weight: 0.20 },
  { key: 'S_rel',     label: 'S_rel',     color: 'var(--signal-rel)',     weight: 0.10 },
  { key: 'S_stab_inv',label: '1-S_stab',  color: 'var(--signal-stab)',   weight: 0.05 },
];

export default function SignalDecomposition({ latestEvent }) {
  const signals = latestEvent?.stage_6?.signals || {};
  const composite = latestEvent?.stage_6?.S_composite ?? 0;

  return (
    <div className="card card--signals">
      <div className="card-header">
        <span className="card-title">
          Signal Weights
          <span className="card-stage-tag">S6</span>
        </span>
        <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>
          S_comp: {composite.toFixed(3)}
        </span>
      </div>
      <div className="signal-bars">
        {SIGNAL_CONFIG.map(sig => {
          const value = signals[sig.key] ?? 0;
          return (
            <div key={sig.key} className="signal-row">
              <span className="signal-label">{sig.label}</span>
              <div className="signal-bar-track">
                <div
                  className="signal-bar-fill"
                  style={{
                    width: `${Math.min(value * 100, 100)}%`,
                    background: `linear-gradient(90deg, ${sig.color}80, ${sig.color})`,
                  }}
                />
              </div>
              <span className="signal-value">{value.toFixed(2)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
