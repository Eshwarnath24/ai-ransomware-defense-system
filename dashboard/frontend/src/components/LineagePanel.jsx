/**
 * LineagePanel.jsx — Stage 2 Process Lineage & Rarity
 * Shows parent→child process relationships with S_rel rarity scores.
 */
import { useMemo } from 'react';

export default function LineagePanel({ events }) {
  // Deduplicate lineage entries by parent+child pair
  const lineageEntries = useMemo(() => {
    const seen = new Map();
    for (const evt of events) {
      const s1 = evt.stage_1 || {};
      const s2 = evt.stage_2 || {};
      const parentExe = s2.parent_exe_name || 'UNKNOWN';
      const childExe = s1.exe_name || 'UNKNOWN';
      const key = `${parentExe}→${childExe}`;
      if (!seen.has(key)) {
        seen.set(key, {
          parent: parentExe,
          child: childExe,
          S_rel: s2.S_rel ?? 0.5,
          ppid: s2.ppid ?? -1,
          pid: s1.pid ?? -1,
        });
      }
    }
    return Array.from(seen.values()).sort((a, b) => b.S_rel - a.S_rel);
  }, [events]);

  const getSrelColor = (srel) => {
    if (srel < 0.2) return 'var(--tier-benign)';
    if (srel < 0.5) return 'var(--tier-elevated)';
    if (srel < 0.8) return 'var(--tier-high)';
    return 'var(--tier-critical)';
  };

  return (
    <div className="card card--lineage">
      <div className="card-header">
        <span className="card-title">
          Process Lineage
          <span className="card-stage-tag">S2</span>
        </span>
        <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          {lineageEntries.length} pairs
        </span>
      </div>
      <div className="lineage-tree">
        {lineageEntries.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔗</div>
            <div>No lineage data yet</div>
          </div>
        ) : (
          lineageEntries.slice(0, 20).map((entry, i) => (
            <div
              key={i}
              className={`lineage-item ${entry.S_rel >= 0.7 ? 'rare' : ''}`}
              style={{ borderLeftColor: getSrelColor(entry.S_rel) }}
            >
              <span className="lineage-exe">{entry.parent}</span>
              <span className="lineage-arrow">→</span>
              <span className="lineage-exe">{entry.child}</span>
              <span className="lineage-srel" style={{ color: getSrelColor(entry.S_rel) }}>
                S_rel: {entry.S_rel.toFixed(2)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
