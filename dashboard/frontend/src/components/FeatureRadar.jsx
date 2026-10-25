/**
 * FeatureRadar.jsx — Stage 4 feature vector spider/radar chart
 * Renders a canvas-based radar chart showing the 7D feature vector.
 */
import { useRef, useEffect } from 'react';

const FEATURES = [
  { key: 'S_entropy', label: 'Entropy' },
  { key: 'S_ETD', label: 'ETD' },
  { key: 'S_dist', label: 'Dist' },
  { key: 'S_dev', label: 'Dev' },
  { key: 'S_stab', label: 'Stab' },
  { key: 'lambda_norm', label: 'λ_norm' },
];

function drawRadar(ctx, w, h, values) {
  const cx = w / 2;
  const cy = h / 2;
  const r = Math.min(cx, cy) - 30;
  const n = FEATURES.length;
  const angleStep = (2 * Math.PI) / n;

  ctx.clearRect(0, 0, w, h);

  // Draw concentric rings
  for (let ring = 1; ring <= 4; ring++) {
    const rr = (r * ring) / 4;
    ctx.beginPath();
    for (let i = 0; i <= n; i++) {
      const angle = -Math.PI / 2 + i * angleStep;
      const x = cx + rr * Math.cos(angle);
      const y = cy + rr * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Draw axis lines + labels
  for (let i = 0; i < n; i++) {
    const angle = -Math.PI / 2 + i * angleStep;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);

    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.1)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Label
    const lx = cx + (r + 18) * Math.cos(angle);
    const ly = cy + (r + 18) * Math.sin(angle);
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(FEATURES[i].label, lx, ly);
  }

  // Draw value polygon
  ctx.beginPath();
  for (let i = 0; i < n; i++) {
    const angle = -Math.PI / 2 + i * angleStep;
    const v = Math.min(values[i] || 0, 1);
    const x = cx + r * v * Math.cos(angle);
    const y = cy + r * v * Math.sin(angle);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.closePath();
  ctx.fillStyle = 'rgba(99, 102, 241, 0.15)';
  ctx.fill();
  ctx.strokeStyle = '#6366f1';
  ctx.lineWidth = 2;
  ctx.stroke();

  // Draw value dots
  for (let i = 0; i < n; i++) {
    const angle = -Math.PI / 2 + i * angleStep;
    const v = Math.min(values[i] || 0, 1);
    const x = cx + r * v * Math.cos(angle);
    const y = cy + r * v * Math.sin(angle);
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, 2 * Math.PI);
    ctx.fillStyle = '#818cf8';
    ctx.fill();
  }
}

export default function FeatureRadar({ latestEvent }) {
  const canvasRef = useRef(null);
  const s4 = latestEvent?.stage_4 || {};

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const values = FEATURES.map(f => s4[f.key] ?? 0);
    drawRadar(ctx, rect.width, rect.height, values);
  }, [s4]);

  return (
    <div className="card card--features">
      <div className="card-header">
        <span className="card-title">
          Feature Vector
          <span className="card-stage-tag">S4</span>
        </span>
        <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          {s4.is_superheated ? '🔥 SUPERHEATED' : ''}
        </span>
      </div>
      <div className="radar-container">
        <canvas ref={canvasRef} className="radar-canvas" />
      </div>
    </div>
  );
}
