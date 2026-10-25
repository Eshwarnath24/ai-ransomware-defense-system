/**
 * DriftTimeline.jsx — Stage 6 IntentDrift over time
 * Canvas-based time-series chart showing IntentDrift values
 * with threat tier zone bands.
 */
import { useRef, useEffect, useState } from 'react';

export default function DriftTimeline({ events }) {
  const canvasRef = useRef(null);

  // Collect recent drift values (newest first → reverse for chart)
  const driftData = events
    .slice(0, 80)
    .map(e => ({
      drift: e.stage_6?.IntentDrift ?? 0,
      time: e.server_time || 0,
    }))
    .reverse();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const w = rect.width;
    const h = rect.height;

    ctx.clearRect(0, 0, w, h);

    const pad = { top: 10, right: 10, bottom: 20, left: 40 };
    const chartW = w - pad.left - pad.right;
    const chartH = h - pad.top - pad.bottom;

    // Tier zone bands
    const tiers = [
      { min: 0, max: 0.10, color: 'rgba(16,185,129,0.06)', label: 'BENIGN' },
      { min: 0.10, max: 0.40, color: 'rgba(245,158,11,0.06)', label: 'ELEVATED' },
      { min: 0.40, max: 0.75, color: 'rgba(249,115,22,0.06)', label: 'HIGH' },
      { min: 0.75, max: 1.00, color: 'rgba(239,68,68,0.08)', label: 'CRITICAL' },
    ];

    tiers.forEach(tier => {
      const y1 = pad.top + chartH * (1 - tier.max);
      const y2 = pad.top + chartH * (1 - tier.min);
      ctx.fillStyle = tier.color;
      ctx.fillRect(pad.left, y1, chartW, y2 - y1);

      // Tier label
      ctx.fillStyle = '#475569';
      ctx.font = '9px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(tier.label, pad.left + 4, y1 + 10);
    });

    // Horizontal grid lines
    [0, 0.25, 0.50, 0.75, 1.0].forEach(v => {
      const y = pad.top + chartH * (1 - v);
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + chartW, y);
      ctx.strokeStyle = 'rgba(148,163,184,0.08)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Y-axis label
      ctx.fillStyle = '#64748b';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.fillText(v.toFixed(2), pad.left - 4, y + 3);
    });

    // Draw threshold lines
    [0.10, 0.40, 0.75].forEach(threshold => {
      const y = pad.top + chartH * (1 - threshold);
      ctx.beginPath();
      ctx.setLineDash([4, 4]);
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + chartW, y);
      ctx.strokeStyle = 'rgba(148,163,184,0.15)';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);
    });

    if (driftData.length < 2) {
      ctx.fillStyle = '#64748b';
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Accumulating drift data...', w / 2, h / 2);
      return;
    }

    // Draw line
    ctx.beginPath();
    driftData.forEach((d, i) => {
      const x = pad.left + (i / (driftData.length - 1)) * chartW;
      const y = pad.top + chartH * (1 - Math.min(d.drift, 1));
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#818cf8';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Gradient fill under line
    const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    gradient.addColorStop(0, 'rgba(99,102,241,0.2)');
    gradient.addColorStop(1, 'rgba(99,102,241,0)');
    ctx.lineTo(pad.left + chartW, pad.top + chartH);
    ctx.lineTo(pad.left, pad.top + chartH);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Latest point dot
    if (driftData.length > 0) {
      const last = driftData[driftData.length - 1];
      const lx = pad.left + chartW;
      const ly = pad.top + chartH * (1 - Math.min(last.drift, 1));
      ctx.beginPath();
      ctx.arc(lx, ly, 4, 0, 2 * Math.PI);
      ctx.fillStyle = '#6366f1';
      ctx.fill();
      ctx.beginPath();
      ctx.arc(lx, ly, 7, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(99,102,241,0.4)';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  }, [driftData]);

  return (
    <div className="card card--timeline">
      <div className="card-header">
        <span className="card-title">
          Drift Timeline
          <span className="card-stage-tag">S6</span>
        </span>
      </div>
      <div className="timeline-container">
        <canvas ref={canvasRef} className="timeline-canvas" />
      </div>
    </div>
  );
}
