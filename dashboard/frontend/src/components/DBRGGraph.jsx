/**
 * DBRGGraph.jsx — Stage 3 Dynamic Behavior Relationship Graph
 * Interactive canvas-based graph visualization of Process→File relationships
 * with TDEW-weighted edges. Polls /api/graph every 2 seconds.
 */
import { useRef, useEffect, useState, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function layoutGraph(nodes, edges, width, height) {
  // Simple force-directed-ish layout
  const processNodes = nodes.filter(n => n.data.type === 'process');
  const fileNodes = nodes.filter(n => n.data.type === 'file');

  const positions = {};
  const cx = width / 2, cy = height / 2;
  const pr = Math.min(width, height) * 0.25;
  const fr = Math.min(width, height) * 0.42;

  processNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(processNodes.length, 1) - Math.PI / 2;
    positions[n.data.id] = { x: cx + pr * Math.cos(angle), y: cy + pr * Math.sin(angle) };
  });

  fileNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(fileNodes.length, 1);
    positions[n.data.id] = { x: cx + fr * Math.cos(angle), y: cy + fr * Math.sin(angle) };
  });

  return positions;
}

function drawGraph(ctx, w, h, graphData) {
  ctx.clearRect(0, 0, w, h);
  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '13px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for DBRG graph data...', w / 2, h / 2 - 10);
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText('Generate file activity to build the graph', w / 2, h / 2 + 10);
    return;
  }

  const { nodes, edges } = graphData;
  const positions = layoutGraph(nodes, edges, w, h);

  // Draw edges
  edges.forEach(edge => {
    const from = positions[edge.data.source];
    const to = positions[edge.data.target];
    if (!from || !to) return;

    const weight = edge.data.weight || 1;
    const alpha = Math.min(0.2 + weight * 0.15, 0.8);
    const lineWidth = Math.max(1, Math.min(weight * 1.5, 4));

    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.strokeStyle = `rgba(99, 102, 241, ${alpha})`;
    ctx.lineWidth = lineWidth;
    ctx.stroke();

    // Arrow
    const angle = Math.atan2(to.y - from.y, to.x - from.x);
    const arrowLen = 8;
    const arrowX = to.x - 14 * Math.cos(angle);
    const arrowY = to.y - 14 * Math.sin(angle);
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(arrowX - arrowLen * Math.cos(angle - 0.4), arrowY - arrowLen * Math.sin(angle - 0.4));
    ctx.lineTo(arrowX - arrowLen * Math.cos(angle + 0.4), arrowY - arrowLen * Math.sin(angle + 0.4));
    ctx.closePath();
    ctx.fillStyle = `rgba(99, 102, 241, ${alpha})`;
    ctx.fill();
  });

  // Draw nodes
  nodes.forEach(node => {
    const pos = positions[node.data.id];
    if (!pos) return;

    const isProcess = node.data.type === 'process';
    const radius = isProcess ? 10 : 7;
    const color = isProcess ? '#6366f1' : '#10b981';
    const glowColor = isProcess ? 'rgba(99,102,241,0.3)' : 'rgba(16,185,129,0.3)';

    // Glow
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, radius + 4, 0, 2 * Math.PI);
    ctx.fillStyle = glowColor;
    ctx.fill();

    // Node circle
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, radius, 0, 2 * Math.PI);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = 'rgba(255,255,255,0.15)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Label
    const label = node.data.label || '?';
    const displayLabel = label.length > 16 ? label.slice(0, 14) + '..' : label;
    ctx.fillStyle = '#e2e8f0';
    ctx.font = `${isProcess ? '10' : '9'}px "JetBrains Mono", monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(displayLabel, pos.x, pos.y + radius + 4);
  });

  // Legend
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'left';

  ctx.beginPath();
  ctx.arc(12, h - 28, 5, 0, 2 * Math.PI);
  ctx.fillStyle = '#6366f1';
  ctx.fill();
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Process', 22, h - 32);

  ctx.beginPath();
  ctx.arc(12, h - 12, 5, 0, 2 * Math.PI);
  ctx.fillStyle = '#10b981';
  ctx.fill();
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('File', 22, h - 16);

  ctx.fillStyle = '#64748b';
  ctx.textAlign = 'right';
  ctx.fillText(`${nodes.length} nodes · ${edges.length} edges`, w - 10, h - 12);
}

export default function DBRGGraph() {
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState(null);

  const fetchGraph = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/graph`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
      }
    } catch (e) { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchGraph();
    const interval = setInterval(fetchGraph, 2000);
    return () => clearInterval(interval);
  }, [fetchGraph]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    drawGraph(ctx, rect.width, rect.height, graphData);
  }, [graphData]);

  return (
    <div className="card card--graph">
      <div className="card-header">
        <span className="card-title">
          DBRG — Process→File Graph
          <span className="card-stage-tag">S3</span>
        </span>
        <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          TDEW-weighted edges
        </span>
      </div>
      <div className="dbrg-graph-container">
        <canvas ref={canvasRef} style={{ width: '100%', height: '100%' }} />
      </div>
    </div>
  );
}
