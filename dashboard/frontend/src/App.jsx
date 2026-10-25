/**
 * App.jsx — Root application component
 * Assembles all dashboard panels and manages WebSocket connection.
 */
import { useWebSocket } from './hooks/useWebSocket';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import ThreatGauge from './components/ThreatGauge';
import SignalDecomposition from './components/SignalDecomposition';
import FeatureRadar from './components/FeatureRadar';
import DBRGGraph from './components/DBRGGraph';
import AnomalyPanel from './components/AnomalyPanel';
import DriftTimeline from './components/DriftTimeline';
import LiveEventTable from './components/LiveEventTable';
import LineagePanel from './components/LineagePanel';
import AlertModal from './components/AlertModal';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live';

export default function App() {
  const { events, latestEvent, connected } = useWebSocket(WS_URL, API_BASE);

  return (
    <div className="app-layout">
      <Sidebar latestEvent={latestEvent} />

      <div className="main-content">
        <Header connected={connected} latestEvent={latestEvent} totalEvents={events.length} />

        <div className="dashboard-grid">
          {/* Row 1: Stage 6 Gauge | Stage 6 Signals | Stage 4 Features */}
          <ThreatGauge latestEvent={latestEvent} />
          <SignalDecomposition latestEvent={latestEvent} />
          <FeatureRadar latestEvent={latestEvent} />

          {/* Row 2-3: Stage 3 DBRG Graph (spans 2 cols, 2 rows) | Stage 5 Anomaly */}
          <DBRGGraph />
          <AnomalyPanel latestEvent={latestEvent} />

          {/* Row 3: (DBRG continues) | Stage 6 Drift Timeline */}
          <DriftTimeline events={events} />

          {/* Row 4: Stage 1 Event Log | Stage 2 Lineage */}
          <LiveEventTable events={events} />
          <LineagePanel events={events} />
        </div>
      </div>

      {/* CRITICAL alert overlay */}
      <AlertModal latestEvent={latestEvent} />
    </div>
  );
}
