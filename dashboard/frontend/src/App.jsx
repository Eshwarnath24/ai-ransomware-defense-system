/**
 * App.jsx — Root application component
 * Assembles all dashboard panels (Stages 1-11) and manages WebSocket streams.
 */
import { useWebSocket } from './hooks/useWebSocket';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import ThreatGauge from './components/ThreatGauge';
import TrustGauge from './components/TrustGauge';
import SignalDecomposition from './components/SignalDecomposition';
import FeatureRadar from './components/FeatureRadar';
import DBRGGraph from './components/DBRGGraph';
import AnomalyPanel from './components/AnomalyPanel';
import DriftTimeline from './components/DriftTimeline';
import ContainmentPanel from './components/ContainmentPanel';
import AttackLauncher from './components/AttackLauncher';
import ResolutionPanel from './components/ResolutionPanel';
import LiveEventTable from './components/LiveEventTable';
import LineagePanel from './components/LineagePanel';
import AlertModal from './components/AlertModal';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live';

export default function App() {
  const {
    events,
    latestEvent,
    connected,
    latestAttackEvent,
    latestContainment,
    latestResolution,
  } = useWebSocket(WS_URL, API_BASE);

  return (
    <div className="app-layout">
      <Sidebar latestEvent={latestEvent} />

      <div className="main-content">
        <Header
          connected={connected}
          latestEvent={latestEvent}
          latestResolution={latestResolution}
          totalEvents={events.length}
        />

        <div className="dashboard-grid">
          {/* Row 1: S6 Gauge | S7 Trust | S6 Signals | S4 Features */}
          <ThreatGauge latestEvent={latestEvent} latestResolution={latestResolution} />
          <TrustGauge latestEvent={latestEvent} latestResolution={latestResolution} />
          <SignalDecomposition latestEvent={latestEvent} />
          <FeatureRadar latestEvent={latestEvent} />

          {/* Row 2-3: S3 DBRG Graph (2cols, 2rows) | S5 Anomaly | S9 Containment */}
          <DBRGGraph />
          <AnomalyPanel latestEvent={latestEvent} />
          <ContainmentPanel
            latestEvent={latestEvent}
            latestContainment={latestContainment}
            latestResolution={latestResolution}
          />

          {/* Row 3: (DBRG continues) | S6 Drift Timeline | (Containment continues) */}
          <DriftTimeline events={events} />

          {/* Row 4: S8 Attack Simulator | S10 Enforcement & Rollback Output */}
          <AttackLauncher latestAttackEvent={latestAttackEvent} />
          <ResolutionPanel
            latestResolution={latestResolution}
            latestContainment={latestContainment}
          />

          {/* Row 5: S1 Event Log | S2 Lineage */}
          <LiveEventTable events={events} />
          <LineagePanel events={events} />
        </div>
      </div>

      {/* CRITICAL / Containment alert overlay */}
      <AlertModal latestEvent={latestEvent} latestResolution={latestResolution} />
    </div>
  );
}
