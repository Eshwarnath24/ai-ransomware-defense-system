/**
 * AttackLauncher.jsx — Stage 8 Attack Simulator & Complete Live Demo Control
 * Launches simulated ransomware profiles (Interactive SOC or Full Auto-Mitigation Demo)
 * as well as benign OS file activity through Stages 1-10 in real time.
 */
import { useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const PROFILES = [
  { id: 'lockbit', name: 'LockBit 3.0', desc: 'Fast batch=5 (.locked)', icon: '⚡' },
  { id: 'wannacry', name: 'WannaCry', desc: 'Burst batch=3 (.WNCRY)', icon: '🐛' },
  { id: 'blackcat', name: 'BlackCat/ALPHV', desc: 'Stealth 250ms (.encrypted)', icon: '🐈‍⬛' },
];

export default function AttackLauncher({ latestAttackEvent }) {
  const [profile, setProfile] = useState('lockbit');
  const [numFiles, setNumFiles] = useState(13);
  const [launching, setLaunching] = useState(false);
  const [lastResult, setLastResult] = useState(null);

  const triggerAttack = async (autoResolve = null) => {
    setLaunching(true);
    setLastResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile,
          num_files: numFiles,
          auto_resolve: autoResolve,
        }),
      });
      const data = await res.json();
      setLastResult({ ...data, mode: autoResolve ? 'AUTO_MITIGATE' : 'INTERACTIVE' });
    } catch (e) {
      setLastResult({ error: e.message });
    }
    setLaunching(false);
  };

  const triggerBenign = async () => {
    setLaunching(true);
    setLastResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/benign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ num_files: 5 }),
      });
      const data = await res.json();
      setLastResult({ ...data, mode: 'BENIGN' });
    } catch (e) {
      setLastResult({ error: e.message });
    }
    setLaunching(false);
  };

  return (
    <div className="card card--attack">
      <div className="card-header">
        <span className="card-title">
          Live Attack &amp; Demo Control <span className="card-stage-tag">S8</span>
        </span>
        {latestAttackEvent && (
          <span className={`tier-badge ${latestAttackEvent.containment_triggered ? 'CRITICAL' : 'ELEVATED'}`}>
            {latestAttackEvent.status}: {latestAttackEvent.files_encrypted ?? 0}/{latestAttackEvent.total_files ?? numFiles}
          </span>
        )}
      </div>

      <div className="attack-controls">
        <div className="attack-profiles">
          {PROFILES.map(p => (
            <button
              key={p.id}
              type="button"
              className={`attack-profile-btn ${profile === p.id ? 'selected' : ''}`}
              onClick={() => setProfile(p.id)}
            >
              <span className="attack-profile-icon">{p.icon}</span>
              <span className="attack-profile-name">{p.name}</span>
              <span className="attack-profile-desc">{p.desc}</span>
            </button>
          ))}
        </div>

        <div className="attack-settings">
          <label className="attack-label">
            Victim Files:
            <input
              type="number"
              min="5"
              max="30"
              value={numFiles}
              onChange={e => setNumFiles(Math.max(5, Math.min(30, parseInt(e.target.value, 10) || 13)))}
              className="attack-input"
            />
          </label>
          <button
            type="button"
            className="attack-launch-btn"
            onClick={() => triggerAttack(null)}
            disabled={launching}
            title="Runs Stages 1-9 and pauses for analyst resolution in Stage 10"
          >
            {launching ? '⏳ Launching...' : '🚀 Interactive SOC Attack'}
          </button>
          <button
            type="button"
            className="attack-auto-btn"
            onClick={() => triggerAttack('MALICIOUS')}
            disabled={launching}
            title="Runs full Attack → Freeze → Vault Rollback → Zero-Data-Loss Proof automatically"
          >
            ⚡ Full Auto-Mitigate Demo
          </button>
          <button
            type="button"
            className="attack-benign-btn"
            onClick={triggerBenign}
            disabled={launching}
            title="Generates normal benign file saves monitored live by Stage 1"
          >
            🟢 Benign Activity
          </button>
        </div>

        {lastResult && (
          <div className={`attack-result ${lastResult.error ? 'error' : 'success'}`}>
            {lastResult.error ? (
              `❌ ${lastResult.error}`
            ) : lastResult.mode === 'BENIGN' ? (
              `🟢 Benign workload running (${lastResult.num_files} low-entropy files) — watch live Stage 1-7 telemetry stay SAFE`
            ) : lastResult.mode === 'AUTO_MITIGATE' ? (
              `⚡ Auto-Mitigation Demo started — PID ${lastResult.pid} | ${lastResult.profile_display} | ${lastResult.num_files} victim files`
            ) : (
              `🚀 Interactive Attack started — PID ${lastResult.pid} | ${lastResult.profile_display} | ${lastResult.num_files} victim files`
            )}
          </div>
        )}
      </div>
    </div>
  );
}
