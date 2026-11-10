# 🛡️ Real-Time Non-Destructive Ransomware Defense System (BIRF)

![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)
![Tests Passing](https://img.shields.io/badge/Tests-484%2F484%20PASSED-brightgreen?style=for-the-badge&logo=pytest)
![Stage 1](https://img.shields.io/badge/Stage%201-20%2F20-brightgreen?style=for-the-badge)
![Stage 2](https://img.shields.io/badge/Stage%202-16%2F16-brightgreen?style=for-the-badge)
![Stage 3](https://img.shields.io/badge/Stage%203-28%2F28-brightgreen?style=for-the-badge)
![Stage 4](https://img.shields.io/badge/Stage%204-62%2F62-brightgreen?style=for-the-badge)
![Stage 5](https://img.shields.io/badge/Stage%205-30%2F30-brightgreen?style=for-the-badge)
![Stage 6](https://img.shields.io/badge/Stage%206-170%2F170-brightgreen?style=for-the-badge)
![Stage 7](https://img.shields.io/badge/Stage%207-36%2F36-brightgreen?style=for-the-badge)
![Stage 8](https://img.shields.io/badge/Stage%208-59%2F59-brightgreen?style=for-the-badge)
![Stage 9](https://img.shields.io/badge/Stage%209-61%2F61-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **A Machine Learning & OS-Kernel Level Defense Pipeline for Real-Time Ransomware Interception, Behavioral Intent Modeling, Dynamic Adaptive Trust Evolution, and Zero-Data-Loss Rollback.**

---

## 📌 Executive Overview

The **Behavioral Intent Recognition Framework (BIRF)** is a 12-stage enterprise security system designed to observe low-level operating system events, model behavioral relationship dynamics using exponential time-decay mathematics, evaluate threat intent across multi-signal corroboration engines, adaptively evolve per-process trust scores, and enforce kernel-level isolation with zero-data-loss rollback.

> [!NOTE]
> **Core Architectural Principle — Non-Destructive Intent Convergence:**  
> Rather than terminating processes on the very first high-entropy write (which causes disastrous false positives on benign tools like 7-Zip, WinRAR, or video exporters), this system tracks multi-signal behavioral intent across a minimal 2-to-3 file observation window (~80 ms), pre-warms write-ahead journals, halts malware via kernel suspension, and rolls back sacrificial files to achieve **Net-Zero Data Loss**.

---

## 🏗️ End-to-End System Architecture Roadmap

```text
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                            STAGE 1: TELEMETRY COLLECTION                          │  ✅ (20/20 PASSED)
 │                Asynchronous File I/O Interception, Process Provenance             │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (eCAR JSON Telemetry Stream in SQLite)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                      STAGE 2: PROCESS IDENTIFICATION & LINEAGE                    │  ✅ (16/16 PASSED)
 │                 Provenance Tracing & Parent-Child Lineage Rarity (S_rel)          │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (Context-Enriched eCAR Events)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                STAGE 3: DYNAMIC BEHAVIOR RELATIONSHIP GRAPH (DBRG)                │  ✅ (28/28 PASSED)
 │                  Exponential Time-Decayed Edge Weighting (TDEW Engine)            │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (Live Process->File Directed Graph)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │            STAGE 4: MULTI-LAYER FEATURE EXTRACTION & HAWKES PROCESS               │  ✅ (62/62 PASSED)
 │         4KB Buffer Sampling, Shannon Entropy, ETD, Hawkes Point Process           │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (Feature Vector: S_entropy, S_ETD, S_dist, S_dev, S_stab, λ_norm)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                 STAGE 5: ANOMALY SCORING & BENIGN PROFILING (DAC-OCF)             │  ✅ (30/30 PASSED)
 │              Dual Isolation Forest + One-Class SVM, Leakage-Free Sysmon ML        │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (Anomaly Scores: S_IF, S_OCSVM, S_anomaly)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │            STAGE 6: MULTI-SIGNAL CORROBORATION & SIGMOIDAL ACCELERATION           │  ✅ (170/170 PASSED)
 │             Priority Weighting, Logistic Intent Drift, Velocity Differentiation   │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (IntentDrift(t), d(Drift)/dt, Threat Tier)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │          STAGE 7: DYNAMIC ADAPTIVE TRUST EVOLUTION & RISK STATE ENGINE            │  ✅ (36/36 PASSED)
 │           Exponential Decay, Momentum Penalty, Risk Tiers (SAFE -> CRITICAL)      │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (Trust(t), Risk Tier, prewarm_journal, should_contain)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                  STAGE 8: SYNTHETIC RANSOMWARE TEST HARNESS                       │  ✅ (59/59 PASSED)
 │         Sandboxed Multi-Profile Simulator (LockBit, WannaCry, BlackCat), Latency  │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                 STAGE 9: FREEZE-GRAPH MIN-CUT CONTAINMENT ENGINE                  │  ✅ (61/61 PASSED)
 │           NtSuspendProcess Kernel Halt, Edmonds-Karp Minimum Cut Optimization     │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │            STAGE 10: FINE-GRAINED ENFORCER, JOURNALING & ROLLBACK                 │  📅 (UPCOMING)
 │               Write-Ahead Journaling Vault & Zero-Data-Loss Restoration           │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                   STAGE 11: SOC DASHBOARD & INTERACTIVE OVERRIDE                  │  ⚡ (UI BUILT)
 │               FastAPI WebSocket Backend & React/Vite Cytoscape UI                 │
 └───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚦 Project Implementation Status Matrix

| Stage | Module Name | Primary Role | Status | Tests | Key Capabilities & Metrics |
|---|---|---|:---:|:---:|---|
| **Stage 1** | **Telemetry Collection** | File I/O Interception, Process Provenance, SQLite WAL | ✅ **Completed** | 20/20 | 50ms deduplication, asynchronous queueing |
| **Stage 2** | **Lineage Analysis** | Parent-Child Provenance & Lineage Rarity ($S_{\text{rel}}$) | ✅ **Completed** | 16/16 | Living-off-the-Land (LotL) detection |
| **Stage 3** | **DBRG Graph Engine** | NetworkX DiGraph with Exponential Decay (TDEW) | ✅ **Completed** | 28/28 | Active event reinforcement & passive decay sweeps |
| **Stage 4** | **Feature Extraction** | 4KB Buffer Sampling, Shannon Entropy, Hawkes Process | ✅ **Completed** | 62/62 | Shannon $H$, ETD KL-divergence, $\lambda(t)$ burst |
| **Stage 5** | **ML Anomaly Scoring** | DAC-OCF (Isolation Forest + OCSVM) | ✅ **Completed** | 30/30 | Authentic Sysmon RADAR ML: **85.1% Acc, 0.911 AUC** |
| **Stage 6** | **Threat Fusion** | Sigmoidal Intent Drift & Finite-Difference Acceleration | ✅ **Completed** | 170/170 | Multi-signal corroboration, single-signal suppression |
| **Stage 7** | **Trust State Engine** | Exponential Decay, Momentum Penalty, 4 Risk Tiers | ✅ **Completed** | 36/36 | SAFE $\to$ MONITOR $\to$ VERIFY $\to$ CRITICAL_RISK |
| **Stage 8** | **Synthetic Harness** | Sandboxed Red-Team Attack Simulator & Benchmark | ✅ **Completed** | 59/59 | LockBit, WannaCry, BlackCat profiles, latency clock |
| **Stage 9** | **Kernel Containment** | `NtSuspendProcess` Freeze-Graph Min-Cut Engine | ✅ **Completed** | 61/61 | Edmonds-Karp min-cut, boundary revocation, <2ms halt |
| **Stage 10** | **Journaling & Rollback** | Write-Ahead Journaling Vault & Zero-Data-Loss Restoration | 📅 *Upcoming* | — | Pre-warm shadow block capture, rollback engine |
| **Stage 11** | **SOC Dashboard** | FastAPI WebSocket Backend + React/Vite Cytoscape UI | ⚡ *Built* | — | Real-time threat visualizer & manual override |
| **Stage 12** | **Evaluation Sweep** | Parameter Ablation & Academic Benchmark Suite | 📅 *Upcoming* | — | Precision-Recall sweeps, latency ablation curves |

---

## 🔬 Mathematical & Algorithmic Foundations

### 1. Stage 3 — Dynamic Behavior Relationship Graph (DBRG + TDEW)
$$\text{Active Event: } W(e) = W_{\text{old}} \cdot e^{-\lambda \cdot \Delta t} + 1.0 \qquad \text{Passive Sweep: } W(e) = W_{\text{old}} \cdot e^{-\lambda \cdot \Delta t}$$

### 2. Stage 4 — Multi-Layer Features & Temporal Hawkes Burst
$$\text{Shannon Entropy: } H = -\sum_{i=0}^{255} P(x_i) \cdot \log_2 P(x_i) \quad \in [0, 8.0]$$
$$\text{Hawkes Intensity: } \lambda(t) = \mu + \sum_{t_i < t} \alpha \cdot e^{-\beta(t - t_i)} \qquad \text{Branching Ratio: } n = \frac{\alpha}{\beta}$$

### 3. Stage 5 — Density-Adaptive One-Class Fusion (DAC-OCF)
$$S_{\text{anomaly}} = 0.6 \cdot S_{\text{IF}} + 0.4 \cdot S_{\text{OCSVM}}$$

### 4. Stage 6 — Sigmoidal Multi-Signal Corroboration
$$S_{\text{composite}} = 0.35 S_{\text{entropy}} + 0.30 S_{\text{dist}} + 0.20 S_{\text{dev}} + 0.10 S_{\text{rel}} + 0.05(1 - S_{\text{stab}})$$
$$\text{IntentDrift}(t) = \frac{1}{1 + e^{-\beta(S_{\text{composite}} - \theta)}} \qquad \frac{d(\text{Drift})}{dt} = \frac{\text{Drift}(t) - \text{Drift}(t - \Delta t)}{\Delta t}$$

### 5. Stage 7 — Dynamic Adaptive Trust Evolution
$$\text{Trust}(t) = \text{Trust}_{\text{prev}} \cdot e^{-\gamma \cdot \text{IntentDrift}(t)} - \delta \cdot \max\left(0, \frac{d(\text{Drift})}{dt}\right)$$

```text
Trust Score:
100.0 ────────── 70.0 ────────── 50.0 ────────── 20.0 ────────── 0.0
   [  🟢 SAFE  ]     [ 🟡 MONITOR ]    [ 🟠 VERIFY ]    [ 🚨 CRITICAL ]
   1x Sampling       2x Sampling       4x Sampling      Kernel Freeze
                                       Pre-warm Journal (Stage 9 + 10)
```

### 6. Stage 8 — Microsecond Benchmark Metrics
$$\text{Detection Latency: } \Delta t_{\text{detect}} = \max(0, t_{\text{contain}} - t_0) \quad (\text{ms})$$
$$\text{Damage Footprint: } N_{\text{damage}} = \sum_{e \in \text{Events}} \mathbb{I}(t_e < t_{\text{contain}})$$

---

## 📁 Complete Project Directory Structure

```text
ai-ransomware-defense-system/
├── collector/                         # 🛡️ Stage 1: Telemetry Ingestion
│   ├── __init__.py                    # Package marker
│   ├── file_monitor.py                # Watchdog observer (50ms event deduplication)
│   ├── process_monitor.py             # Process monitor & mtime SHA-256 hash cache
│   ├── queue_joiner.py                # Thread-safe queue & 3-tier PID resolver
│   ├── ecar_formatter.py              # MITRE eCAR JSON schema formatter
│   ├── db_writer.py                   # SQLite WAL persistence layer
│   └── main.py                        # Main orchestrator & privilege checker
├── lineage/                           # 🌲 Stage 2: Lineage Analysis
│   ├── __init__.py
│   ├── tracker.py                     # Parent-child process provenance tree
│   ├── rarity_engine.py               # Lineage rarity score engine (S_rel)
│   └── demo_replay.py                 # Lineage replay utility
├── src/                               # ⚡ Core Pipeline Source Code
│   ├── __init__.py
│   ├── stage_3_dbrg/                  # 🕸️ Stage 3: DBRG & TDEW Graph Engine
│   │   ├── __init__.py
│   │   ├── tdew_calculator.py         # Exponential decay math engine
│   │   ├── dbrg_manager.py            # Thread-safe NetworkX DiGraph wrapper
│   │   ├── garbage_collector.py       # Daemon thread for passive edge pruning
│   │   └── visualize_dbrg.py          # Matplotlib & NetworkX graph visualizer
│   ├── stage_4_features/              # 📐 Stage 4: Feature Extraction & Hawkes
│   │   ├── __init__.py
│   │   ├── entropy_calculator.py      # 4KB buffer reader & Shannon entropy engine
│   │   ├── hawkes_engine.py           # Self-exciting Hawkes temporal intensity
│   │   ├── etd_engine.py              # Entropy-Topology Divergence (KL-divergence)
│   │   └── feature_extractor.py       # Multi-layer feature extraction orchestrator
│   ├── stage_5_anomaly/               # 🎯 Stage 5: Anomaly Scoring (DAC-OCF)
│   │   ├── __init__.py
│   │   ├── preprocessor.py            # Dataset loading, variance thresholding, scaling
│   │   ├── model_trainer.py           # Isolation Forest + OCSVM training pipeline
│   │   ├── anomaly_scorer.py          # Real-time scoring engine (ML mode + fallback)
│   │   └── train_stage5.py            # Training CLI script
│   ├── stage_6_fusion/                # ⚡ Stage 6: Threat Fusion & Sigmoid
│   │   ├── __init__.py
│   │   ├── composite_scorer.py        # Priority-weighted composite signal fusion
│   │   ├── sigmoid_engine.py          # Logistic sigmoidal acceleration & velocity
│   │   └── threat_fusion.py           # Stage 6 orchestrator consumed by Stage 7
│   ├── stage_7_trust/                 # 🛡️ Stage 7: Dynamic Trust Evolution
│   │   ├── __init__.py
│   │   ├── trust_engine.py            # Exponential trust decay & momentum penalty
│   │   ├── risk_state_machine.py      # 4-tier risk state machine & transition rules
│   │   ├── trust_evolution.py         # Stage 7 orchestrator
│   │   ├── live_stage7_monitor.py     # Live terminal monitor for Stages 1-7
│   │   └── demo_stage7_trust.py       # Standalone demonstration CLI
│   └── stage_8_harness/               # 🧪 Stage 8: Synthetic Ransomware Test Harness
│       ├── __init__.py
│       ├── sandbox_manager.py         # Isolated victim directory & path-safety guards
│       ├── attack_profiles.py         # LockBit, WannaCry, BlackCat speed presets
│       ├── attack_engine.py           # Multi-phase attack engine (encrypt, rename, notes)
│       ├── benchmark_logger.py        # Microsecond latency & damage tracker
│       └── runner.py                  # Standalone CLI & live pipeline orchestrator
├── dashboard/                         # 📊 Stage 11: Real-Time SOC Dashboard
│   ├── backend/                       # FastAPI WebSocket Server
│   │   ├── main.py                    # API endpoints & WebSocket broadcaster
│   │   └── pipeline_bridge.py         # Bridge connecting Stages 1-7 to UI stream
│   └── frontend/                      # React / Vite / Tailwind / Cytoscape UI
│       ├── src/App.jsx                # Main dashboard component
│       ├── src/components/            # Telemetry feed, graph visualizer, trust gauge
│       └── package.json
├── models/                            # 💾 Trained Model Artifacts
│   ├── isolation_forest.joblib        # Trained Isolation Forest model
│   ├── one_class_svm.joblib           # Trained One-Class SVM model
│   ├── scaler.joblib                  # Fitted MinMaxScaler
│   └── training_metadata.json         # Training metrics & hyperparameters
├── tests/                             # 🧪 Automated Test Suite (423 Tests)
│   ├── __init__.py
│   ├── test_stage1.py                 # 20 tests: Telemetry collection
│   ├── test_stage2.py                 # 16 tests: Lineage & rarity
│   ├── test_stage_3_dbrg.py           # 28 tests: DBRG graph & TDEW
│   ├── test_stage_4_features.py       # 62 tests: Features & Hawkes
│   ├── test_stage_5_anomaly.py        # 30 tests: DAC-OCF ML anomaly
│   ├── test_stage_6_fusion.py         # 170 tests: Multi-signal threat fusion
│   ├── test_stage_7_trust.py          # 36 tests: Trust decay & state machine
│   ├── test_stage_8_harness.py        # 59 tests: Synthetic harness & benchmarks
│   ├── manual_test_stage_3.py         # Interactive graph verification CLI
│   └── demo_ransomware_scenario.py    # Scenario demonstration
├── simulate_ransomware.py             # 💥 Stage 8 Powered Simulation CLI
├── config.yaml                        # ⚙️ Unified System Configuration
└── README.md                          # 📖 System Documentation
```

---

## 🚀 Quick Start & Live Demonstrations

### 1. Prerequisites & Installation

```bash
git clone https://github.com/Shanmukha-Gautam-Pidaparthi/ai-ransomware-defense-system.git
cd ai-ransomware-defense-system

# Install core dependencies
pip install -r requirements.txt
```

### 2. Run the Full Test Suite (423 Tests)

```bash
# Run all 423 automated tests across Stages 1–8
python -m pytest -q

# Run specific stage test suites
python -m pytest tests/test_stage_7_trust.py -v
python -m pytest tests/test_stage_8_harness.py -v
```

---

### 3. Live Stage 8 Red-Team Attack Demonstrations

#### Option A: Live Pipeline Detection Benchmark (Stages 2 $\to$ 7)
Execute synthetic ransomware directly against the live defense pipeline:

```bash
# 1. LockBit-Aggressive: Rapid multi-threaded burst (20ms interval)
python -m src.stage_8_harness.runner --profile lockbit --with-pipeline

# 2. WannaCry-Burst: Spreading worm traversal (50ms interval, batch 3)
python -m src.stage_8_harness.runner --profile wannacry --with-pipeline

# 3. BlackCat-Stealth: Low-and-slow evasion attempt (250ms interval)
python -m src.stage_8_harness.runner --profile blackcat --with-pipeline

# 4. Stress test with dynamic scaling (e.g. 50 victim files)
python -m src.stage_8_harness.runner --profile lockbit --num-files 50
```

#### Option B: Two-Terminal Live Monitor Demonstration
Simulates a real workstation environment with background file watching:

```bash
# TERMINAL 1: Start the live real-time detection monitor
python -m src.stage_7_trust.live_stage7_monitor

# TERMINAL 2: Launch the attack simulator
python simulate_ransomware.py --profile lockbit --num-files 15
```

---

### 4. Live SOC Dashboard (Stage 11)

```bash
# Terminal 1: Launch FastAPI WebSocket backend
cd dashboard/backend
uvicorn main:app --reload --port 8000

# Terminal 2: Launch React / Vite frontend
cd dashboard/frontend
npm install
npm run dev
# Open http://localhost:5173 to view real-time behavioral graph & trust stream
```

---

## 📜 License

This project is open-source and distributed under the **MIT License**.
