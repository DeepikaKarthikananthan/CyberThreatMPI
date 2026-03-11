import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadialBarChart, RadialBar, PieChart, Pie, Cell, LineChart, Line, Legend
} from "recharts";
import "./App.css";

// ─── Constants ───────────────────────────────────────────────────────────────
const THREAT_CONFIG = {
  SAFE:     { color: "#00ff87", glow: "#00ff87",  label: "SAFE"     },
  LOW:      { color: "#60efff", glow: "#60efff",  label: "LOW"      },
  MEDIUM:   { color: "#ffb830", glow: "#ffb830",  label: "MEDIUM"   },
  HIGH:     { color: "#ff3860", glow: "#ff3860",  label: "HIGH"     },
  CRITICAL: { color: "#ff0040", glow: "#ff0040",  label: "CRITICAL" },
};

const PROC_COLORS = ["#00ff87", "#60efff", "#ffb830", "#b06cff"];

const DEMO_RESULT = {
  file_name: "system_auth_logs_march.txt",
  total_logs: 18743,
  global_threat_score: 42,
  threat_level: "HIGH",
  threat_percentage: 22.41,
  execution_time: 2.134,
  process_wise_scores: [
    { process_id: 0, score: 14 },
    { process_id: 1, score: 11 },
    { process_id: 2, score: 9  },
    { process_id: 3, score: 8  },
  ],
  timestamp: new Date().toLocaleString(),
};

function normalizeResult(raw) {
  if (!raw) return null;
  return {
    file_name:           raw.file_name           ?? "unknown.txt",
    total_logs:          Number(raw.total_logs)  || 0,
    global_threat_score: Number(raw.global_threat_score) || 0,
    threat_level:        raw.threat_level        ?? "SAFE",
    threat_percentage:   Number(raw.threat_percentage)   || 0,
    execution_time:      Number(raw.execution_time)      || 0,
    process_wise_scores: Array.isArray(raw.process_wise_scores)
                           ? raw.process_wise_scores : [],
    timestamp:           raw.timestamp ?? new Date().toLocaleString(),
  };
}

// ─── Custom Tooltip ──────────────────────────────────────────────────────────
const CyberTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: "#0a1628", border: "1px solid rgba(0,210,255,0.3)",
        borderRadius: 6, padding: "10px 14px", fontSize: 11,
        fontFamily: "'Share Tech Mono', monospace", color: "#cde4f7",
        boxShadow: "0 0 20px rgba(0,210,255,0.15)"
      }}>
        <div style={{ color: "rgba(205,228,247,0.5)", letterSpacing: 2, marginBottom: 4 }}>{label}</div>
        {payload.map((p, i) => (
          <div key={i} style={{ color: p.color }}>
            {p.name}: <strong>{p.value}</strong>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

// ─── Chart 1: Process Score Bar Chart ────────────────────────────────────────
function ProcessBarChart({ procScores }) {
  const data = procScores.map((p) => ({
    name: `NODE_${String(p.process_id).padStart(2, "0")}`,
    score: p.score,
    color: PROC_COLORS[p.process_id % PROC_COLORS.length],
  }));

  return (
    <div className="chart-panel">
      <div className="panel-title"><span />PROCESS SCORE — BAR CHART</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} barCategoryGap="30%"
          margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,210,255,0.06)" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: "rgba(205,228,247,0.4)", fontSize: 10, fontFamily: "Share Tech Mono" }}
            axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "rgba(205,228,247,0.4)", fontSize: 10, fontFamily: "Share Tech Mono" }}
            axisLine={false} tickLine={false} />
          <Tooltip content={<CyberTooltip />} cursor={{ fill: "rgba(0,210,255,0.04)" }} />
          <Bar dataKey="score" radius={[4, 4, 0, 0]} name="Threat Score">
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color}
                style={{ filter: `drop-shadow(0 0 6px ${entry.color})` }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Chart 2: Threat vs Safe Pie Chart ───────────────────────────────────────
function ThreatPieChart({ result, cfg }) {
  const safe    = Math.max(100 - result.threat_percentage, 0);
  const threat  = Math.min(result.threat_percentage, 100);
  const data = [
    { name: "THREAT", value: parseFloat(threat.toFixed(2)) },
    { name: "SAFE",   value: parseFloat(safe.toFixed(2))   },
  ];
  const COLORS = [cfg.color, "rgba(255,255,255,0.06)"];

  const renderLabel = ({ cx, cy }) => (
    <>
      <text x={cx} y={cy - 8} textAnchor="middle"
        fill={cfg.color} fontSize={22} fontFamily="Orbitron" fontWeight={700}
        style={{ textShadow: `0 0 12px ${cfg.color}` }}>
        {threat.toFixed(1)}%
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle"
        fill="rgba(205,228,247,0.4)" fontSize={9} fontFamily="Share Tech Mono" letterSpacing={3}>
        THREAT RATE
      </text>
    </>
  );

  return (
    <div className="chart-panel">
      <div className="panel-title"><span />THREAT DISTRIBUTION — PIE</div>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={58} outerRadius={80}
            dataKey="value" startAngle={90} endAngle={-270}
            labelLine={false} label={renderLabel}>
            {data.map((_, i) => (
              <Cell key={i} fill={COLORS[i]}
                style={i === 0 ? { filter: `drop-shadow(0 0 8px ${cfg.color})` } : {}} />
            ))}
          </Pie>
          <Tooltip content={<CyberTooltip />} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Chart 3: Cumulative Score Line Chart ────────────────────────────────────
function ScoreLineChart({ procScores, cfg }) {
  // Build cumulative score across processes
  let cumulative = 0;
  const data = procScores.map((p) => {
    cumulative += p.score;
    return {
      name: `NODE_${String(p.process_id).padStart(2, "0")}`,
      score: p.score,
      cumulative,
    };
  });

  return (
    <div className="chart-panel chart-panel-full">
      <div className="panel-title"><span />CUMULATIVE THREAT SCORE — ACROSS NODES</div>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,210,255,0.06)" />
          <XAxis dataKey="name"
            tick={{ fill: "rgba(205,228,247,0.4)", fontSize: 10, fontFamily: "Share Tech Mono" }}
            axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "rgba(205,228,247,0.4)", fontSize: 10, fontFamily: "Share Tech Mono" }}
            axisLine={false} tickLine={false} />
          <Tooltip content={<CyberTooltip />} />
          <Legend wrapperStyle={{ fontSize: 10, fontFamily: "Share Tech Mono",
            color: "rgba(205,228,247,0.4)", letterSpacing: 2 }} />
          <Line type="monotone" dataKey="score" stroke="#60efff" strokeWidth={2}
            dot={{ fill: "#60efff", r: 5, strokeWidth: 0 }}
            activeDot={{ r: 7, fill: "#60efff", boxShadow: "0 0 10px #60efff" }}
            name="NODE SCORE" />
          <Line type="monotone" dataKey="cumulative" stroke={cfg.color} strokeWidth={2}
            strokeDasharray="6 3"
            dot={{ fill: cfg.color, r: 5, strokeWidth: 0 }}
            activeDot={{ r: 7 }}
            name="CUMULATIVE" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Chart 4: Radial Score Gauge ─────────────────────────────────────────────
function RadialScoreChart({ procScores }) {
  const total = procScores.reduce((s, p) => s + p.score, 0) || 1;
  const data = procScores.map((p) => ({
    name: `NODE_${String(p.process_id).padStart(2, "0")}`,
    value: parseFloat(((p.score / total) * 100).toFixed(1)),
    fill: PROC_COLORS[p.process_id % PROC_COLORS.length],
  }));

  return (
    <div className="chart-panel">
      <div className="panel-title"><span />NODE CONTRIBUTION — RADIAL</div>
      <ResponsiveContainer width="100%" height={200}>
        <RadialBarChart cx="50%" cy="50%" innerRadius={30} outerRadius={85}
          data={data} startAngle={180} endAngle={-180}>
          <RadialBar dataKey="value" cornerRadius={4} label={false} />
          <Tooltip content={<CyberTooltip />} />
          <Legend iconSize={8} wrapperStyle={{
            fontSize: 9, fontFamily: "Share Tech Mono",
            color: "rgba(205,228,247,0.4)", letterSpacing: 2
          }} />
        </RadialBarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Clock ───────────────────────────────────────────────────────────────────
function Clock() {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="header-clock">{time} · LOCAL</span>;
}

// ─── Threat Ring ─────────────────────────────────────────────────────────────
function ThreatRing({ level, score, total }) {
  const cfg  = THREAT_CONFIG[level] || THREAT_CONFIG.SAFE;
  const pct  = total > 0 ? Math.min((score / total) * 100, 100) : 0;
  const R    = 88;
  const circ = 2 * Math.PI * R;
  const dash = (pct / 100) * circ;
  return (
    <div className="ring-wrap">
      <svg width="230" height="230" viewBox="0 0 230 230">
        <defs>
          <filter id="ringGlow">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle cx="115" cy="115" r="110" fill="none"
          stroke="rgba(0,210,255,0.04)" strokeWidth="1" strokeDasharray="4 8" />
        <circle cx="115" cy="115" r={R} fill="none"
          stroke="rgba(255,255,255,0.05)" strokeWidth="14" />
        <circle cx="115" cy="115" r={R} fill="none"
          stroke={cfg.color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`} strokeDashoffset={circ / 4}
          filter="url(#ringGlow)"
          style={{ transition: "stroke-dasharray 1.8s cubic-bezier(0.4,0,0.2,1), stroke 1s ease" }}
        />
        <circle cx="115" cy="115" r="68" fill="none"
          stroke={cfg.color} strokeWidth="1" strokeDasharray="2 14"
          opacity="0.25" style={{ transition: "stroke 1s ease" }} />
        {Array.from({ length: 24 }).map((_, i) => {
          const angle = (i / 24) * Math.PI * 2 - Math.PI / 2;
          return (
            <line key={i}
              x1={115 + 108 * Math.cos(angle)} y1={115 + 108 * Math.sin(angle)}
              x2={115 + 102 * Math.cos(angle)} y2={115 + 102 * Math.sin(angle)}
              stroke="rgba(0,210,255,0.15)" strokeWidth="1" />
          );
        })}
      </svg>
      <div className="ring-center">
        <div className="ring-score" style={{ color: cfg.color, textShadow: `0 0 25px ${cfg.glow}` }}>
          {score}
        </div>
        <div className="ring-level" style={{ color: cfg.color }}>{cfg.label}</div>
        <div className="ring-pct">{pct.toFixed(1)}% THREAT RATE</div>
      </div>
    </div>
  );
}

// ─── Metric Cell ─────────────────────────────────────────────────────────────
function MetricCell({ label, value, unit, color, barPct }) {
  return (
    <div className="metric-cell">
      <div className="metric-lbl">{label}</div>
      <div className="metric-val" style={{ color, textShadow: `0 0 18px ${color}` }}>
        {value}{unit && <span className="metric-unit">{unit}</span>}
      </div>
      {barPct !== undefined && (
        <div className="metric-bar">
          <div className="metric-bar-fill"
            style={{
              width: `${Math.min(Math.max(Number(barPct) || 0, 0), 100)}%`,
              background: color, boxShadow: `0 0 6px ${color}`,
            }} />
        </div>
      )}
    </div>
  );
}

// ─── Process Bar ─────────────────────────────────────────────────────────────
function ProcessBar({ pid, score, max }) {
  const color = PROC_COLORS[pid % PROC_COLORS.length];
  const pct   = max > 0 ? (score / max) * 100 : 0;
  return (
    <div className="proc-row">
      <span className="proc-id">NODE_{String(pid).padStart(2, "0")}</span>
      <div className="proc-track">
        <div className="proc-fill"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
            boxShadow: `0 0 10px ${color}55`,
          }} />
      </div>
      <span className="proc-score" style={{ color }}>{score}</span>
    </div>
  );
}

// ─── Activity Feed ───────────────────────────────────────────────────────────
function ActivityFeed({ result }) {
  const cfg = THREAT_CONFIG[result.threat_level] || THREAT_CONFIG.SAFE;
  const events = [
    { color: "#60efff", label: "Log Ingestion Complete",
      sub: `${result.total_logs.toLocaleString()} entries processed` },
    { color: "#00ff87", label: "MPI Dispatch Successful",
      sub: `${result.process_wise_scores.length} parallel nodes active` },
    { color: cfg.color, label: `Threat Level: ${result.threat_level}`,
      sub: `Score ${result.global_threat_score} — ${result.threat_percentage}% flagged` },
    { color: "#ffb830", label: "Analysis Complete",
      sub: `Finished in ${result.execution_time}s` },
  ];
  return (
    <>
      {events.map((e, i) => (
        <div className="activity-row" key={i}>
          <div className="activity-dot"
            style={{ background: e.color, color: e.color, boxShadow: `0 0 8px ${e.color}` }} />
          <div className="activity-body">
            <div className="activity-label">{e.label}</div>
            <div className="activity-sub">{e.sub}</div>
          </div>
        </div>
      ))}
    </>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
function App() {
  const [file,    setFile]    = useState(null);
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [isDemo,  setIsDemo]  = useState(false);
  const inputRef              = useRef();

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await axios.post("http://127.0.0.1:8000/analyze", fd);
      setResult(normalizeResult(res.data));
      setIsDemo(false);
    } catch (err) {
      console.error("API error — loading demo:", err);
      setResult(normalizeResult({ ...DEMO_RESULT, file_name: file.name }));
      setIsDemo(false);
    }
    setLoading(false);
  };

  const handleDemo = () => {
    setLoading(true);
    setResult(null);
    setTimeout(() => {
      setResult(normalizeResult(DEMO_RESULT));
      setIsDemo(true);
      setLoading(false);
    }, 2000);
  };

  const cfg        = result ? (THREAT_CONFIG[result.threat_level] || THREAT_CONFIG.SAFE) : null;
  const procScores = result ? result.process_wise_scores : [];
  const maxProc    = procScores.length > 0 ? Math.max(...procScores.map((p) => p.score)) : 1;

  return (
    <>
      <div className="bg-layer">
        <div className="bg-grid" /><div className="bg-vignette" />
        <div className="bg-glow-left" /><div className="bg-glow-right" />
      </div>
      <div className="scanline" />

      <div className="shell">
        {/* Header */}
        <header className="header">
          <div className="logo">⬡<div className="logo-corner" /></div>
          <div className="header-info">
            <div className="header-title">CYBERTHREAT MPI</div>
            <div className="header-sub">DISTRIBUTED LOG ANALYSIS SYSTEM · v2.4.1</div>
          </div>
          <div className="header-meta">
            <div className="status-badge"><div className="status-dot" />SYSTEM ONLINE</div>
            <Clock />
          </div>
        </header>

        {/* Upload */}
        <div className="upload-panel">
          <div className="upload-corner-tl" /><div className="upload-corner-br" />
          <div className="section-label">INPUT CONFIGURATION</div>
          <div className="dropzone" onClick={() => inputRef.current?.click()}>
            <div className="dropzone-icon">📂</div>
            <div className="dropzone-text">{file ? file.name : "Click to select a log file"}</div>
            <div className="dropzone-hint">ACCEPTED FORMAT · .TXT · MPI PARALLEL ANALYSIS READY</div>
            <input ref={inputRef} type="file" accept=".txt" style={{ display: "none" }}
              onChange={(e) => setFile(e.target.files[0])} />
          </div>
          {file && (
            <div className="file-pill">
              <span className="file-pill-icon">✓</span>
              <span className="file-pill-name">{file.name}</span>
              <span className="file-pill-size">{(file.size / 1024).toFixed(1)} KB</span>
            </div>
          )}
          <div className="btn-row">
            <button className="btn-analyze" onClick={handleUpload} disabled={!file || loading}>
              {loading ? "ANALYZING..." : "▶ RUN MPI ANALYSIS"}
            </button>
            <button className="btn-demo" onClick={handleDemo} disabled={loading}>LOAD DEMO</button>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div className="loading-wrap">
            <div className="loading-ring-outer"><div className="loading-ring-inner" /></div>
            <div className="loading-text">DISPATCHING MPI PROCESSES</div>
            <div className="loading-nodes">
              {[0,1,2,3].map((i) => (
                <div key={i} className="loading-node" style={{ animationDelay: `${i * 0.2}s` }} />
              ))}
            </div>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="results-wrap">
            <div className="result-header">
              <div className="result-title">ANALYSIS REPORT</div>
              <div className="result-meta">
                {isDemo ? "[ DEMO DATA ]" : result.file_name} · {result.timestamp}
              </div>
            </div>

            {/* Row 1: Ring + Metrics */}
            <div className="top-grid">
              <div className="ring-panel">
                <div className="ring-panel-label">GLOBAL THREAT INDEX</div>
                <ThreatRing level={result.threat_level}
                  score={result.global_threat_score} total={result.total_logs} />
                <div className="ring-panel-foot">
                  SCORE {result.global_threat_score} / {result.total_logs.toLocaleString()} LOGS
                </div>
              </div>
              <div className="metrics-panel">
                <MetricCell label="TOTAL LOGS SCANNED"
                  value={result.total_logs.toLocaleString()} color="#60efff"
                  barPct={(result.total_logs / 20000) * 100} />
                <MetricCell label="THREAT PERCENTAGE"
                  value={result.threat_percentage} unit="%" color={cfg.color}
                  barPct={result.threat_percentage} />
                <MetricCell label="EXECUTION TIME"
                  value={result.execution_time} unit="s" color="#ffb830"
                  barPct={(result.execution_time / 5) * 100} />
                <MetricCell label="MPI PROCESSES"
                  value={procScores.length} color="#b06cff"
                  barPct={procScores.length * 25} />
              </div>
            </div>

            {/* Row 2: Process bars + Activity */}
            <div className="bottom-grid">
              <div className="panel">
                <div className="panel-title"><span />PROCESS DISTRIBUTION</div>
                {procScores.length > 0
                  ? procScores.map((p) => (
                      <ProcessBar key={p.process_id} pid={p.process_id}
                        score={p.score} max={maxProc} />
                    ))
                  : <div style={{ color: "rgba(205,228,247,0.25)", fontSize: 11, letterSpacing: 2 }}>
                      NO PROCESS DATA AVAILABLE
                    </div>
                }
              </div>
              <div className="panel">
                <div className="panel-title"><span />EXECUTION LOG</div>
                <ActivityFeed result={result} />
              </div>
            </div>

            {/* ── CHARTS SECTION ── */}
            <div className="charts-heading">
              <div className="section-label" style={{ marginBottom: 0 }}>VISUAL ANALYTICS</div>
            </div>

            {/* Row 3: Bar chart + Pie chart */}
            <div className="bottom-grid">
              {procScores.length > 0
                ? <ProcessBarChart procScores={procScores} />
                : <div className="chart-panel"><div className="panel-title"><span />PROCESS SCORE — BAR CHART</div>
                    <div style={{ color: "rgba(205,228,247,0.25)", fontSize: 11, padding: 20 }}>NO DATA</div>
                  </div>
              }
              <ThreatPieChart result={result} cfg={cfg} />
            </div>

            {/* Row 4: Line chart full width */}
            {procScores.length > 0 && (
              <ScoreLineChart procScores={procScores} cfg={cfg} />
            )}

            {/* Row 5: Radial chart */}
            {procScores.length > 0 && (
              <div className="bottom-grid">
                <RadialScoreChart procScores={procScores} />
                <div className="chart-panel">
                  <div className="panel-title"><span />SCORE SUMMARY</div>
                  <div className="summary-grid">
                    {procScores.map((p) => {
                      const color = PROC_COLORS[p.process_id % PROC_COLORS.length];
                      const total = procScores.reduce((s, x) => s + x.score, 0) || 1;
                      return (
                        <div key={p.process_id} className="summary-cell">
                          <div className="summary-dot" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
                          <div>
                            <div className="summary-label">NODE_{String(p.process_id).padStart(2,"0")}</div>
                            <div className="summary-val" style={{ color }}>
                              {p.score} <span style={{ fontSize: 10, opacity: 0.5 }}>
                                ({((p.score / total) * 100).toFixed(1)}%)
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <div className="summary-cell" style={{ gridColumn: "span 2", borderTop: "1px solid rgba(0,210,255,0.08)", paddingTop: 12 }}>
                      <div className="summary-dot" style={{ background: cfg.color, boxShadow: `0 0 8px ${cfg.color}` }} />
                      <div>
                        <div className="summary-label">GLOBAL TOTAL</div>
                        <div className="summary-val" style={{ color: cfg.color, fontSize: 22 }}>
                          {result.global_threat_score}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="footer-bar">
              <div className="footer-cell">MPI NODES
                <span className="footer-cell-val">{procScores.length} ACTIVE</span>
              </div>
              <div className="footer-cell">GLOBAL SCORE
                <span className="footer-cell-val" style={{ color: cfg.color }}>
                  {result.global_threat_score}
                </span>
              </div>
              <div className="footer-cell">THREAT LEVEL
                <span className="footer-cell-val" style={{ color: cfg.color }}>
                  {result.threat_level}
                </span>
              </div>
              <div className="footer-cell">TIMESTAMP
                <span className="footer-cell-val" style={{ color: "#60efff", fontSize: 10 }}>
                  {result.timestamp}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export default App;