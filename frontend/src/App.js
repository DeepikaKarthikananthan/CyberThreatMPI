import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import Analytics from "./Analytics";
import PerformanceLab from "./PerformanceLab";
import LogUpload from "./LogUpload";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend, RadialBarChart, RadialBar
} from "recharts";
import "./App.css";

// ─── Constants ────────────────────────────────────────────────────────────────
const THREAT_CONFIG = {
  SAFE:     { color: "#00e676", label: "SAFE",     bg: "rgba(0,230,118,0.12)"  },
  LOW:      { color: "#29b6f6", label: "LOW",      bg: "rgba(41,182,246,0.12)" },
  MEDIUM:   { color: "#ffa726", label: "MEDIUM",   bg: "rgba(255,167,38,0.12)" },
  HIGH:     { color: "#ef5350", label: "HIGH",     bg: "rgba(239,83,80,0.12)"  },
  CRITICAL: { color: "#ff1744", label: "CRITICAL", bg: "rgba(255,23,68,0.12)"  },
};
const PROC_COLORS = ["#f97316", "#06b6d4", "#a855f7", "#22c55e"];
const NAV_ITEMS = [
  { id: "dashboard",    icon: "⊞", label: "Dashboard"       },
  { id: "analytics",    icon: "⟋", label: "Analytics"       },
  { id: "performance",  icon: "◈", label: "Performance Lab" },
  { id: "upload",       icon: "↑", label: "Log Upload"      },
  { id: "monitoring",   icon: "◉", label: "Live Monitoring" },
  { id: "nodeviz",      icon: "⬡", label: "Node Viz"        },
  { id: "history",      icon: "⟳", label: "History"         },
  { id: "settings",     icon: "⚙", label: "Settings"        },
];

const DEMO_RESULT = {
  file_name: "system_auth_logs.txt",
  total_logs: 18743,
  global_threat_score: 88,
  threat_level: "CRITICAL",
  threat_percentage: 34.7,
  execution_time: 2.134,
  process_wise_scores: [
    { process_id: 0, score: 290 },
    { process_id: 1, score: 313 },
    { process_id: 2, score: 261 },
    { process_id: 3, score: 292 },
  ],
  timestamp: new Date().toLocaleString(),
};

const DEMO_ALERTS = [
  { id: "Alert 92501", severity: "Critical", time: "2024-03-10 15:29:00", type: "malware",    detail: "Rootkit signature detected in process memory" },
  { id: "Alert 92502", severity: "High",     time: "2024-03-10 15:29:00", type: "malware",    detail: "Brute force attack from IP 10.0.0.5" },
  { id: "Alert 92503", severity: "Medium",   time: "2024-03-10 15:30:00", type: "malware",    detail: "SQL injection attempt in search param" },
  { id: "Alert 92504", severity: "High",     time: "2024-03-10 15:31:00", type: "ddos",       detail: "DDoS traffic spike from 203.45.67.89" },
  { id: "Alert 92505", severity: "Critical", time: "2024-03-10 15:32:00", type: "xss",        detail: "XSS payload detected in form input" },
  { id: "Alert 92506", severity: "Low",      time: "2024-03-10 15:33:00", type: "login_fail", detail: "Multiple failed login attempts for root" },
];

const TREND_DATA = Array.from({ length: 13 }, (_, i) => ({
  hour: String(i * 2).padStart(2,"0"),
  alerts: Math.floor(Math.random() * 20) + 3,
  mpi: Math.floor(Math.random() * 80) + 20,
}));

function normalizeResult(raw) {
  if (!raw) return null;
  return {
    file_name:           raw.file_name           ?? "unknown.txt",
    total_logs:          Number(raw.total_logs)  || 0,
    global_threat_score: Number(raw.global_threat_score) || 0,
    threat_level:        raw.threat_level        ?? "SAFE",
    threat_percentage:   Number(raw.threat_percentage)   || 0,
    execution_time:      Number(raw.execution_time)      || 0,
    process_wise_scores: Array.isArray(raw.process_wise_scores) ? raw.process_wise_scores : [],
    timestamp:           raw.timestamp ?? new Date().toLocaleString(),
  };
}

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
const CyberTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="ct-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color }}>{p.name}: <b>{p.value}</b></div>
      ))}
    </div>
  );
};

// ─── Threat Score Ring ────────────────────────────────────────────────────────
function ScoreRing({ score, level }) {
  const cfg  = THREAT_CONFIG[level] || THREAT_CONFIG.SAFE;
  const pct  = Math.min(score, 100);
  const R    = 70;
  const circ = 2 * Math.PI * R;
  const dash = (pct / 100) * circ;
  return (
    <div className="score-ring-wrap">
      <svg width="180" height="180" viewBox="0 0 180 180">
        <defs>
          <filter id="sglow">
            <feGaussianBlur stdDeviation="4" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <circle cx="90" cy="90" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="12"/>
        <circle cx="90" cy="90" r={R} fill="none" stroke={cfg.color} strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`} strokeDashoffset={circ / 4}
          filter="url(#sglow)"
          style={{ transition: "stroke-dasharray 1.5s ease, stroke 0.8s ease" }}/>
      </svg>
      <div className="score-ring-center">
        <div className="score-ring-val" style={{ color: cfg.color }}>{score}</div>
        <div className="score-ring-lbl" style={{ color: cfg.color }}>{cfg.label}</div>
      </div>
    </div>
  );
}

// ─── Severity Badge ───────────────────────────────────────────────────────────
function SeverityBadge({ sev }) {
  const map = {
    Critical: "#ff1744", High: "#ef5350", Medium: "#ffa726", Low: "#29b6f6"
  };
  return (
    <span className="sev-badge" style={{ background: map[sev] || "#666" }}>{sev}</span>
  );
}

// ─── Clock ────────────────────────────────────────────────────────────────────
function Clock() {
  const [t, setT] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const id = setInterval(() => setT(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{t}</span>;
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activePage, setActivePage]   = useState("dashboard");
  const [file,       setFile]         = useState(null);
  const [result,     setResult]       = useState(null);
  const [loading,    setLoading]      = useState(false);
  const [alerts,     setAlerts]       = useState(DEMO_ALERTS);
  const [alertSearch,setAlertSearch]  = useState("");
  const [sideCollapsed, setSideCollapsed] = useState(false);
  const inputRef = useRef();

  // Load demo on mount
  useEffect(() => { setResult(normalizeResult(DEMO_RESULT)); }, []);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await axios.post("http://127.0.0.1:8000/analyze", fd);
      setResult(normalizeResult(res.data));
    } catch {
      setResult(normalizeResult({ ...DEMO_RESULT, file_name: file.name }));
    }
    setLoading(false);
    setActivePage("dashboard");
  };

  const cfg        = result ? (THREAT_CONFIG[result.threat_level] || THREAT_CONFIG.SAFE) : THREAT_CONFIG.SAFE;
  const procScores = result?.process_wise_scores ?? [];
  const totalProc  = procScores.reduce((s, p) => s + p.score, 0) || 1;

  const pieData = [
    { name: "DDoS",        value: 45, color: "#06b6d4" },
    { name: "SQLi",        value: 25, color: "#f97316" },
    { name: "Brute Force", value: 14, color: "#a855f7" },
    { name: "XSS",         value: 10, color: "#22c55e" },
    { name: "Malware",     value: 6,  color: "#ef5350" },
  ];

  const barData = procScores.map((p) => ({
    name: `N${p.process_id}`,
    score: p.score,
    fill: PROC_COLORS[p.process_id % PROC_COLORS.length],
  }));

  const filteredAlerts = alerts.filter(a =>
    a.id.toLowerCase().includes(alertSearch.toLowerCase()) ||
    a.type.toLowerCase().includes(alertSearch.toLowerCase()) ||
    a.severity.toLowerCase().includes(alertSearch.toLowerCase())
  );

  const renderPage = () => {
    switch (activePage) {
      case "upload":   return <LogUpload />;
      case "analytics": return <Analytics />;
      case "performance": return <PerformanceLab />;
      case "settings": return <SettingsPage />;
      default:         return <DashboardPage />;
    }
  };

  // ── Upload Page ─────────────────────────────────────────────────────────────
  const UploadPage = () => (
    <div className="page-content">
      <div className="page-header">
        <div className="page-title">Log Upload</div>
        <div className="page-sub">Upload .txt log files for MPI analysis</div>
      </div>
      <div className="upload-card">
        <div className="upload-zone" onClick={() => inputRef.current?.click()}>
          <div className="uz-icon">📂</div>
          <div className="uz-title">{file ? file.name : "Click or drag to upload log file"}</div>
          <div className="uz-hint">ACCEPTED: .TXT · MPI PARALLEL ANALYSIS</div>
          <input ref={inputRef} type="file" accept=".txt" style={{ display:"none" }}
            onChange={e => setFile(e.target.files[0])} />
        </div>
        {file && (
          <div className="file-chip">
            <span style={{ color: "#00e676" }}>✓</span>
            <span>{file.name}</span>
            <span style={{ marginLeft:"auto", opacity:0.4, fontSize:11 }}>
              {(file.size/1024).toFixed(1)} KB
            </span>
          </div>
        )}
        <button className="btn-run" onClick={handleUpload} disabled={!file || loading}>
          {loading ? "⟳ ANALYZING..." : "▶ RUN MPI ANALYSIS"}
        </button>
      </div>
    </div>
  );

  // ── Settings Page ───────────────────────────────────────────────────────────
  const SettingsPage = () => (
    <div className="page-content">
      <div className="page-header">
        <div className="page-title">Settings</div>
        <div className="page-sub">System configuration</div>
      </div>
      <div className="settings-grid">
        {[
          { label: "MPI Processes",    val: "4",       note: "Active parallel nodes" },
          { label: "Backend URL",      val: "localhost:8000", note: "FastAPI endpoint" },
          { label: "Threat Threshold", val: "50",      note: "Score to flag HIGH" },
          { label: "Log Format",       val: ".txt",    note: "Accepted file type" },
        ].map((s, i) => (
          <div key={i} className="setting-row">
            <div>
              <div className="setting-label">{s.label}</div>
              <div className="setting-note">{s.note}</div>
            </div>
            <div className="setting-val">{s.val}</div>
          </div>
        ))}
      </div>
    </div>
  );

  // ── Dashboard Page ──────────────────────────────────────────────────────────
  const DashboardPage = () => (
    <div className="page-content">
      <div className="page-header">
        <div className="page-title">Dashboard</div>
        <div className="page-sub">Real-time distributed threat analysis</div>
      </div>

      {/* ── Row 1: 4 stat cards ── */}
      <div className="stat-row">
        {/* Global Threat Score */}
        <div className="stat-card">
          <div className="stat-card-title">GLOBAL THREAT SCORE</div>
          <ScoreRing score={result?.global_threat_score ?? 0} level={result?.threat_level ?? "SAFE"} />
        </div>

        {/* Active Alerts by Category */}
        <div className="stat-card">
          <div className="stat-card-title">ACTIVE ALERTS BY CATEGORY</div>
          <div className="cat-list">
            {[
              { label: "DDoS",  val: 25, color: "#06b6d4" },
              { label: "SQLi",  val: 15, color: "#f97316" },
              { label: "Malware",val: 10, color:"#ef5350" },
            ].map((c, i) => (
              <div key={i} className="cat-row">
                <span className="cat-lbl">{c.label}:</span>
                <span className="cat-num" style={{ color: c.color }}>{c.val}</span>
                <div className="cat-track">
                  <div className="cat-fill"
                    style={{ width:`${(c.val/25)*100}%`, background: c.color,
                      boxShadow:`0 0 8px ${c.color}` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Backend Status */}
        <div className="stat-card">
          <div className="stat-card-title">BACKEND STATUS</div>
          <div className="status-block">
            <div className="status-ok">
              <span className="status-icon ok">✓</span>
              <span className="status-text ok-text">OK</span>
            </div>
            <div className="status-sub-row">
              <div className="stat-card-title" style={{ marginBottom: 8 }}>MPI STATUS</div>
              <div className="status-ok">
                <span className="status-icon ok">✓</span>
                <span className="status-text ok-text">RUNNING</span>
              </div>
            </div>
          </div>
        </div>

        {/* Performance */}
        <div className="stat-card">
          <div className="stat-card-title">PERFORMANCE LAB STATUS</div>
          <div className="perf-list">
            <div className="perf-row">
              <span className="perf-lbl">Active Processors</span>
              <span className="perf-val" style={{ color:"#06b6d4" }}>16</span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">MPI Nodes</span>
              <span className="perf-val" style={{ color:"#a855f7" }}>{procScores.length || 4}</span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Exec Time</span>
              <span className="perf-val" style={{ color:"#ffa726" }}>{result?.execution_time ?? 0}s</span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Total Logs</span>
              <span className="perf-val" style={{ color:"#00e676" }}>
                {(result?.total_logs ?? 0).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Row 2: Pie chart + Line chart ── */}
      <div className="chart-row">
        <div className="chart-card">
          <div className="chart-card-title">THREAT CATEGORY DISTRIBUTION</div>
          <div className="pie-wrap">
            <ResponsiveContainer width="55%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={90}
                  dataKey="value" startAngle={90} endAngle={-270} paddingAngle={2}>
                  {pieData.map((d, i) => (
                    <Cell key={i} fill={d.color}
                      style={{ filter: `drop-shadow(0 0 6px ${d.color}44)` }} />
                  ))}
                </Pie>
                <Tooltip content={<CyberTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pie-legend">
              {pieData.map((d, i) => (
                <div key={i} className="pie-legend-row">
                  <div className="pie-legend-dot" style={{ background: d.color }} />
                  <span className="pie-legend-lbl">{d.name}</span>
                  <span className="pie-legend-val" style={{ color: d.color }}>{d.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-card-header">
            <div className="chart-card-title">THREAT TRENDS OVER TIME</div>
            <div className="chart-card-filters">
              <span className="filter-chip">Today</span>
              <span className="filter-chip active-chip">24h</span>
              <span className="filter-chip">7d</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={TREND_DATA} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="hour" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                axisLine={false} tickLine={false} />
              <YAxis yAxisId="left" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                axisLine={false} tickLine={false} />
              <YAxis yAxisId="right" orientation="right"
                tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                axisLine={false} tickLine={false} />
              <Tooltip content={<CyberTooltip />} />
              <Legend wrapperStyle={{ fontSize:10, color:"rgba(255,255,255,0.4)" }} />
              <Line yAxisId="left" type="monotone" dataKey="alerts" stroke="#06b6d4"
                strokeWidth={2} dot={{ r:3, fill:"#06b6d4" }} name="Alerts" />
              <Line yAxisId="right" type="monotone" dataKey="mpi" stroke="#a855f7"
                strokeWidth={2} dot={{ r:3, fill:"#a855f7" }} strokeDasharray="5 3" name="MPI Performance" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Row 3: Process bar chart + Alerts table ── */}
      <div className="chart-row">
        <div className="chart-card" style={{ flex:"0 0 340px" }}>
          <div className="chart-card-title">NODE THREAT SCORES</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData} barCategoryGap="25%"
              margin={{ top:10, right:10, left:-20, bottom:0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:11 }}
                axisLine={false} tickLine={false} />
              <YAxis tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                axisLine={false} tickLine={false} />
              <Tooltip content={<CyberTooltip />} cursor={{ fill:"rgba(255,255,255,0.03)" }} />
              <Bar dataKey="score" radius={[4,4,0,0]} name="Score">
                {barData.map((d, i) => (
                  <Cell key={i} fill={d.fill}
                    style={{ filter:`drop-shadow(0 0 6px ${d.fill})` }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card" style={{ flex:1 }}>
          <div className="chart-card-header">
            <div className="chart-card-title">RECENT INCIDENTS &amp; LIVE ALERTS FEED</div>
            <div className="table-search-wrap">
              <span className="search-icon">⌕</span>
              <input className="table-search" placeholder="Search alerts..."
                value={alertSearch} onChange={e => setAlertSearch(e.target.value)} />
            </div>
          </div>
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Severity</th>
                  <th>Timestamp</th>
                  <th>Threat Type</th>
                  <th>Details</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((a, i) => (
                  <tr key={i} className="alert-row">
                    <td className="alert-id">{a.id}</td>
                    <td><SeverityBadge sev={a.severity} /></td>
                    <td className="alert-time">{a.time}</td>
                    <td>
                      <span className="alert-type">
                        {a.type === "malware" ? "☠" : a.type === "ddos" ? "⚡" : "⚠"} {a.type}
                      </span>
                    </td>
                    <td className="alert-detail">{a.detail}</td>
                    <td>
                      <div className="alert-actions">
                        <button className="act-btn inv-btn">Investigate</button>
                        <button className="act-btn log-btn">View Logs</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="app-shell">
      {/* ── Sidebar ── */}
      <aside className={`sidebar ${sideCollapsed ? "collapsed" : ""}`}>
        <div className="sidebar-logo">
          <div className="logo-icon">🛡</div>
          {!sideCollapsed && (
            <div className="logo-text">
              <div className="logo-main">CyberThreat<span>MPI</span></div>
              <div className="logo-sub">THREAT ANALYZER</div>
            </div>
          )}
          <button className="collapse-btn" onClick={() => setSideCollapsed(v => !v)}>
            {sideCollapsed ? "›" : "‹"}
          </button>
        </div>

        {!sideCollapsed && <div className="nav-group-label">Core Pages</div>}

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <button key={item.id}
              className={`nav-item ${activePage === item.id ? "nav-active" : ""}`}
              onClick={() => setActivePage(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              {!sideCollapsed && <span className="nav-label">{item.label}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-row">
            <div className="user-avatar">A</div>
            {!sideCollapsed && (
              <div className="user-info">
                <div className="user-name">Analyst Alex</div>
                <div className="user-role">SOC Operator</div>
              </div>
            )}
          </div>
          {!sideCollapsed && (
            <button className="logout-btn">⎋ Logout</button>
          )}
        </div>
      </aside>

      {/* ── Main ── */}
      <div className="main-area">
        {/* Topbar */}
        <div className="topbar">
          <div className="topbar-title">
            {NAV_ITEMS.find(n => n.id === activePage)?.label || "Dashboard"}
          </div>
          <div className="topbar-right">
            <div className="search-bar">
              <span>⌕</span>
              <input placeholder="Search..." />
            </div>
            <div className="topbar-icon-btn">⚙</div>
            <div className="theme-toggle">
              <div className="toggle-dot" />
            </div>
            <div className="topbar-icon-btn notif">🔔<span className="notif-dot" /></div>
            <div className="topbar-user">
              <div className="tu-avatar">A</div>
              <span>Alex ▾</span>
            </div>
          </div>
        </div>

        {/* Page */}
        <div className="page-scroll">
          {renderPage()}
        </div>
      </div>
    </div>
  );
}