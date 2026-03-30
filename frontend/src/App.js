import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import axios from "axios";

import './Theme.css';
import "./App.css";
import './Settings.css';

import Analytics     from "./Analytics";
import PerformanceLab from "./PerformanceLab";
import LogUpload     from "./LogUpload";
import Settings      from './Settings';
import History       from './History';
import Threatviz     from './Threatviz';
import LiveMonitoring from './LiveMonitoring';

import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend, AreaChart, Area,
} from "recharts";

import {
  useTheme, useMpiConfig, useApiConfig, useClassifyThreat,
} from './Settingscontext';

// ─── Constants ─────────────────────────────────────────────────────────────────
const THREAT_CONFIG = {
  SAFE:     { color: "#00e676", label: "SAFE",     bg: "rgba(0,230,118,0.12)"  },
  LOW:      { color: "#29b6f6", label: "LOW",      bg: "rgba(41,182,246,0.12)" },
  MEDIUM:   { color: "#ffa726", label: "MEDIUM",   bg: "rgba(255,167,38,0.12)" },
  HIGH:     { color: "#ef5350", label: "HIGH",     bg: "rgba(239,83,80,0.12)"  },
  CRITICAL: { color: "#ff1744", label: "CRITICAL", bg: "rgba(255,23,68,0.12)"  },
};
const PROC_COLORS = ["#f97316", "#06b6d4", "#a855f7", "#22c55e",
                     "#00e5ff", "#76ff03", "#ff6d00", "#d500f9",
                     "#ffea00", "#ff1744", "#29b6f6", "#ffa726",
                     "#ef5350", "#76ff03", "#ff6d00", "#d500f9"];
const LEVEL_COLORS = {
  SAFE:"#00e676", LOW:"#29b6f6", MEDIUM:"#ffa726", HIGH:"#ef5350", CRITICAL:"#ff1744"
};
const NAV_ITEMS = [
  { id:"dashboard",   icon:"⊞", label:"Dashboard"       },
  { id:"analytics",   icon:"⟋", label:"Analytics"       },
  { id:"performance", icon:"◈", label:"Performance Lab" },
  { id:"upload",      icon:"↑", label:"Log Upload"      },
  { id:"monitoring",  icon:"◉", label:"Live Monitoring" },
  { id:"nodeviz",     icon:"⬡", label:"Threat Workbench" },
  { id:"history",     icon:"⟳", label:"History"         },
  { id:"settings",    icon:"⚙", label:"Settings"        },
];

// ─── Timestamp parser ──────────────────────────────────────────────────────────
// History entries have timestamps like "21/03/2026, 09:02:58 am"
// OR "2026-03-21 09:02:58" — handle both
function parseTimestamp(ts) {
  if (!ts) return new Date(0);
  // Try DD/MM/YYYY, h:mm:ss am/pm
  const m = ts.match(/(\d{2})\/(\d{2})\/(\d{4}),?\s+(\d+):(\d+):(\d+)\s*(am|pm)?/i);
  if (m) {
    let h = parseInt(m[4]);
    if (m[7]?.toLowerCase() === "pm" && h < 12) h += 12;
    if (m[7]?.toLowerCase() === "am" && h === 12) h = 0;
    return new Date(+m[3], +m[2]-1, +m[1], h, +m[5], +m[6]);
  }
  return new Date(ts);
}

// ─── Helpers ───────────────────────────────────────────────────────────────────
const fmtNum = (n) => Number(n || 0).toLocaleString();
const tc = (level) => THREAT_CONFIG[level] || THREAT_CONFIG.SAFE;

function normalizeEntry(raw) {
  if (!raw) return null;
  return {
    file_name:           raw.file_name           ?? "unknown.txt",
    total_logs:          Number(raw.total_logs)  || 0,
    global_threat_score: Number(raw.global_threat_score) || 0,
    threat_level:        raw.threat_level        ?? "SAFE",
    threat_percentage:   Number(raw.threat_percentage)   || 0,
    execution_time:      Number(raw.execution_time)      || 0,
    process_wise_scores: Array.isArray(raw.process_wise_scores) ? raw.process_wise_scores : [],
    processors_used:     Number(raw.processors_used)     || 0,
    file_format:         raw.file_format                 || "TXT",
    timestamp:           raw.timestamp ?? new Date().toLocaleString(),
    _date:               parseTimestamp(raw.timestamp),
  };
}

// ─── Custom Tooltip ────────────────────────────────────────────────────────────
const CyberTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="ct-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color:p.color }}>{p.name}: <b>{p.value}</b></div>
      ))}
    </div>
  );
};

// ─── Threat Score Ring ─────────────────────────────────────────────────────────
function ScoreRing({ score, level }) {
  const cfg  = tc(level);
  const pct  = Math.min(score, 100);
  const R    = 70, circ = 2 * Math.PI * R;
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
        <circle cx="90" cy="90" r={R} fill="none"
          stroke="rgba(255,255,255,0.06)" strokeWidth="12"/>
        <circle cx="90" cy="90" r={R} fill="none"
          stroke={cfg.color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`} strokeDashoffset={circ/4}
          filter="url(#sglow)"
          style={{ transition:"stroke-dasharray 1.5s ease, stroke 0.8s ease" }}/>
      </svg>
      <div className="score-ring-center">
        <div className="score-ring-val" style={{ color:cfg.color }}>{score}</div>
        <div className="score-ring-lbl" style={{ color:cfg.color }}>{cfg.label}</div>
      </div>
    </div>
  );
}

// ─── Severity Badge ────────────────────────────────────────────────────────────
function SeverityBadge({ sev }) {
  const map = { Critical:"#ff1744", High:"#ef5350", Medium:"#ffa726",
                Low:"#29b6f6", SAFE:"#00e676" };
  return (
    <span className="sev-badge" style={{ background:map[sev]||"#666" }}>{sev}</span>
  );
}

// ─── Clock ─────────────────────────────────────────────────────────────────────
function Clock() {
  const [t, setT] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const id = setInterval(() => setT(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{t}</span>;
}

// ─── Theme Toggle ──────────────────────────────────────────────────────────────
function ThemeToggle() {
  const { isDark, toggleTheme } = useTheme();
  return (
    <button className="theme-toggle-btn" onClick={toggleTheme}
      title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
      style={{ background:"transparent", border:"none", cursor:"pointer", padding:0 }}>
      <div className={`tt-track ${isDark ? "tt-dark" : "tt-light"}`}>
        <div className="tt-knob">
          <span style={{ fontSize:13 }}>{isDark ? "🌙" : "☀️"}</span>
        </div>
      </div>
    </button>
  );
}

// ─── Alert Detail Modal ────────────────────────────────────────────────────────
function AlertModal({ entry, mode, onClose }) {
  if (!entry) return null;
  const c = tc(entry.threat_level);
  const procs = entry.process_wise_scores || [];
  const total = procs.reduce((s,p) => s+p.score, 0) || 1;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <div className="modal-title">
              {mode === "investigate" ? "🔍 INVESTIGATION" : "📋 LOG DETAILS"}
            </div>
            <div className="modal-subtitle">{entry.file_name} · {entry.timestamp}</div>
          </div>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        {mode === "investigate" ? (
          <div className="modal-body">
            <div className="inv-grid">
              <div className="inv-block">
                <div className="inv-label">THREAT LEVEL</div>
                <div className="inv-val" style={{ color:c.color, fontSize:22,
                  fontFamily:"'Orbitron',monospace", fontWeight:900 }}>
                  {entry.threat_level}
                </div>
              </div>
              <div className="inv-block">
                <div className="inv-label">THREAT SCORE</div>
                <div className="inv-val" style={{ color:c.color }}>{entry.global_threat_score}</div>
              </div>
              <div className="inv-block">
                <div className="inv-label">TOTAL LOGS</div>
                <div className="inv-val" style={{ color:"#00e5ff" }}>{fmtNum(entry.total_logs)}</div>
              </div>
              <div className="inv-block">
                <div className="inv-label">THREAT RATE</div>
                <div className="inv-val" style={{ color:c.color }}>
                  {Number(entry.threat_percentage).toFixed(1)}%
                </div>
              </div>
              <div className="inv-block">
                <div className="inv-label">EXEC TIME</div>
                <div className="inv-val" style={{ color:"#ffea00" }}>
                  {Number(entry.execution_time).toFixed(3)}s
                </div>
              </div>
              <div className="inv-block">
                <div className="inv-label">PROCESSORS</div>
                <div className="inv-val" style={{ color:"#76ff03" }}>
                  {entry.processors_used || procs.length}
                </div>
              </div>
            </div>

            <div className="inv-section-title">NODE-LEVEL THREAT DISTRIBUTION</div>
            {procs.length > 0 ? (
              <div className="inv-proc-list">
                {procs.map((p, i) => {
                  const share = ((p.score / total) * 100).toFixed(1);
                  const color = PROC_COLORS[i % PROC_COLORS.length];
                  return (
                    <div key={i} className="inv-proc-row">
                      <span style={{ color, fontFamily:"'Orbitron',monospace",
                        fontSize:11, fontWeight:700, width:50 }}>
                        N{p.process_id}
                      </span>
                      <div className="inv-proc-track">
                        <div className="inv-proc-fill"
                          style={{ width:`${share}%`, background:color,
                            boxShadow:`0 0 6px ${color}66` }}/>
                      </div>
                      <span style={{ color, fontFamily:"'Orbitron',monospace",
                        fontSize:11, width:45, textAlign:"right" }}>
                        {p.score}
                      </span>
                      <span style={{ color:"rgba(255,255,255,0.3)",
                        fontSize:10, width:40, textAlign:"right" }}>
                        {share}%
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ color:"rgba(255,255,255,0.3)", fontFamily:"'Share Tech Mono',monospace",
                fontSize:12, padding:"12px 0" }}>
                No per-node data available for this entry.
              </div>
            )}

            <div className="inv-section-title" style={{ marginTop:16 }}>RECOMMENDED ACTIONS</div>
            <div className="inv-actions-list">
              {entry.threat_level === "SAFE" && (
                <div className="inv-action-item ok">✓ No action required — system appears clean</div>
              )}
              {entry.threat_level === "LOW" && (
                <div className="inv-action-item low">◉ Monitor for recurring patterns from this source</div>
              )}
              {entry.threat_level === "MEDIUM" && (<>
                <div className="inv-action-item med">⚠ Review flagged log entries manually</div>
                <div className="inv-action-item med">⚠ Check for repeated IP addresses</div>
              </>)}
              {entry.threat_level === "HIGH" && (<>
                <div className="inv-action-item high">⛔ Escalate to security team immediately</div>
                <div className="inv-action-item high">⛔ Isolate affected system if possible</div>
                <div className="inv-action-item high">⛔ Collect forensic evidence</div>
              </>)}
              {entry.threat_level === "CRITICAL" && (<>
                <div className="inv-action-item crit">🚨 CRITICAL — Initiate incident response protocol</div>
                <div className="inv-action-item crit">🚨 Isolate affected systems immediately</div>
                <div className="inv-action-item crit">🚨 Notify management and CISO</div>
                <div className="inv-action-item crit">🚨 Preserve all logs as evidence</div>
              </>)}
            </div>
          </div>
        ) : (
          // View Logs mode
          <div className="modal-body">
            <div className="log-raw-terminal">
              <div className="lrt-line">
                $ mpirun --oversubscribe -np {entry.processors_used || procs.length || 4}{" "}
                --mca btl_vader_single_copy_mechanism none ./mpi_log_analyzer {entry.file_name}
              </div>
              <div className="lrt-sep">── MPI execution output ─────────────────────</div>
              {procs.map((p, i) => (
                <div key={i} className="lrt-line">
                  Process <span style={{ color:PROC_COLORS[i%PROC_COLORS.length] }}>
                    {p.process_id}
                  </span> Local Threat Score:{" "}
                  <span style={{ color:PROC_COLORS[i%PROC_COLORS.length], fontWeight:700 }}>
                    {p.score}
                  </span>
                </div>
              ))}
              <div className="lrt-sep"/>
              <div className="lrt-line">
                Total logs read: <span style={{ color:"#00e5ff" }}>{entry.total_logs}</span>
              </div>
              <div className="lrt-line">
                GLOBAL THREAT SCORE:{" "}
                <span style={{ color:c.color, fontWeight:700 }}>{entry.global_threat_score}</span>
              </div>
              <div className="lrt-line">
                Execution Time: <span style={{ color:"#ffea00" }}>
                  {Number(entry.execution_time).toFixed(3)}
                </span>
              </div>
              <div className="lrt-line">
                Threat Level:{" "}
                <span style={{ color:c.color, fontWeight:700 }}>{entry.threat_level}</span>
              </div>
              <div className="lrt-line">
                Threat Rate:{" "}
                <span style={{ color:c.color }}>{Number(entry.threat_percentage).toFixed(2)}%</span>
              </div>
              <div className="lrt-line">
                File: <span style={{ color:"#d500f9" }}>{entry.file_name}</span>{" "}
                [{entry.file_format || "TXT"}]
              </div>
              <div className="lrt-line">
                Timestamp: <span style={{ color:"rgba(255,255,255,0.5)" }}>{entry.timestamp}</span>
              </div>
              <div className="lrt-sep"/>
              <div className="lrt-line ok">✓ Process exited with code 0</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ════════════════════════════════════════════════════════════════════════════════
export default function App() {
  const { isDark }     = useTheme();
  const { processors } = useMpiConfig();
  const { backendUrl } = useApiConfig();
  const classify       = useClassifyThreat();

  // ── Core state ───────────────────────────────────────────────────────────────
  const [activePage,    setActivePage]    = useState("dashboard");
  const [sideCollapsed, setSideCollapsed] = useState(false);

  // ── History state (source of truth for dashboard) ────────────────────────────
  const [history,     setHistory]     = useState([]);
  const [histLoading, setHistLoading] = useState(true);
  const [lastFetch,   setLastFetch]   = useState(null);

  // ── Dashboard UI state ───────────────────────────────────────────────────────
  const [trendRange,  setTrendRange]  = useState("24h");  // "today"|"24h"|"7d"
  const [modalEntry,  setModalEntry]  = useState(null);
  const [modalMode,   setModalMode]   = useState(null);   // "investigate"|"logs"

  // ── Fetch history ─────────────────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/history`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const raw = await res.json();
      const normalized = (Array.isArray(raw) ? raw : [])
        .map(normalizeEntry)
        .filter(Boolean)
        .sort((a, b) => b._date - a._date);  // newest first
      setHistory(normalized);
      setLastFetch(new Date());
    } catch (e) {
      console.warn("[Dashboard] History fetch failed:", e.message);
    } finally {
      setHistLoading(false);
    }
  }, [backendUrl]);

  // Fetch on mount + when page changes to dashboard
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Re-fetch when navigating to dashboard
  useEffect(() => {
    if (activePage === "dashboard") fetchHistory();
  }, [activePage]);

  // Auto-refresh every 30s while on dashboard
  useEffect(() => {
    if (activePage !== "dashboard") return;
    const id = setInterval(fetchHistory, 30000);
    return () => clearInterval(id);
  }, [activePage, fetchHistory]);

  // ── Derived dashboard data ────────────────────────────────────────────────────
  const latest = history[0] || null;

  // ── GLOBAL SCORE: average across all history ─────────────────────────────────
  const avgStats = useMemo(() => {
    if (!history.length) return { avgScore: 0, level: "SAFE" };
    const scores = history.map(h => h.global_threat_score);
    const avg    = Math.round(scores.reduce((s,v) => s+v, 0) / scores.length);
    // Classify the average using the same thresholds
    const level  = avg === 0  ? "SAFE"
                 : avg < 10   ? "SAFE"
                 : avg < 25   ? "LOW"
                 : avg < 50   ? "MEDIUM"
                 : avg < 100  ? "HIGH"
                 : "CRITICAL";
    return { avgScore: avg, level };
  }, [history]);

  // Active Alerts by Category — count threat levels across ALL history
  const alertsByLevel = useMemo(() => {
    if (!history.length) return [];
    const counts = {};
    history.forEach(h => {
      counts[h.threat_level] = (counts[h.threat_level] || 0) + 1;
    });
    return Object.entries(counts)
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([level, count]) => ({
        label: level, val: count,
        color: LEVEL_COLORS[level] || "#666",
      }));
  }, [history]);

  const maxAlertVal = useMemo(
    () => Math.max(...alertsByLevel.map(a => a.val), 1),
    [alertsByLevel]
  );

  // Threat Category Distribution Pie — ALL history
  const pieData = useMemo(() => {
    if (!history.length) return [
      { name:"No Data", value:1, color:"rgba(255,255,255,0.15)" }
    ];
    const counts = {};
    history.forEach(h => {
      counts[h.threat_level] = (counts[h.threat_level] || 0) + 1;
    });
    return Object.entries(counts).map(([level, count]) => ({
      name: level, value: count,
      color: LEVEL_COLORS[level] || "#666",
    }));
  }, [history]);

  // Trend Chart — group history by time period, working time filter
  const trendData = useMemo(() => {
    if (!history.length) return [];
    const now  = new Date();
    const cutoffs = {
      today: new Date(now.getFullYear(), now.getMonth(), now.getDate()),
      "24h": new Date(now - 24 * 60 * 60 * 1000),
      "7d":  new Date(now - 7  * 24 * 60 * 60 * 1000),
    };
    const cutoff = cutoffs[trendRange] || cutoffs["24h"];
    const filtered = history.filter(h => h._date >= cutoff);

    if (!filtered.length) return [];

    if (trendRange === "today" || trendRange === "24h") {
      // Group by hour
      const byHour = {};
      for (let h = 0; h < 24; h++) byHour[String(h).padStart(2,"0")+":00"] = { score:0, count:0, logs:0 };
      filtered.forEach(h => {
        const key = String(h._date.getHours()).padStart(2,"0") + ":00";
        if (byHour[key]) {
          byHour[key].score  = Math.max(byHour[key].score, h.global_threat_score);
          byHour[key].count += 1;
          byHour[key].logs  += h.total_logs;
        }
      });
      return Object.entries(byHour)
        .filter(([, v]) => v.count > 0 || trendRange === "24h")
        .map(([hour, v]) => ({
          label:    hour,
          score:    v.score,
          analyses: v.count,
          logs:     v.logs,
        }));
    } else {
      // 7d — group by day
      const days = {};
      for (let i = 6; i >= 0; i--) {
        const d = new Date(now - i * 24 * 60 * 60 * 1000);
        const key = d.toLocaleDateString("en-GB", { weekday:"short", day:"numeric" });
        days[key] = { score:0, count:0, logs:0, date:d };
      }
      filtered.forEach(h => {
        const key = h._date.toLocaleDateString("en-GB", { weekday:"short", day:"numeric" });
        if (days[key]) {
          days[key].score  = Math.max(days[key].score, h.global_threat_score);
          days[key].count += 1;
          days[key].logs  += h.total_logs;
        }
      });
      return Object.entries(days).map(([label, v]) => ({
        label,
        score:    v.score,
        analyses: v.count,
        logs:     v.logs,
      }));
    }
  }, [history, trendRange]);

  // Node Threat Scores — AGGREGATED across all history by node ID
  // Shows total accumulated score per node across every analysis run
  const barData = useMemo(() => {
    if (!history.length) {
      // Empty placeholder bars matching configured processor count
      return Array.from({ length: processors }, (_, i) => ({
        name: `N${i}`, score: 0,
        fill: PROC_COLORS[i % PROC_COLORS.length], active: false,
      }));
    }
    // Sum scores per node across all history entries
    const nodeMap = {};
    history.forEach(h => {
      (h.process_wise_scores || []).forEach(p => {
        const id = p.process_id;
        nodeMap[id] = (nodeMap[id] || 0) + p.score;
      });
    });
    // Include at least `processors` nodes, even if some have no data yet
    const maxNode = Math.max(
      ...Object.keys(nodeMap).map(Number),
      processors - 1,
      -1
    );
    return Array.from({ length: maxNode + 1 }, (_, i) => ({
      name:   `N${i}`,
      score:  nodeMap[i] || 0,
      fill:   PROC_COLORS[i % PROC_COLORS.length],
      active: (nodeMap[i] || 0) > 0,
    }));
  }, [history, processors]);

  // Alerts Feed — convert history entries to alert rows (latest 10)
  const alertFeed = useMemo(() => {
    return history.slice(0, 10).map((h, i) => ({
      id:       `Analysis #${String(history.length - i).padStart(4,"0")}`,
      severity: h.threat_level === "SAFE" ? "Low"
              : h.threat_level === "LOW"  ? "Low"
              : h.threat_level === "MEDIUM" ? "Medium"
              : h.threat_level === "HIGH" ? "High" : "Critical",
      time:     h.timestamp,
      file:     h.file_name,
      score:    h.global_threat_score,
      level:    h.threat_level,
      logs:     h.total_logs,
      pct:      h.threat_percentage,
      entry:    h,
    }));
  }, [history]);

  // ── Modal openers ─────────────────────────────────────────────────────────────
  const openInvestigate = (entry) => { setModalEntry(entry); setModalMode("investigate"); };
  const openLogs        = (entry) => { setModalEntry(entry); setModalMode("logs");        };
  const closeModal      = ()      => { setModalEntry(null);  setModalMode(null);           };

  // ── Page render ───────────────────────────────────────────────────────────────
  const renderPage = () => {
    switch (activePage) {
      case "monitoring":  return <LiveMonitoring/>;
      case "nodeviz":     return <Threatviz/>;
      case "upload":      return <LogUpload/>;
      case "analytics":   return <Analytics/>;
      case "performance": return <PerformanceLab/>;
      case "history":     return <History/>;
      case "settings":    return <Settings/>;
      default:            return <DashboardPage/>;
    }
  };

  // ══════════════════════════════════════════════════════════════════════════════
  // DASHBOARD
  // ══════════════════════════════════════════════════════════════════════════════
  const DashboardPage = () => (
    <div className="page-content">
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-sub">
            Real-time distributed threat analysis ·{" "}
            {histLoading
              ? <span style={{ color:"rgba(255,255,255,0.3)" }}>loading...</span>
              : <span style={{ color:"#00e5ff" }}>{history.length} analyses</span>
            }
            {lastFetch && (
              <span style={{ color:"rgba(255,255,255,0.2)", marginLeft:8 }}>
                · refreshed {lastFetch.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
        <button className="dash-refresh-btn" onClick={fetchHistory} title="Refresh dashboard">
          ↻ Refresh
        </button>
      </div>

      {/* ── No data banner ── */}
      {!histLoading && history.length === 0 && (
        <div className="dash-empty">
          <div className="dash-empty-icon">◎</div>
          <div className="dash-empty-msg">No analysis history yet.</div>
          <div className="dash-empty-sub">
            Upload a log file on the{" "}
            <button className="dash-link" onClick={() => setActivePage("upload")}>
              Log Upload
            </button>{" "}
            page to populate the dashboard.
          </div>
        </div>
      )}

      {/* ── Row 1: 4 stat cards ── */}
      <div className="stat-row">

        {/* 1 — Global Threat Score (AVERAGE across all history) */}
        <div className="stat-card">
          <div className="stat-card-header">
            <div className="stat-card-title">AVERAGE THREAT SCORE</div>
            {history.length > 0 && (
              <div className="stat-card-meta">
                <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10,
                  fontFamily:"'Share Tech Mono',monospace" }}>
                  avg of {history.length} analyses
                </span>
              </div>
            )}
          </div>
          {history.length > 0 ? (
            <ScoreRing
              score={avgStats.avgScore}
              level={avgStats.level}
            />
          ) : (
            <div className="stat-empty">No analyses yet</div>
          )}
          {history.length > 0 && (
            <div className="stat-card-footer">
              <span style={{ color:"#00e5ff", fontFamily:"'Orbitron',monospace", fontSize:11 }}>
                max: {Math.max(...history.map(h => h.global_threat_score))}
              </span>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10 }}>
                min: {Math.min(...history.map(h => h.global_threat_score))}
              </span>
            </div>
          )}
        </div>

        {/* 2 — Active Analyses by Threat Level */}
        <div className="stat-card">
          <div className="stat-card-title">ANALYSES BY THREAT LEVEL</div>
          {alertsByLevel.length > 0 ? (
            <div className="cat-list">
              {alertsByLevel.slice(0, 5).map((c, i) => (
                <div key={i} className="cat-row">
                  <span className="cat-lbl">{c.label}:</span>
                  <span className="cat-num" style={{ color:c.color }}>{c.val}</span>
                  <div className="cat-track">
                    <div className="cat-fill"
                      style={{ width:`${(c.val/maxAlertVal)*100}%`,
                        background:c.color, boxShadow:`0 0 8px ${c.color}` }}/>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="stat-empty">No data yet</div>
          )}
        </div>

        {/* 3 — Backend Status */}
        <div className="stat-card">
          <div className="stat-card-title">BACKEND STATUS</div>
          <div className="status-block">
            <div className="status-ok">
              <span className="status-icon ok">✓</span>
              <span className="status-text ok-text">API ONLINE</span>
            </div>
            <div className="status-sub-row">
              <div className="stat-card-title" style={{ marginBottom:8 }}>MPI STATUS</div>
              <div className="status-ok">
                <span className="status-icon ok">✓</span>
                <span className="status-text ok-text">RUNNING</span>
              </div>
            </div>
            <div style={{ marginTop:12, fontFamily:"'Share Tech Mono',monospace",
              fontSize:11, color:"rgba(255,255,255,0.3)" }}>
              {backendUrl}
            </div>
          </div>
        </div>

        {/* 4 — Performance — all dynamic */}
        <div className="stat-card">
          <div className="stat-card-title">PERFORMANCE SUMMARY</div>
          <div className="perf-list">
            <div className="perf-row">
              <span className="perf-lbl">Configured Processors</span>
              <span className="perf-val" style={{ color:"#06b6d4" }}>{processors}</span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Last Run Nodes</span>
              <span className="perf-val" style={{ color:"#a855f7" }}>
                {latest?.process_wise_scores?.length || "—"}
              </span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Last Exec Time</span>
              <span className="perf-val" style={{ color:"#ffa726" }}>
                {latest ? `${Number(latest.execution_time).toFixed(3)}s` : "—"}
              </span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Last File Logs</span>
              <span className="perf-val" style={{ color:"#00e676" }}>
                {latest ? fmtNum(latest.total_logs) : "—"}
              </span>
            </div>
            <div className="perf-row">
              <span className="perf-lbl">Total Analyses</span>
              <span className="perf-val" style={{ color:"#00e5ff" }}>{history.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Row 2: Threat Distribution Pie + Trend Line ── */}
      <div className="chart-row">

        {/* Pie — threat level distribution from history */}
        <div className="chart-card">
          <div className="chart-card-title">THREAT LEVEL DISTRIBUTION</div>
          {history.length > 0 ? (
            <div className="pie-wrap">
              <ResponsiveContainer width="55%" height={220}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%"
                    innerRadius={55} outerRadius={90}
                    dataKey="value" startAngle={90} endAngle={-270} paddingAngle={2}>
                    {pieData.map((d, i) => (
                      <Cell key={i} fill={d.color}
                        style={{ filter:`drop-shadow(0 0 6px ${d.color}44)` }}/>
                    ))}
                  </Pie>
                  <Tooltip content={<CyberTooltip/>}/>
                </PieChart>
              </ResponsiveContainer>
              <div className="pie-legend">
                {pieData.map((d, i) => (
                  <div key={i} className="pie-legend-row">
                    <div className="pie-legend-dot" style={{ background:d.color }}/>
                    <span className="pie-legend-lbl">{d.name}</span>
                    <span className="pie-legend-val" style={{ color:d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="stat-empty" style={{ height:200, display:"flex",
              alignItems:"center", justifyContent:"center" }}>
              No data yet
            </div>
          )}
        </div>

        {/* Trend Line — time filter WORKS, data from history */}
        <div className="chart-card">
          <div className="chart-card-header">
            <div className="chart-card-title">THREAT SCORE TREND</div>
            <div className="chart-card-filters">
              {["today","24h","7d"].map(r => (
                <span key={r}
                  className={`filter-chip ${trendRange===r?"active-chip":""}`}
                  onClick={() => setTrendRange(r)}
                  style={{ cursor:"pointer" }}>
                  {r}
                </span>
              ))}
            </div>
          </div>
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trendData} margin={{ top:10, right:20, left:-20, bottom:0 }}>
                <defs>
                  <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="analysesGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#a855f7" stopOpacity={0.25}/>
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)"/>
                <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }}
                  axisLine={false} tickLine={false} interval="preserveStartEnd"/>
                <YAxis yAxisId="left" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <YAxis yAxisId="right" orientation="right"
                  tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<CyberTooltip/>}/>
                <Legend wrapperStyle={{ fontSize:10, color:"rgba(255,255,255,0.4)" }}/>
                <Area yAxisId="left" type="monotone" dataKey="score"
                  stroke="#06b6d4" strokeWidth={2} fill="url(#trendGrad)"
                  dot={{ r:3, fill:"#06b6d4" }} name="Max Score"/>
                <Area yAxisId="right" type="monotone" dataKey="analyses"
                  stroke="#a855f7" strokeWidth={2} fill="url(#analysesGrad)"
                  dot={{ r:3, fill:"#a855f7" }} name="Analyses"/>
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="stat-empty" style={{ height:220, display:"flex",
              alignItems:"center", justifyContent:"center", flexDirection:"column", gap:8 }}>
              <span>No analyses in this time range</span>
              <span style={{ fontSize:11, opacity:0.5 }}>
                ({trendRange === "today" ? "today so far" :
                   trendRange === "24h"  ? "last 24 hours" : "last 7 days"})
              </span>
            </div>
          )}
        </div>
      </div>

      {/* ── Row 3: Node Scores ABOVE Recent Alerts (full width, stacked) ── */}
      <div style={{ display:"flex", flexDirection:"column", gap:16, marginBottom:20 }}>

        {/* NODE THREAT SCORES — full width, aggregated across all history */}
        <div className="chart-card" style={{ width:"100%" }}>
          <div className="chart-card-header">
            <div className="chart-card-title">NODE THREAT SCORES — CUMULATIVE ALL HISTORY</div>
            <span style={{ fontSize:10, fontFamily:"'Share Tech Mono',monospace",
              color:"rgba(255,255,255,0.3)" }}>
              {processors} processors configured · summed across {history.length} analyses
            </span>
          </div>
          {barData.some(b => b.score > 0) ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData} barCategoryGap="20%"
                margin={{ top:10, right:20, left:-10, bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3"
                  stroke="rgba(255,255,255,0.05)" vertical={false}/>
                <XAxis dataKey="name" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:12 }}
                  axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<CyberTooltip/>}
                  cursor={{ fill:"rgba(255,255,255,0.03)" }}/>
                <Bar dataKey="score" radius={[4,4,0,0]} name="Cumulative Score">
                  {barData.map((d, i) => (
                    <Cell key={i} fill={d.active ? d.fill : "rgba(255,255,255,0.08)"}
                      style={ d.active ? { filter:`drop-shadow(0 0 6px ${d.fill})` } : {}}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="stat-empty" style={{ height:200, display:"flex",
              alignItems:"center", justifyContent:"center" }}>
              No node data yet — upload a log file to populate
            </div>
          )}
        </div>

        {/* RECENT ANALYSIS RESULTS — full width, below node scores */}
        <div className="chart-card" style={{ width:"100%" }}>
          <div className="chart-card-header">
            <div className="chart-card-title">RECENT ANALYSIS RESULTS</div>
            <span style={{ fontSize:10, fontFamily:"'Share Tech Mono',monospace",
              color:"rgba(255,255,255,0.3)" }}>
              {alertFeed.length} recent · click buttons to investigate
            </span>
          </div>

          {alertFeed.length > 0 ? (
            <div className="alerts-table-wrap">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Level</th>
                    <th>File</th>
                    <th>Score</th>
                    <th>Logs</th>
                    <th>Timestamp</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {alertFeed.map((a, i) => {
                    const c = tc(a.level);
                    return (
                      <tr key={i} className="alert-row">
                        <td className="alert-id" style={{ color:"rgba(255,255,255,0.4)" }}>
                          {a.id}
                        </td>
                        <td>
                          <span className="sev-badge"
                            style={{ background:c.bg, color:c.color,
                              border:`1px solid ${c.color}44` }}>
                            {a.level}
                          </span>
                        </td>
                        <td className="alert-detail"
                          style={{ maxWidth:200, overflow:"hidden",
                            textOverflow:"ellipsis", whiteSpace:"nowrap" }}
                          title={a.file}>
                          {a.file}
                        </td>
                        <td style={{ fontFamily:"'Orbitron',monospace",
                          fontSize:12, color:c.color, fontWeight:700 }}>
                          {a.score}
                        </td>
                        <td style={{ fontFamily:"'Share Tech Mono',monospace",
                          fontSize:12, color:"rgba(255,255,255,0.5)" }}>
                          {fmtNum(a.logs)}
                        </td>
                        <td className="alert-time" style={{ fontSize:10, whiteSpace:"nowrap" }}>
                          {a.time}
                        </td>
                        <td>
                          <div className="alert-actions">
                            <button className="act-btn inv-btn"
                              onClick={() => openInvestigate(a.entry)}>
                              🔍 Investigate
                            </button>
                            <button className="act-btn log-btn"
                              onClick={() => openLogs(a.entry)}>
                              📋 View Logs
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="stat-empty" style={{ height:120, display:"flex",
              alignItems:"center", justifyContent:"center", flexDirection:"column", gap:8 }}>
              <span>No analysis results yet</span>
              <button className="dash-link" onClick={() => setActivePage("upload")}>
                → Upload a log file to get started
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // ── Shell ─────────────────────────────────────────────────────────────────────
  return (
    <div className={`app-shell ${isDark ? "app-dark" : "app-light"}`}>

      {/* Sidebar */}
      <aside className={`sidebar app-sidebar ${sideCollapsed ? "collapsed" : ""}`}>
        <div className="sidebar-logo">
          <div className="logo-icon">🛡</div>
          {!sideCollapsed && (
            <div className="logo-text app-logo-text">
              <div className="logo-main">CyberThreat<span>MPI</span></div>
              <div className="logo-sub">THREAT ANALYZER</div>
            </div>
          )}
          <button className="collapse-btn"
            onClick={() => setSideCollapsed(v => !v)}>
            {sideCollapsed ? "›" : "‹"}
          </button>
        </div>

        {!sideCollapsed && <div className="nav-group-label">CORE PAGES</div>}

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(item => (
            <button key={item.id}
              className={`nav-item app-nav-item ${activePage===item.id ? "nav-active active" : ""}`}
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
          {!sideCollapsed && <button className="logout-btn">⎋ Logout</button>}
        </div>
      </aside>

      {/* Main */}
      <div className="main-area app-content">
        <div className="topbar app-topbar">
          <div className="topbar-title">
            {NAV_ITEMS.find(n => n.id === activePage)?.label || "Dashboard"}
          </div>
          <div className="topbar-right">
            <div className="search-bar app-search">
              <span>⌕</span>
              <input placeholder="Search..."/>
            </div>
            <ThemeToggle/>
            <div className="topbar-icon-btn notif">
              🔔<span className="notif-dot"/>
            </div>
            <div className="topbar-user">
              <div className="tu-avatar">A</div>
              <span>Alex ▾</span>
            </div>
          </div>
        </div>

        <div className="page-scroll">
          {renderPage()}
        </div>
      </div>

      {/* Alert/Log Detail Modal */}
      {modalEntry && (
        <AlertModal
          entry={modalEntry}
          mode={modalMode}
          onClose={closeModal}
        />
      )}
    </div>
  );
}