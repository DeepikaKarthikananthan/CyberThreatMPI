import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import { useApiConfig, useThresholds } from "./Settingscontext";
import "./History.css";

// ─── Constants ────────────────────────────────────────────────────────────────
const THREAT_CFG = {
  SAFE:     { color: "#00e676", bg: "rgba(0,230,118,0.1)",  border: "rgba(0,230,118,0.3)"  },
  LOW:      { color: "#29b6f6", bg: "rgba(41,182,246,0.1)", border: "rgba(41,182,246,0.3)" },
  MEDIUM:   { color: "#ffa726", bg: "rgba(255,167,38,0.1)", border: "rgba(255,167,38,0.3)" },
  HIGH:     { color: "#ef5350", bg: "rgba(239,83,80,0.1)",  border: "rgba(239,83,80,0.3)"  },
  CRITICAL: { color: "#ff1744", bg: "rgba(255,23,68,0.1)",  border: "rgba(255,23,68,0.3)"  },
};
const tc = (level) => THREAT_CFG[level] || THREAT_CFG.SAFE;

const FORMAT_ICON = { TXT:"📄", LOG:"📋", JSON:"{ }", CSV:"📊" };

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (n) => Number(n || 0).toLocaleString();
const pct = (n) => `${Number(n || 0).toFixed(1)}%`;

function scoreBar(score, thresholds) {
  const max = (thresholds?.critical || 100) * 1.5;
  return Math.min((score / max) * 100, 100);
}

// ─── Custom tooltip ───────────────────────────────────────────────────────────
const HTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="hy-tooltip">
      <div className="hy-tt-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.stroke }}>
          {p.name}: <b>{typeof p.value === "number" ? p.value.toFixed(1) : p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Sparkline ────────────────────────────────────────────────────────────────
function Spark({ data, color }) {
  if (!data || data.length < 2) return <span style={{ color:"rgba(255,255,255,0.2)", fontSize:11 }}>—</span>;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * 60;
    const y = 16 - (v / max) * 14;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width="64" height="20" viewBox="0 0 64 20">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round"
        style={{ filter:`drop-shadow(0 0 3px ${color})` }}/>
    </svg>
  );
}

// ─── Threat Level Badge ───────────────────────────────────────────────────────
function ThreatBadge({ level }) {
  const c = tc(level);
  return (
    <span className="hy-badge" style={{ background:c.bg, color:c.color, borderColor:c.border }}>
      {level}
    </span>
  );
}

// ─── Score Ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score, level, size = 56 }) {
  const c   = tc(level);
  const R   = size * 0.38;
  const cx  = size / 2, cy = size / 2;
  const pct = Math.min(score / 200, 1);
  const startAngle = (210 * Math.PI) / 180;
  const sweep = (240 * Math.PI) / 180;
  const endAngle = startAngle - sweep * pct;
  const ap = (r, a) => [cx - r * Math.cos(a), cy + r * Math.sin(a)];
  const arc = (a1, a2, lg) => {
    const [x1,y1] = ap(R,a1), [x2,y2] = ap(R,a2);
    return `M${x1},${y1} A${R},${R} 0 ${lg} 1 ${x2},${y2}`;
  };
  return (
    <div style={{ position:"relative", display:"inline-flex", alignItems:"center", justifyContent:"center" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <path d={arc(startAngle, startAngle-sweep, 1)}
          fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="4" strokeLinecap="round"/>
        {pct > 0 && (
          <path d={arc(startAngle, endAngle, pct>0.5?1:0)}
            fill="none" stroke={c.color} strokeWidth="4" strokeLinecap="round"
            style={{ filter:`drop-shadow(0 0 3px ${c.color})` }}/>
        )}
      </svg>
      <div style={{
        position:"absolute", textAlign:"center",
        fontFamily:"'Orbitron',monospace", fontSize:size*0.2,
        fontWeight:900, color:c.color, lineHeight:1,
      }}>{score}</div>
    </div>
  );
}

// ─── Comparison Modal ─────────────────────────────────────────────────────────
function CompareModal({ a, b, onClose, thresholds }) {
  const fields = [
    { key:"total_logs",          label:"Total Logs",     fmt: fmt },
    { key:"global_threat_score", label:"Threat Score",   fmt: String },
    { key:"threat_level",        label:"Threat Level",   fmt: String },
    { key:"threat_percentage",   label:"Threat Rate",    fmt: pct },
    { key:"execution_time",      label:"Exec Time (s)",  fmt: (v) => Number(v).toFixed(3) },
    { key:"processors_used",     label:"Processors",     fmt: String },
    { key:"file_format",         label:"Format",         fmt: String },
  ];
  const radarData = [
    "total_logs","global_threat_score","threat_percentage","execution_time",
  ].map(k => ({
    metric: k.replace(/_/g," ").toUpperCase().slice(0,12),
    A: Math.min((Number(a[k]||0) / Math.max(Number(a[k]||0), Number(b[k]||0), 1)) * 100, 100),
    B: Math.min((Number(b[k]||0) / Math.max(Number(a[k]||0), Number(b[k]||0), 1)) * 100, 100),
  }));

  return (
    <div className="hy-modal-overlay" onClick={onClose}>
      <div className="hy-modal" onClick={e => e.stopPropagation()}>
        <div className="hy-modal-header">
          <div className="hy-modal-title">COMPARISON ANALYSIS</div>
          <button className="hy-modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="hy-cmp-grid">
          <div className="hy-cmp-col">
            <div className="hy-cmp-col-label" style={{ color:"#00e5ff" }}>RECORD A</div>
            <div className="hy-cmp-filename">{a.file_name}</div>
            <div className="hy-cmp-ts">{a.timestamp}</div>
          </div>
          <div className="hy-cmp-vs">VS</div>
          <div className="hy-cmp-col">
            <div className="hy-cmp-col-label" style={{ color:"#d500f9" }}>RECORD B</div>
            <div className="hy-cmp-filename">{b.file_name}</div>
            <div className="hy-cmp-ts">{b.timestamp}</div>
          </div>
        </div>

        <div className="hy-cmp-table">
          {fields.map(f => {
            const av = Number(a[f.key] || 0), bv = Number(b[f.key] || 0);
            const aWins = typeof av === "number" && av < bv;
            const bWins = typeof bv === "number" && bv < av;
            return (
              <div key={f.key} className="hy-cmp-row">
                <div className={`hy-cmp-val ${aWins ? "hy-cmp-win" : ""}`}
                  style={{ color:"#00e5ff" }}>
                  {f.fmt(a[f.key])}
                </div>
                <div className="hy-cmp-field">{f.label}</div>
                <div className={`hy-cmp-val ${bWins ? "hy-cmp-win" : ""}`}
                  style={{ color:"#d500f9" }}>
                  {f.fmt(b[f.key])}
                </div>
              </div>
            );
          })}
        </div>

        <div className="hy-cmp-radar">
          <div className="hy-cmp-radar-title">RELATIVE COMPARISON RADAR</div>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData} margin={{ top:10,right:30,left:30,bottom:10 }}>
              <PolarGrid stroke="rgba(255,255,255,0.08)"/>
              <PolarAngleAxis dataKey="metric"
                tick={{ fill:"rgba(255,255,255,0.4)", fontSize:10, fontFamily:"Rajdhani" }}/>
              <PolarRadiusAxis angle={30} domain={[0,100]}
                tick={{ fill:"rgba(255,255,255,0.2)", fontSize:9 }} axisLine={false}/>
              <Radar name="Record A" dataKey="A" stroke="#00e5ff"
                fill="#00e5ff" fillOpacity={0.15} strokeWidth={2}
                dot={{ fill:"#00e5ff", r:3 }}/>
              <Radar name="Record B" dataKey="B" stroke="#d500f9"
                fill="#d500f9" fillOpacity={0.15} strokeWidth={2}
                dot={{ fill:"#d500f9", r:3 }}/>
              <Tooltip content={<HTooltip/>}/>
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

// ─── Detail Drawer ────────────────────────────────────────────────────────────
function DetailDrawer({ entry, onClose }) {
  if (!entry) return null;
  const c     = tc(entry.threat_level);
  const procs = entry.process_wise_scores || [];
  const total = procs.reduce((s, p) => s + p.score, 0) || 1;

  return (
    <div className="hy-drawer-overlay" onClick={onClose}>
      <div className="hy-drawer" onClick={e => e.stopPropagation()}>
        <div className="hy-drawer-header">
          <div>
            <div className="hy-drawer-title">{entry.file_name}</div>
            <div className="hy-drawer-ts">{entry.timestamp}</div>
          </div>
          <button className="hy-modal-close" onClick={onClose}>✕</button>
        </div>

        {/* Score + level */}
        <div className="hy-drawer-hero">
          <ScoreRing score={entry.global_threat_score} level={entry.threat_level} size={90}/>
          <div className="hy-drawer-hero-right">
            <ThreatBadge level={entry.threat_level}/>
            <div className="hy-drawer-stat-row">
              <div className="hy-ds">
                <div className="hy-ds-val" style={{ color:"#00e5ff" }}>{fmt(entry.total_logs)}</div>
                <div className="hy-ds-lbl">Total Logs</div>
              </div>
              <div className="hy-ds">
                <div className="hy-ds-val" style={{ color:c.color }}>{pct(entry.threat_percentage)}</div>
                <div className="hy-ds-lbl">Threat Rate</div>
              </div>
              <div className="hy-ds">
                <div className="hy-ds-val" style={{ color:"#ffea00" }}>{Number(entry.execution_time||0).toFixed(3)}s</div>
                <div className="hy-ds-lbl">Exec Time</div>
              </div>
              <div className="hy-ds">
                <div className="hy-ds-val" style={{ color:"#76ff03" }}>{entry.processors_used || procs.length}</div>
                <div className="hy-ds-lbl">Processors</div>
              </div>
            </div>
          </div>
        </div>

        {/* Per-process bar chart */}
        {procs.length > 0 && (
          <div className="hy-drawer-section">
            <div className="hy-drawer-section-title">PER-NODE SCORES</div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={procs.map(p => ({ name:`N${p.process_id}`, score:p.score }))}
                margin={{ top:5,right:10,left:-20,bottom:0 }} barCategoryGap="25%">
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="name" tick={{ fill:"rgba(255,255,255,0.4)",fontSize:11 }}
                  axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill:"rgba(255,255,255,0.3)",fontSize:10 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<HTooltip/>} cursor={{ fill:"rgba(255,255,255,0.03)" }}/>
                <Bar dataKey="score" name="Score" radius={[4,4,0,0]}>
                  {procs.map((_, i) => {
                    const colors = ["#00e5ff","#76ff03","#ff6d00","#d500f9",
                                    "#ffea00","#ff1744","#29b6f6","#ffa726"];
                    return <Cell key={i} fill={colors[i % colors.length]}
                      style={{ filter:`drop-shadow(0 0 4px ${colors[i%colors.length]}66)` }}/>;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Contribution share */}
        {procs.length > 0 && (
          <div className="hy-drawer-section">
            <div className="hy-drawer-section-title">LOAD DISTRIBUTION</div>
            <div className="hy-proc-bars">
              {procs.map((p, i) => {
                const colors = ["#00e5ff","#76ff03","#ff6d00","#d500f9",
                                "#ffea00","#ff1744","#29b6f6","#ffa726"];
                const share = ((p.score / total) * 100).toFixed(1);
                return (
                  <div key={i} className="hy-proc-bar-row">
                    <span className="hy-proc-id" style={{ color:colors[i%colors.length] }}>N{p.process_id}</span>
                    <div className="hy-proc-track">
                      <div className="hy-proc-fill"
                        style={{ width:`${share}%`, background:colors[i%colors.length],
                          boxShadow:`0 0 6px ${colors[i%colors.length]}66` }}/>
                    </div>
                    <span className="hy-proc-pct">{share}%</span>
                    <span className="hy-proc-score">{p.score}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Raw fields */}
        <div className="hy-drawer-section">
          <div className="hy-drawer-section-title">RAW RECORD</div>
          <div className="hy-raw-grid">
            {[
              ["File",         entry.file_name],
              ["Format",       entry.file_format || "TXT"],
              ["Total Logs",   fmt(entry.total_logs)],
              ["Threat Score", entry.global_threat_score],
              ["Threat Level", entry.threat_level],
              ["Threat Rate",  pct(entry.threat_percentage)],
              ["Execution",    `${Number(entry.execution_time||0).toFixed(4)}s`],
              ["Processors",   entry.processors_used || procs.length],
              ["Timestamp",    entry.timestamp],
            ].map(([k,v]) => (
              <div key={k} className="hy-raw-row">
                <span className="hy-raw-key">{k}</span>
                <span className="hy-raw-val">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════
export default function History() {
  const { backendUrl }  = useApiConfig();
  const thresholds      = useThresholds();

  // ── State ──────────────────────────────────────────────────────────────────
  const [history,       setHistory]       = useState([]);
  const [loading,       setLoading]       = useState(true);
  const [error,         setError]         = useState(null);
  const [search,        setSearch]        = useState("");
  const [levelFilter,   setLevelFilter]   = useState("ALL");
  const [formatFilter,  setFormatFilter]  = useState("ALL");
  const [sortCol,       setSortCol]       = useState("timestamp");
  const [sortDir,       setSortDir]       = useState("desc");
  const [viewMode,      setViewMode]      = useState("table");   // table | timeline | grid
  const [selected,      setSelected]      = useState(new Set()); // ids for comparison
  const [compareOpen,   setCompareOpen]   = useState(false);
  const [detailEntry,   setDetailEntry]   = useState(null);
  const [page,          setPage]          = useState(1);
  const [autoRefresh,   setAutoRefresh]   = useState(false);
  const [lastRefresh,   setLastRefresh]   = useState(null);
  const PAGE_SIZE = 10;
  const timerRef = useRef(null);

  // ── Fetch ──────────────────────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/history`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory(Array.isArray(data) ? data.reverse() : []);
      setLastRefresh(new Date());
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [backendUrl]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  // Auto-refresh every 15s if enabled
  useEffect(() => {
    clearInterval(timerRef.current);
    if (autoRefresh) {
      timerRef.current = setInterval(fetchHistory, 15000);
    }
    return () => clearInterval(timerRef.current);
  }, [autoRefresh, fetchHistory]);

  // ── Delete ─────────────────────────────────────────────────────────────────
  const deleteAll = async () => {
    if (!window.confirm("Delete ALL analysis history?")) return;
    await fetch(`${backendUrl}/history`, { method:"DELETE" });
    setHistory([]); setSelected(new Set());
  };

  // ── Export ─────────────────────────────────────────────────────────────────
  const exportData = (format) => {
    if (format === "json") {
      const blob = new Blob([JSON.stringify(history, null, 2)], { type:"application/json" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a"); a.href=url;
      a.download = `history_${Date.now()}.json`; a.click();
      URL.revokeObjectURL(url);
    } else {
      const headers = ["file_name","total_logs","global_threat_score","threat_level",
                       "threat_percentage","execution_time","processors_used","file_format","timestamp"];
      const rows = history.map(h => headers.map(k => JSON.stringify(h[k]??"")));
      const csv  = [headers, ...rows].map(r => r.join(",")).join("\n");
      const blob = new Blob([csv], { type:"text/csv" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a"); a.href=url;
      a.download = `history_${Date.now()}.csv`; a.click();
      URL.revokeObjectURL(url);
    }
  };

  // ── Filter + sort ──────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let r = [...history];
    if (levelFilter !== "ALL")  r = r.filter(h => h.threat_level === levelFilter);
    if (formatFilter !== "ALL") r = r.filter(h => (h.file_format||"TXT") === formatFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      r = r.filter(h =>
        (h.file_name||"").toLowerCase().includes(q) ||
        (h.threat_level||"").toLowerCase().includes(q) ||
        String(h.global_threat_score).includes(q)
      );
    }
    r.sort((a, b) => {
      let av = a[sortCol] ?? "", bv = b[sortCol] ?? "";
      if (!isNaN(Number(av)) && !isNaN(Number(bv))) { av = Number(av); bv = Number(bv); }
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return r;
  }, [history, levelFilter, formatFilter, search, sortCol, sortDir]);

  const pages     = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  // ── Stats ──────────────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    if (!history.length) return null;
    const scores = history.map(h => Number(h.global_threat_score||0));
    const levels = history.reduce((acc, h) => {
      acc[h.threat_level] = (acc[h.threat_level]||0)+1; return acc;
    }, {});
    const topLevel = Object.entries(levels).sort((a,b)=>b[1]-a[1])[0]?.[0] || "SAFE";
    return {
      total:    history.length,
      avgScore: (scores.reduce((s,v)=>s+v,0)/scores.length).toFixed(1),
      maxScore: Math.max(...scores),
      minScore: Math.min(...scores),
      topLevel,
      levels,
      avgLogs:  Math.round(history.reduce((s,h)=>s+Number(h.total_logs||0),0)/history.length),
      totalLogs: history.reduce((s,h)=>s+Number(h.total_logs||0),0),
    };
  }, [history]);

  // ── Chart data ─────────────────────────────────────────────────────────────
  const trendData = useMemo(() =>
    [...history].reverse().slice(-20).map((h, i) => ({
      i: i+1,
      score: Number(h.global_threat_score||0),
      logs:  Number(h.total_logs||0),
      label: (h.file_name||"").slice(0,10),
    })), [history]);

  const levelDist = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.levels).map(([level, count]) => ({
      name: level, value: count, color: tc(level).color,
    }));
  }, [stats]);

  // ── Sort toggle ───────────────────────────────────────────────────────────
  const toggleSort = (col) => {
    if (sortCol === col) setSortDir(d => d==="asc"?"desc":"asc");
    else { setSortCol(col); setSortDir("desc"); }
    setPage(1);
  };

  const SortTh = ({ col, label }) => (
    <th className={`hy-th sortable ${sortCol===col?"hy-th-active":""}`}
      onClick={() => toggleSort(col)}>
      {label}
      <span className="hy-sort-arrow">
        {sortCol===col ? (sortDir==="asc"?"↑":"↓") : "⇅"}
      </span>
    </th>
  );

  // ── Comparison ────────────────────────────────────────────────────────────
  const toggleSelect = (entry) => {
    setSelected(prev => {
      const next = new Set(prev);
      const key  = entry.timestamp + entry.file_name;
      if (next.has(key)) next.delete(key);
      else if (next.size < 2) next.add(key);
      return next;
    });
  };
  const isSelected = (entry) => selected.has(entry.timestamp + entry.file_name);
  const selectedEntries = history.filter(h => selected.has(h.timestamp + h.file_name));

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="hy-page">
      <div className="hy-scanline" aria-hidden="true"/>

      {/* ── Header ── */}
      <div className="hy-header">
        <div className="hy-header-left">
          <div className="hy-header-icon">◈</div>
          <div>
            <div className="hy-title">ANALYSIS HISTORY</div>
            <div className="hy-subtitle">
              Full audit trail of MPI threat analyses ·{" "}
              {stats ? <span style={{ color:"#00e5ff" }}>{stats.total} records</span> : "loading..."}
              {lastRefresh && (
                <span style={{ color:"rgba(255,255,255,0.2)", marginLeft:10 }}>
                  · refreshed {lastRefresh.toLocaleTimeString()}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="hy-header-right">
          {/* Auto-refresh toggle */}
          <button className={`hy-hdr-btn ${autoRefresh?"hy-hdr-btn-active":""}`}
            onClick={() => setAutoRefresh(v=>!v)}>
            <span className={autoRefresh?"hy-spin":""}>↻</span> AUTO
          </button>
          <button className="hy-hdr-btn" onClick={fetchHistory}>⟳ REFRESH</button>
          <button className="hy-hdr-btn" onClick={() => exportData("csv")}>⬇ CSV</button>
          <button className="hy-hdr-btn" onClick={() => exportData("json")}>⬇ JSON</button>
          {selected.size === 2 && (
            <button className="hy-hdr-btn hy-compare-btn"
              onClick={() => setCompareOpen(true)}>
              ⟺ COMPARE
            </button>
          )}
          <button className="hy-hdr-btn hy-danger-btn" onClick={deleteAll}>🗑 CLEAR ALL</button>
        </div>
      </div>

      {/* ── Stats Strip ── */}
      {stats && (
        <div className="hy-stats-strip">
          {[
            { label:"TOTAL ANALYSES",   val: stats.total,                    color:"#00e5ff" },
            { label:"AVG THREAT SCORE", val: stats.avgScore,                 color:"#ffa726" },
            { label:"HIGHEST SCORE",    val: stats.maxScore,                 color:"#ff1744" },
            { label:"LOWEST SCORE",     val: stats.minScore,                 color:"#76ff03" },
            { label:"DOMINANT LEVEL",   val: stats.topLevel,                 color: tc(stats.topLevel).color },
            { label:"TOTAL LOGS",       val: stats.totalLogs.toLocaleString(), color:"#d500f9" },
            { label:"AVG LOGS/FILE",    val: stats.avgLogs.toLocaleString(), color:"#29b6f6" },
          ].map((s, i) => (
            <div key={i} className="hy-stat-card" style={{ animationDelay:`${i*0.07}s` }}>
              <div className="hy-stat-val" style={{ color:s.color }}>{s.val}</div>
              <div className="hy-stat-lbl">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Charts Row ── */}
      {history.length > 1 && (
        <div className="hy-charts-row">
          {/* Trend line */}
          <div className="hy-chart-card" style={{ flex:2 }}>
            <div className="hy-chart-title">THREAT SCORE TREND (LAST 20 ANALYSES)</div>
            <ResponsiveContainer width="100%" height={150}>
              <AreaChart data={trendData} margin={{ top:8,right:16,left:-20,bottom:0 }}>
                <defs>
                  <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="i" tick={{ fill:"rgba(255,255,255,0.25)",fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill:"rgba(255,255,255,0.25)",fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<HTooltip/>}/>
                <Area type="monotone" dataKey="score" stroke="#00e5ff" strokeWidth={2}
                  fill="url(#trendGrad)" dot={false} name="Score"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Level distribution pie */}
          <div className="hy-chart-card" style={{ flex:1 }}>
            <div className="hy-chart-title">THREAT LEVEL DISTRIBUTION</div>
            <div style={{ display:"flex", alignItems:"center", gap:16 }}>
              <ResponsiveContainer width={120} height={120}>
                <PieChart>
                  <Pie data={levelDist} cx="50%" cy="50%"
                    innerRadius={30} outerRadius={52} dataKey="value" paddingAngle={2}>
                    {levelDist.map((d, i) => (
                      <Cell key={i} fill={d.color}
                        style={{ filter:`drop-shadow(0 0 4px ${d.color}66)` }}/>
                    ))}
                  </Pie>
                  <Tooltip content={<HTooltip/>}/>
                </PieChart>
              </ResponsiveContainer>
              <div className="hy-pie-legend">
                {levelDist.map((d, i) => (
                  <div key={i} className="hy-pie-leg-row">
                    <div className="hy-pie-dot" style={{ background:d.color }}/>
                    <span style={{ color:"rgba(255,255,255,0.6)", fontSize:11 }}>{d.name}</span>
                    <span style={{ color:d.color, fontFamily:"'Orbitron',monospace", fontSize:11, marginLeft:"auto" }}>
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Score bars */}
          <div className="hy-chart-card" style={{ flex:2 }}>
            <div className="hy-chart-title">SCORE DISTRIBUTION (LAST 20)</div>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={trendData} barCategoryGap="20%"
                margin={{ top:8,right:16,left:-20,bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="i" tick={{ fill:"rgba(255,255,255,0.25)",fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill:"rgba(255,255,255,0.25)",fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<HTooltip/>} cursor={{ fill:"rgba(255,255,255,0.03)" }}/>
                <Bar dataKey="score" name="Score" radius={[3,3,0,0]}>
                  {trendData.map((d, i) => {
                    const level = history[history.length-1-i]?.threat_level || "SAFE";
                    return <Cell key={i} fill={tc(level).color}
                      style={{ filter:`drop-shadow(0 0 3px ${tc(level).color}66)` }}/>;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ── Controls ── */}
      <div className="hy-controls">
        <div className="hy-search-wrap">
          <span className="hy-search-icon">⌕</span>
          <input className="hy-search" placeholder="Search by filename, threat level, score..."
            value={search} onChange={e => { setSearch(e.target.value); setPage(1); }}/>
          {search && (
            <button className="hy-search-clear" onClick={() => setSearch("")}>✕</button>
          )}
        </div>

        <div className="hy-filter-group">
          {["ALL","SAFE","LOW","MEDIUM","HIGH","CRITICAL"].map(l => (
            <button key={l}
              className={`hy-filter-btn ${levelFilter===l?"hy-filter-active":""}`}
              style={ levelFilter===l && l!=="ALL"
                ? { borderColor:tc(l).border, color:tc(l).color, background:tc(l).bg }
                : {} }
              onClick={() => { setLevelFilter(l); setPage(1); }}>
              {l}
            </button>
          ))}
        </div>

        <div className="hy-filter-group">
          {["ALL","TXT","JSON","CSV","LOG"].map(f => (
            <button key={f}
              className={`hy-filter-btn ${formatFilter===f?"hy-filter-active":""}`}
              onClick={() => { setFormatFilter(f); setPage(1); }}>
              {FORMAT_ICON[f] || "◈"} {f}
            </button>
          ))}
        </div>

        <div className="hy-view-toggle">
          {[["table","⊞ TABLE"],["timeline","⦿ TIMELINE"],["grid","▦ GRID"]].map(([m,l]) => (
            <button key={m}
              className={`hy-view-btn ${viewMode===m?"hy-view-active":""}`}
              onClick={() => setViewMode(m)}>{l}</button>
          ))}
        </div>
      </div>

      {/* ── Compare hint ── */}
      {selected.size > 0 && (
        <div className="hy-compare-hint">
          <span>◈ {selected.size}/2 selected for comparison</span>
          {selected.size === 2
            ? <button className="hy-compare-go" onClick={() => setCompareOpen(true)}>⟺ COMPARE NOW</button>
            : <span style={{ opacity:0.5 }}> · select one more</span>
          }
          <button className="hy-compare-clear" onClick={() => setSelected(new Set())}>✕ Clear</button>
        </div>
      )}

      {/* ── Loading / Error ── */}
      {loading && (
        <div className="hy-state-msg">
          <div className="hy-spinner"/>
          <span>FETCHING HISTORY...</span>
        </div>
      )}

      {error && !loading && (
        <div className="hy-error-msg">
          <span>⚠ {error}</span>
          <button className="hy-hdr-btn" onClick={fetchHistory}>RETRY</button>
        </div>
      )}

      {!loading && !error && history.length === 0 && (
        <div className="hy-empty">
          <div className="hy-empty-icon">◎</div>
          <div className="hy-empty-title">NO HISTORY YET</div>
          <div className="hy-empty-sub">Upload and analyze a log file to start building your history.</div>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════ */}
      {/* TABLE VIEW                                                           */}
      {/* ════════════════════════════════════════════════════════════════════ */}
      {!loading && !error && viewMode === "table" && filtered.length > 0 && (
        <div className="hy-table-wrap">
          <table className="hy-table">
            <thead>
              <tr>
                <th className="hy-th hy-th-check">
                  <span style={{ fontSize:10, color:"rgba(255,255,255,0.3)" }}>CMP</span>
                </th>
                <SortTh col="file_name"           label="FILE"        />
                <SortTh col="file_format"         label="FMT"         />
                <SortTh col="total_logs"          label="LOGS"        />
                <SortTh col="global_threat_score" label="SCORE"       />
                <SortTh col="threat_level"        label="LEVEL"       />
                <SortTh col="threat_percentage"   label="THREAT %"    />
                <SortTh col="execution_time"      label="EXEC TIME"   />
                <SortTh col="processors_used"     label="PROC"        />
                <SortTh col="timestamp"           label="TIMESTAMP"   />
                <th className="hy-th">TREND</th>
                <th className="hy-th">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {paginated.map((h, i) => {
                const sel  = isSelected(h);
                const c    = tc(h.threat_level);
                const procs = h.process_wise_scores || [];
                const scores = procs.map(p => p.score);
                return (
                  <tr key={i}
                    className={`hy-tr ${sel ? "hy-tr-selected" : ""}`}
                    style={ sel ? { background:`${c.bg}`, boxShadow:`inset 0 0 0 1px ${c.border}` } : {} }>
                    <td className="hy-td">
                      <button
                        className={`hy-cmp-check ${sel?"hy-cmp-checked":""}`}
                        style={ sel ? { borderColor:c.color, background:c.bg } : {} }
                        onClick={() => toggleSelect(h)}>
                        {sel ? "✓" : ""}
                      </button>
                    </td>
                    <td className="hy-td">
                      <div className="hy-filename" title={h.file_name}>
                        {h.file_name}
                      </div>
                    </td>
                    <td className="hy-td">
                      <span className="hy-fmt-badge">{FORMAT_ICON[h.file_format||"TXT"]} {h.file_format||"TXT"}</span>
                    </td>
                    <td className="hy-td hy-td-mono" style={{ color:"#00e5ff" }}>
                      {fmt(h.total_logs)}
                    </td>
                    <td className="hy-td">
                      <ScoreRing score={h.global_threat_score||0} level={h.threat_level} size={44}/>
                    </td>
                    <td className="hy-td">
                      <ThreatBadge level={h.threat_level}/>
                    </td>
                    <td className="hy-td">
                      <div className="hy-pct-cell">
                        <div className="hy-pct-bar">
                          <div className="hy-pct-fill"
                            style={{ width:pct(h.threat_percentage), background:c.color,
                              boxShadow:`0 0 6px ${c.color}55` }}/>
                        </div>
                        <span style={{ color:c.color, fontFamily:"'Orbitron',monospace", fontSize:11 }}>
                          {pct(h.threat_percentage)}
                        </span>
                      </div>
                    </td>
                    <td className="hy-td hy-td-mono" style={{ color:"#ffea00" }}>
                      {Number(h.execution_time||0).toFixed(3)}s
                    </td>
                    <td className="hy-td hy-td-mono" style={{ color:"#76ff03" }}>
                      {h.processors_used || procs.length || "—"}
                    </td>
                    <td className="hy-td hy-td-ts">{h.timestamp}</td>
                    <td className="hy-td">
                      <Spark data={scores} color={c.color}/>
                    </td>
                    <td className="hy-td">
                      <button className="hy-act-btn" onClick={() => setDetailEntry(h)}>
                        ⊕ Detail
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════ */}
      {/* TIMELINE VIEW                                                        */}
      {/* ════════════════════════════════════════════════════════════════════ */}
      {!loading && !error && viewMode === "timeline" && filtered.length > 0 && (
        <div className="hy-timeline">
          {paginated.map((h, i) => {
            const c = tc(h.threat_level);
            return (
              <div key={i} className="hy-tl-item" style={{ animationDelay:`${i*0.05}s` }}>
                <div className="hy-tl-dot" style={{ background:c.color, boxShadow:`0 0 8px ${c.color}` }}/>
                <div className="hy-tl-line"/>
                <div className="hy-tl-card" onClick={() => setDetailEntry(h)}>
                  <div className="hy-tl-card-header">
                    <span className="hy-tl-file">{h.file_name}</span>
                    <ThreatBadge level={h.threat_level}/>
                    <span className="hy-tl-ts">{h.timestamp}</span>
                  </div>
                  <div className="hy-tl-card-body">
                    <ScoreRing score={h.global_threat_score||0} level={h.threat_level} size={52}/>
                    <div className="hy-tl-stats">
                      <span><span style={{ color:"#00e5ff" }}>{fmt(h.total_logs)}</span> logs</span>
                      <span><span style={{ color:c.color }}>{pct(h.threat_percentage)}</span> threat</span>
                      <span><span style={{ color:"#76ff03" }}>{h.processors_used||"?"}</span> procs</span>
                      <span><span style={{ color:"#ffea00" }}>{Number(h.execution_time||0).toFixed(3)}s</span></span>
                    </div>
                    <div className="hy-tl-score-bar">
                      <div className="hy-tl-score-fill"
                        style={{
                          width:`${scoreBar(h.global_threat_score||0, thresholds)}%`,
                          background:`linear-gradient(90deg, ${c.color}66, ${c.color})`,
                        }}/>
                    </div>
                  </div>
                  <button className="hy-tl-cmp"
                    onClick={e => { e.stopPropagation(); toggleSelect(h); }}
                    style={ isSelected(h) ? { color:c.color, borderColor:c.color } : {} }>
                    {isSelected(h) ? "✓ SELECTED" : "+ COMPARE"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════ */}
      {/* GRID VIEW                                                            */}
      {/* ════════════════════════════════════════════════════════════════════ */}
      {!loading && !error && viewMode === "grid" && filtered.length > 0 && (
        <div className="hy-grid">
          {paginated.map((h, i) => {
            const c    = tc(h.threat_level);
            const sel  = isSelected(h);
            return (
              <div key={i}
                className={`hy-grid-card ${sel?"hy-grid-selected":""}`}
                style={{ borderColor:sel?c.color:undefined, animationDelay:`${i*0.05}s` }}
                onClick={() => setDetailEntry(h)}>
                <div className="hy-grid-card-top">
                  <div className="hy-gc-filename" title={h.file_name}>{h.file_name}</div>
                  <ThreatBadge level={h.threat_level}/>
                </div>
                <div className="hy-grid-card-mid">
                  <ScoreRing score={h.global_threat_score||0} level={h.threat_level} size={64}/>
                  <div className="hy-gc-stats">
                    <div className="hy-gc-stat">
                      <span style={{ color:"#00e5ff" }}>{fmt(h.total_logs)}</span>
                      <span className="hy-gc-stat-lbl">logs</span>
                    </div>
                    <div className="hy-gc-stat">
                      <span style={{ color:c.color }}>{pct(h.threat_percentage)}</span>
                      <span className="hy-gc-stat-lbl">threat</span>
                    </div>
                    <div className="hy-gc-stat">
                      <span style={{ color:"#76ff03" }}>{h.processors_used||"?"}</span>
                      <span className="hy-gc-stat-lbl">procs</span>
                    </div>
                  </div>
                </div>
                <div className="hy-gc-bar">
                  <div className="hy-gc-bar-fill"
                    style={{
                      width:`${scoreBar(h.global_threat_score||0, thresholds)}%`,
                      background:c.color, boxShadow:`0 0 6px ${c.color}55`,
                    }}/>
                </div>
                <div className="hy-gc-footer">
                  <span className="hy-gc-ts">{h.timestamp}</span>
                  <button className="hy-gc-cmp"
                    onClick={e => { e.stopPropagation(); toggleSelect(h); }}
                    style={ sel ? { color:c.color } : {} }>
                    {sel ? "✓" : "+"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Pagination ── */}
      {!loading && filtered.length > PAGE_SIZE && (
        <div className="hy-pagination">
          <button className="hy-pg-btn" disabled={page===1}
            onClick={() => setPage(1)}>«</button>
          <button className="hy-pg-btn" disabled={page===1}
            onClick={() => setPage(p=>p-1)}>‹</button>
          {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
            let p = i + 1;
            if (pages > 7) {
              if (page <= 4)       p = i + 1;
              else if (page >= pages - 3) p = pages - 6 + i;
              else p = page - 3 + i;
            }
            return (
              <button key={p} className={`hy-pg-btn ${page===p?"hy-pg-active":""}`}
                onClick={() => setPage(p)}>{p}</button>
            );
          })}
          <button className="hy-pg-btn" disabled={page===pages}
            onClick={() => setPage(p=>p+1)}>›</button>
          <button className="hy-pg-btn" disabled={page===pages}
            onClick={() => setPage(pages)}>»</button>
          <span className="hy-pg-info">
            {((page-1)*PAGE_SIZE)+1}–{Math.min(page*PAGE_SIZE, filtered.length)} of {filtered.length}
          </span>
        </div>
      )}

      {/* ── Detail Drawer ── */}
      {detailEntry && (
        <DetailDrawer entry={detailEntry} onClose={() => setDetailEntry(null)}
          thresholds={thresholds}/>
      )}

      {/* ── Comparison Modal ── */}
      {compareOpen && selectedEntries.length === 2 && (
        <CompareModal
          a={selectedEntries[0]} b={selectedEntries[1]}
          thresholds={thresholds}
          onClose={() => setCompareOpen(false)}/>
      )}
    </div>
  );
}