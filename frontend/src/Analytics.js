import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ScatterChart, Scatter, ZAxis, Legend, LineChart, Line,
} from "recharts";
import "./Analytics.css";
import { useApiConfig, useThresholds, useMpiConfig } from "./Settingscontext";

// ─── Constants ─────────────────────────────────────────────────────────────────
const LEVEL_COLOR = {
  SAFE:"#00e676", LOW:"#29b6f6", MEDIUM:"#ffa726", HIGH:"#ef5350", CRITICAL:"#ff1744"
};
const LEVEL_ORDER = ["SAFE","LOW","MEDIUM","HIGH","CRITICAL"];
const FORMAT_COLOR = { TXT:"#06b6d4", JSON:"#a855f7", CSV:"#10b981", LOG:"#f97316" };

// ─── Timestamp parser (handles both formats) ───────────────────────────────────
function parseTs(ts) {
  if (!ts) return new Date(0);
  const m = ts.match(/(\d{2})\/(\d{2})\/(\d{4}),?\s+(\d+):(\d+):(\d+)\s*(am|pm)?/i);
  if (m) {
    let h = parseInt(m[4]);
    if (m[7]?.toLowerCase() === "pm" && h < 12) h += 12;
    if (m[7]?.toLowerCase() === "am" && h === 12) h = 0;
    return new Date(+m[3], +m[2]-1, +m[1], h, +m[5], +m[6]);
  }
  return new Date(ts);
}

function normalizeEntry(raw) {
  return {
    file_name:           raw.file_name || "unknown",
    total_logs:          Number(raw.total_logs) || 0,
    global_threat_score: Number(raw.global_threat_score) || 0,
    threat_level:        raw.threat_level || "SAFE",
    threat_percentage:   Number(raw.threat_percentage) || 0,
    execution_time:      Number(raw.execution_time) || 0,
    process_wise_scores: Array.isArray(raw.process_wise_scores) ? raw.process_wise_scores : [],
    processors_used:     Number(raw.processors_used) || 0,
    file_format:         raw.file_format || "TXT",
    timestamp:           raw.timestamp || "",
    _date:               parseTs(raw.timestamp),
  };
}

const fmt  = (n) => Number(n||0).toLocaleString();
const fmtD = (n, d=1) => Number(n||0).toFixed(d);

// ─── Custom Tooltip ─────────────────────────────────────────────────────────────
const Tip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="an-tooltip">
      <div className="an-tt-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.stroke || "#fff" }}>
          {p.name}: <b>{typeof p.value === "number" ? p.value.toFixed(1) : p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Animated Counter ──────────────────────────────────────────────────────────
function AnimCounter({ target, duration = 1000, decimals = 0 }) {
  const [val, setVal] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const from = prev.current;
    prev.current = target;
    const start = Date.now();
    const tick = () => {
      const p = Math.min((Date.now()-start)/duration, 1);
      const ease = 1 - Math.pow(1-p, 3);
      const cur = from + (target-from) * ease;
      setVal(cur);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);
  return <>{decimals > 0 ? val.toFixed(decimals) : Math.round(val).toLocaleString()}</>;
}

// ─── Score Ring ──────────────────────────────────────────────────────────────
function ScoreRing({ score, maxScore = 200, color = "#f97316" }) {
  const R = 80; const circ = 2*Math.PI*R;
  const pct = Math.min(score/maxScore, 1);
  const dash = pct * circ;
  return (
    <div className="an-score-ring">
      <svg width="200" height="200" viewBox="0 0 200 200">
        <defs>
          <linearGradient id="sgA" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#ef4444"/>
            <stop offset="100%" stopColor="#f97316"/>
          </linearGradient>
          <filter id="sglow">
            <feGaussianBlur stdDeviation="4" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        {[...Array(36)].map((_,i) => {
          const a = (i/36)*Math.PI*2 - Math.PI/2;
          const x1=100+90*Math.cos(a), y1=100+90*Math.sin(a);
          const x2=100+82*Math.cos(a), y2=100+82*Math.sin(a);
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
            stroke={i/36 < pct ? "url(#sgA)" : "rgba(255,255,255,0.07)"}
            strokeWidth="3" strokeLinecap="round"
            style={i/36 < pct ? {filter:"drop-shadow(0 0 3px #f97316)"} : {}}/>;
        })}
        <circle cx="100" cy="100" r="68" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="1"/>
      </svg>
      <div className="an-score-center">
        <div className="an-score-label">AVG SCORE</div>
        <div className="an-score-val" style={{ color }}>
          <AnimCounter target={Math.round(score)}/>
        </div>
        <div className="an-score-sub">
          {score === 0 ? "NO DATA" : score < 25 ? "POSTURE: GOOD" : score < 100 ? "POSTURE: MODERATE" : "POSTURE: CRITICAL"}
        </div>
      </div>
    </div>
  );
}

// ─── Risk Badge ──────────────────────────────────────────────────────────────
const RiskBadge = ({ level }) => (
  <span className="an-badge" style={{
    background: `${LEVEL_COLOR[level]||"#666"}22`,
    color: LEVEL_COLOR[level]||"#666",
    border: `1px solid ${LEVEL_COLOR[level]||"#666"}44`,
  }}>{level}</span>
);

// ─── Sparkline ────────────────────────────────────────────────────────────────
const Spark = ({ data, color }) => {
  if (!data?.length) return null;
  const max = Math.max(...data, 1);
  const pts = data.map((v,i) => {
    const x = (i/(data.length-1))*60;
    const y = 18-(v/max)*16;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width="64" height="20" viewBox="0 0 64 20">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round"
        style={{ filter:`drop-shadow(0 0 3px ${color})` }}/>
    </svg>
  );
};

// ─── Export helpers ───────────────────────────────────────────────────────────
function exportCSV(data) {
  const headers = ["file_name","total_logs","global_threat_score","threat_level",
    "threat_percentage","execution_time","processors_used","file_format","timestamp"];
  const rows = data.map(h => headers.map(k => JSON.stringify(h[k]??"")));
  const csv = [headers, ...rows].map(r => r.join(",")).join("\n");
  const blob = new Blob([csv], { type:"text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href=url;
  a.download = `analytics_${Date.now()}.csv`; a.click();
  URL.revokeObjectURL(url);
}

function exportJSON(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type:"application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href=url;
  a.download = `analytics_${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
}

// ═══ MAIN ══════════════════════════════════════════════════════════════════════
export default function Analytics() {
  const { backendUrl } = useApiConfig();
  const thresholds     = useThresholds();
  const { processors } = useMpiConfig();

  // ── State ──────────────────────────────────────────────────────────────────
  const [history,    setHistory]    = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [activeTab,  setActiveTab]  = useState("overview");
  const [timeRange,  setTimeRange]  = useState("30d");
  const [levelFilter,setLevelFilter]= useState("All");
  const [fmtFilter,  setFmtFilter]  = useState("All");
  const [sortCol,    setSortCol]    = useState("timestamp");
  const [sortDir,    setSortDir]    = useState("desc");
  const [drillSearch,setDrillSearch]= useState("");
  const [selFile,    setSelFile]    = useState(null);    // for file detail panel
  const [lastRefresh,setLastRefresh]= useState(null);
  const [autoRefresh,setAutoRefresh]= useState(false);
  const timerRef = useRef(null);

  // ── Fetch ──────────────────────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/history`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const raw = await res.json();
      setHistory((Array.isArray(raw) ? raw : []).map(normalizeEntry)
        .sort((a,b) => b._date - a._date));
      setLastRefresh(new Date());
      setError(null);
    } catch(e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [backendUrl]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  useEffect(() => {
    clearInterval(timerRef.current);
    if (autoRefresh) timerRef.current = setInterval(fetchHistory, 20000);
    return () => clearInterval(timerRef.current);
  }, [autoRefresh, fetchHistory]);

  // ── Watched Folder state ────────────────────────────────────────────────────
  const [folderData,    setFolderData]    = useState(null);
  const [folderLoading, setFolderLoading] = useState(false);
  const [analyzing,     setAnalyzing]     = useState({}); // { filename: "running"|"done"|"error" }
  const [analyzeResults,setAnalyzeResults]= useState({});// { filename: result }

  const fetchFolder = useCallback(async () => {
    setFolderLoading(true);
    try {
      const res = await fetch(`${backendUrl}/watched-folder`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFolderData(await res.json());
    } catch(e) {
      console.warn("[folder] fetch failed:", e.message);
      setFolderData({ error: e.message, files:[], total:0, pending:0 });
    } finally {
      setFolderLoading(false);
    }
  }, [backendUrl]);

  useEffect(() => { fetchFolder(); }, [fetchFolder]);

  const analyzeFile = useCallback(async (filename) => {
    setAnalyzing(prev => ({ ...prev, [filename]: "running" }));
    try {
      const fd = new FormData();
      fd.append("filename",   filename);
      fd.append("processors", String(processors || 4));
      const res = await fetch(`${backendUrl}/analyze-from-folder`, { method:"POST", body:fd });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      if (result.error) throw new Error(result.error);
      setAnalyzing(prev      => ({ ...prev, [filename]: "done"  }));
      setAnalyzeResults(prev => ({ ...prev, [filename]: result  }));
      // Refresh both history and folder list
      await Promise.all([fetchHistory(), fetchFolder()]);
    } catch(e) {
      setAnalyzing(prev => ({ ...prev, [filename]: "error:"+e.message }));
    }
  }, [backendUrl, processors, fetchHistory, fetchFolder]);

  const analyzeAll = useCallback(async () => {
    if (!folderData?.files) return;
    const pending = folderData.files.filter(f => !f.analysed);
    for (const f of pending) {
      await analyzeFile(f.name);
    }
  }, [folderData, analyzeFile]);

  // ── Time filter ────────────────────────────────────────────────────────────
  const cutoffDate = useMemo(() => {
    const now = new Date();
    const d = {
      "24h":  new Date(now - 24*3600*1000),
      "7d":   new Date(now - 7*24*3600*1000),
      "30d":  new Date(now - 30*24*3600*1000),
      "90d":  new Date(now - 90*24*3600*1000),
      "all":  new Date(0),
    };
    return d[timeRange] || d["30d"];
  }, [timeRange]);

  const filtered = useMemo(() =>
    history.filter(h => h._date >= cutoffDate), [history, cutoffDate]);

  // ── Derived KPIs ──────────────────────────────────────────────────────────
  const kpi = useMemo(() => {
    if (!filtered.length) return {
      count:0, avgScore:0, totalLogs:0, criticals:0, avgExec:0,
      avgThreatPct:0, maxScore:0, minScore:0, avgThroughput:0,
    };
    const scores = filtered.map(h => h.global_threat_score);
    const execs  = filtered.map(h => h.execution_time).filter(v=>v>0);
    const thrpts = filtered.map(h => h.execution_time > 0 ? h.total_logs/h.execution_time : 0).filter(v=>v>0);
    return {
      count:        filtered.length,
      avgScore:     scores.reduce((s,v)=>s+v,0) / scores.length,
      totalLogs:    filtered.reduce((s,h)=>s+h.total_logs,0),
      criticals:    filtered.filter(h=>h.threat_level==="CRITICAL").length,
      avgExec:      execs.length ? execs.reduce((s,v)=>s+v,0)/execs.length : 0,
      avgThreatPct: filtered.reduce((s,h)=>s+h.threat_percentage,0)/filtered.length,
      maxScore:     Math.max(...scores,0),
      minScore:     Math.min(...scores,Infinity)===Infinity?0:Math.min(...scores),
      avgThroughput:thrpts.length ? thrpts.reduce((s,v)=>s+v,0)/thrpts.length : 0,
    };
  }, [filtered]);

  // ── Threat level distribution ──────────────────────────────────────────────
  const levelDist = useMemo(() => {
    const counts = {};
    filtered.forEach(h => counts[h.threat_level] = (counts[h.threat_level]||0)+1);
    return LEVEL_ORDER.filter(l=>counts[l]).map(l => ({
      name:l, value:counts[l], color:LEVEL_COLOR[l]
    }));
  }, [filtered]);

  // ── Timeline: group by day ─────────────────────────────────────────────────
  const timeline = useMemo(() => {
    if (!filtered.length) return [];
    const days = {};
    filtered.forEach(h => {
      const key = h._date.toLocaleDateString("en-GB", {month:"short",day:"numeric"});
      if (!days[key]) days[key] = { label:key, count:0, score:0, logs:0, criticals:0, date:h._date };
      days[key].count++;
      days[key].score  = Math.max(days[key].score, h.global_threat_score);
      days[key].logs  += h.total_logs;
      days[key].criticals += h.threat_level==="CRITICAL"?1:0;
    });
    return Object.values(days).sort((a,b)=>a.date-b.date).slice(-30);
  }, [filtered]);

  // ── Score trend ───────────────────────────────────────────────────────────
  const scoreTrend = useMemo(() =>
    [...filtered].reverse().slice(-20).map((h,i) => ({
      i: i+1, score: h.global_threat_score, pct: h.threat_percentage,
      throughput: h.execution_time>0 ? Math.round(h.total_logs/h.execution_time) : 0,
      label: h.file_name.slice(0,12),
      color: LEVEL_COLOR[h.threat_level],
    })),
  [filtered]);

  // ── Format distribution ────────────────────────────────────────────────────
  const formatDist = useMemo(() => {
    const counts = {};
    filtered.forEach(h => counts[h.file_format||"TXT"] = (counts[h.file_format||"TXT"]||0)+1);
    return Object.entries(counts).map(([name,value]) => ({
      name, value, color: FORMAT_COLOR[name]||"#666"
    }));
  }, [filtered]);

  // ── Processor distribution ─────────────────────────────────────────────────
  const procDist = useMemo(() => {
    const counts = {};
    filtered.forEach(h => {
      const n = h.processors_used||"?";
      counts[n] = (counts[n]||0)+1;
    });
    return Object.entries(counts).map(([procs,count]) => ({
      name: `${procs} procs`, value:count, procs:Number(procs)
    })).sort((a,b)=>a.procs-b.procs);
  }, [filtered]);

  // ── Node aggregate scores ─────────────────────────────────────────────────
  const nodeScores = useMemo(() => {
    const totals = {}, counts = {};
    filtered.forEach(h => {
      (h.process_wise_scores||[]).forEach(p => {
        totals[p.process_id] = (totals[p.process_id]||0) + p.score;
        counts[p.process_id] = (counts[p.process_id]||0) + 1;
      });
    });
    const colors = ["#06b6d4","#a855f7","#f97316","#10b981","#f59e0b","#ef4444","#00e5ff","#76ff03"];
    return Object.entries(totals).map(([id,total]) => ({
      name: `Node ${id}`, total, avg: total/counts[id],
      count: counts[id], color: colors[id%colors.length],
    })).sort((a,b)=>Number(a.name.split(" ")[1])-Number(b.name.split(" ")[1]));
  }, [filtered]);

  // ── Heatmap (day × hour from real timestamps) ──────────────────────────────
  const heatmap = useMemo(() => {
    const DAYS  = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    const HOURS = Array.from({length:24},(_,i)=>String(i).padStart(2,"0"));
    const grid  = DAYS.map(() => HOURS.map(()=>0));
    filtered.forEach(h => {
      const d = h._date.getDay();
      const hr = h._date.getHours();
      grid[d][hr] += h.global_threat_score;
    });
    return { grid, DAYS, HOURS };
  }, [filtered]);

  // ── Execution time scatter ─────────────────────────────────────────────────
  const scatterData = useMemo(() =>
    filtered.filter(h=>h.execution_time>0&&h.total_logs>0).map(h => ({
      x: h.total_logs,
      y: h.execution_time,
      z: h.global_threat_score,
      name: h.file_name,
      level: h.threat_level,
      throughput: Math.round(h.total_logs/h.execution_time),
    })),
  [filtered]);

  // ── Drill-down table ───────────────────────────────────────────────────────
  const drillFiltered = useMemo(() => {
    let data = [...filtered];
    if (levelFilter !== "All") data = data.filter(h=>h.threat_level===levelFilter);
    if (fmtFilter   !== "All") data = data.filter(h=>(h.file_format||"TXT")===fmtFilter);
    if (drillSearch.trim()) {
      const q = drillSearch.toLowerCase();
      data = data.filter(h =>
        h.file_name.toLowerCase().includes(q) ||
        h.threat_level.toLowerCase().includes(q) ||
        String(h.global_threat_score).includes(q)
      );
    }
    return [...data].sort((a,b) => {
      const av = a[sortCol]??"", bv = b[sortCol]??"";
      const cmp = String(av).localeCompare(String(bv), undefined, {numeric:true});
      return sortDir==="asc" ? cmp : -cmp;
    });
  }, [filtered, levelFilter, fmtFilter, drillSearch, sortCol, sortDir]);

  const toggleSort = (col) => {
    if (sortCol===col) setSortDir(d=>d==="asc"?"desc":"asc");
    else { setSortCol(col); setSortDir("desc"); }
  };

  const SortTh = ({ col, label }) => (
    <th className={`sortable ${sortCol===col?"sorted":""}`} onClick={()=>toggleSort(col)}>
      {label} <span className="sort-arrow">{sortCol===col?(sortDir==="asc"?"↑":"↓"):"⇅"}</span>
    </th>
  );

  // ── Heatmap color ──────────────────────────────────────────────────────────
  const hmColor = (v) => {
    if (v===0) return "rgba(255,255,255,0.03)";
    if (v<50)  return "rgba(16,185,129,0.25)";
    if (v<150) return "rgba(245,158,11,0.4)";
    if (v<300) return "rgba(249,115,22,0.55)";
    return "rgba(239,68,68,0.8)";
  };

  // ─────────────────────────────────────────────────────────────────────────────
  return (
    <div className="an-page">

      {/* ── Header ── */}
      <div className="an-header">
        <div>
          <div className="an-page-title">Analytics</div>
          <div className="an-page-sub">
            Advanced threat intelligence · {fmt(kpi.count)} analyses
            {lastRefresh && (
              <span style={{color:"rgba(255,255,255,0.2)",marginLeft:8}}>
                · {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
        <div className="an-header-controls">
          {["24h","7d","30d","90d","all"].map(t => (
            <button key={t} className={`an-time-btn ${timeRange===t?"active":""}`}
              onClick={()=>setTimeRange(t)}>{t}</button>
          ))}
          <button className={`an-time-btn ${autoRefresh?"active":""}`}
            onClick={()=>setAutoRefresh(v=>!v)}
            style={autoRefresh?{color:"#10b981",borderColor:"rgba(16,185,129,0.4)"}:{}}>
            ↻ AUTO
          </button>
          <button className="an-time-btn" onClick={fetchHistory}>⟳</button>
          <button className="an-export-btn" onClick={()=>exportCSV(filtered)}>⬇ CSV</button>
          <button className="an-export-btn" onClick={()=>exportJSON(filtered)}
            style={{borderColor:"rgba(168,85,247,0.4)",color:"#a855f7",background:"rgba(168,85,247,0.1)"}}>
            ⬇ JSON
          </button>
        </div>
      </div>

      {/* ── Loading / Error ── */}
      {loading && (
        <div style={{display:"flex",alignItems:"center",gap:12,padding:"40px 0",
          fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.3)",letterSpacing:3}}>
          <div style={{width:20,height:20,borderRadius:"50%",border:"2px solid rgba(6,182,212,0.3)",
            borderTop:"2px solid #06b6d4",animation:"spin 0.8s linear infinite"}}/>
          LOADING ANALYTICS...
        </div>
      )}
      {error && !loading && (
        <div className="an-card" style={{borderColor:"rgba(239,68,68,0.3)",background:"rgba(239,68,68,0.05)"}}>
          <span style={{color:"#ef4444",fontFamily:"'Share Tech Mono',monospace",fontSize:12}}>
            ⚠ {error} — make sure uvicorn is running at {backendUrl}
          </span>
        </div>
      )}
      {!loading && !error && history.length === 0 && (
        <div className="an-card" style={{textAlign:"center",padding:"60px 20px"}}>
          <div style={{fontSize:40,marginBottom:12}}>◎</div>
          <div style={{fontFamily:"'Orbitron',monospace",fontSize:14,letterSpacing:4,color:"rgba(255,255,255,0.2)"}}>
            NO ANALYSIS DATA YET
          </div>
          <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:14,color:"rgba(255,255,255,0.25)",marginTop:8}}>
            Upload log files to populate this dashboard.
          </div>
        </div>
      )}

      {!loading && filtered.length > 0 && (<>

      {/* ── KPI Strip ── */}
      <div className="an-kpi-strip">
        {[
          { label:"Total Analyses",   val:kpi.count,           color:"#06b6d4", icon:"⊞", decimals:0 },
          { label:"Avg Threat Score", val:kpi.avgScore,        color:"#f97316", icon:"⚡",decimals:1 },
          { label:"Total Logs",       val:kpi.totalLogs,       color:"#10b981", icon:"📄",decimals:0 },
          { label:"Critical Files",   val:kpi.criticals,       color:"#ef4444", icon:"🚨",decimals:0 },
          { label:"Avg Exec (s)",     val:kpi.avgExec,         color:"#ffea00", icon:"⏱", decimals:3 },
          { label:"Avg Threat Rate",  val:kpi.avgThreatPct,    color:"#a855f7", icon:"◉", decimals:1 },
          { label:"Avg Throughput",   val:kpi.avgThroughput,   color:"#00e5ff", icon:"⬡", decimals:0 },
        ].map((k,i) => (
          <div key={i} className="an-kpi-card" style={{ animationDelay:`${i*0.06}s` }}>
            <div className="an-kpi-top">
              <span className="an-kpi-icon" style={{ color:k.color }}>{k.icon}</span>
              <span style={{ fontSize:9, fontFamily:"'Rajdhani',sans-serif",
                color:"rgba(255,255,255,0.25)", letterSpacing:1 }}>
                {timeRange.toUpperCase()}
              </span>
            </div>
            <div className="an-kpi-val" style={{ color:k.color }}>
              <AnimCounter target={k.val} decimals={k.decimals}/>
              {k.label==="Avg Threat Rate"||k.label==="Avg Exec (s)" ? "" : ""}
              {k.label==="Avg Throughput" ? <span style={{fontSize:12,opacity:0.6}}> /s</span> : null}
            </div>
            <div className="an-kpi-label">{k.label}</div>
            <Spark
              data={scoreTrend.slice(-6).map(d =>
                k.label==="Avg Threat Score" ? d.score :
                k.label==="Avg Throughput"   ? d.throughput :
                k.label==="Avg Threat Rate"  ? d.pct : d.score
              )}
              color={k.color}
            />
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div className="an-tabs">
        {[
          {id:"overview",  label:"Overview"},
          {id:"timeline",  label:"Timeline"},
          {id:"nodes",     label:"Node Analysis"},
          {id:"heatmap",   label:"Heatmap"},
          {id:"scatter",   label:"Correlation"},
          {id:"drill",     label:"Drill-Down"},
          {id:"folder",    label:`📂 Log Queue${folderData?.pending ? ` (${folderData.pending})` : ""}`},
        ].map(t => (
          <button key={t.id} className={`an-tab ${activeTab===t.id?"an-tab-active":""}`}
            onClick={()=>setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══ OVERVIEW ══════════════════════════════════════════════════════════ */}
      {activeTab === "overview" && (
        <>
          <div className="an-row">
            {/* Score Ring */}
            <div className="an-card" style={{flex:"0 0 380px"}}>
              <div className="an-card-header">
                <div className="an-card-title">AVERAGE THREAT SCORE</div>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"rgba(255,255,255,0.25)"}}>
                  {fmt(kpi.count)} analyses · range {kpi.minScore}–{kpi.maxScore}
                </span>
              </div>
              <div className="an-score-wrap">
                <ScoreRing score={kpi.avgScore} maxScore={Math.max(kpi.maxScore,100)}/>
                <div className="an-score-breakdown">
                  {LEVEL_ORDER.filter(l=>levelDist.find(d=>d.name===l)).map((l,i) => {
                    const d = levelDist.find(x=>x.name===l);
                    return (
                      <div key={i} className="an-score-row">
                        <div className="an-score-icon" style={{color:d.color}}>◉</div>
                        <div className="an-score-info">
                          <div className="an-score-name">{l}</div>
                          <div className="an-score-bar-wrap">
                            <div className="an-score-bar-track">
                              <div className="an-score-bar-fill"
                                style={{width:`${(d.value/kpi.count)*100}%`,
                                  background:d.color, boxShadow:`0 0 6px ${d.color}`}}/>
                            </div>
                            <span className="an-score-num" style={{color:d.color}}>{d.value}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Level distribution */}
            <div className="an-card" style={{flex:1}}>
              <div className="an-card-header">
                <div className="an-card-title">THREAT LEVEL DISTRIBUTION</div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:20}}>
                <ResponsiveContainer width="45%" height={220}>
                  <PieChart>
                    <Pie data={levelDist} cx="50%" cy="50%"
                      innerRadius={55} outerRadius={90}
                      dataKey="value" paddingAngle={2}
                      startAngle={90} endAngle={-270}>
                      {levelDist.map((d,i) => (
                        <Cell key={i} fill={d.color}
                          style={{filter:`drop-shadow(0 0 6px ${d.color}66)`}}/>
                      ))}
                    </Pie>
                    <Tooltip content={<Tip/>}/>
                  </PieChart>
                </ResponsiveContainer>
                <div style={{flex:1,display:"flex",flexDirection:"column",gap:10}}>
                  {levelDist.map((d,i) => (
                    <div key={i} style={{display:"flex",alignItems:"center",gap:10}}>
                      <div style={{width:10,height:10,borderRadius:2,background:d.color,flexShrink:0}}/>
                      <span style={{fontFamily:"'Rajdhani',sans-serif",fontSize:13,
                        color:"rgba(255,255,255,0.6)",flex:1,fontWeight:600}}>{d.name}</span>
                      <div style={{flex:2,height:6,background:"rgba(255,255,255,0.05)",borderRadius:3,overflow:"hidden"}}>
                        <div style={{width:`${(d.value/kpi.count)*100}%`,height:"100%",
                          background:d.color,borderRadius:3,boxShadow:`0 0 6px ${d.color}55`}}/>
                      </div>
                      <span style={{fontFamily:"'Orbitron',monospace",fontSize:12,
                        color:d.color,fontWeight:700,width:28,textAlign:"right"}}>{d.value}</span>
                      <span style={{fontSize:10,color:"rgba(255,255,255,0.3)",width:36,textAlign:"right"}}>
                        {((d.value/kpi.count)*100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Format & Processor breakdown */}
            <div className="an-card" style={{flex:"0 0 260px"}}>
              <div className="an-card-header">
                <div className="an-card-title">FILE FORMAT MIX</div>
              </div>
              {formatDist.map((f,i) => (
                <div key={i} style={{display:"flex",alignItems:"center",gap:10,marginBottom:10}}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                    color:f.color,width:36}}>{f.name}</span>
                  <div style={{flex:1,height:8,background:"rgba(255,255,255,0.05)",borderRadius:4,overflow:"hidden"}}>
                    <div style={{width:`${(f.value/kpi.count)*100}%`,height:"100%",
                      background:f.color,boxShadow:`0 0 6px ${f.color}55`,borderRadius:4}}/>
                  </div>
                  <span style={{fontFamily:"'Orbitron',monospace",fontSize:12,
                    color:f.color,fontWeight:700,width:24,textAlign:"right"}}>{f.value}</span>
                </div>
              ))}
              <div className="an-card-title" style={{marginTop:20,marginBottom:12}}>PROCESSOR USAGE</div>
              {procDist.map((p,i) => (
                <div key={i} style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                    color:"rgba(255,255,255,0.4)",width:48}}>{p.name}</span>
                  <div style={{flex:1,height:6,background:"rgba(255,255,255,0.05)",borderRadius:3,overflow:"hidden"}}>
                    <div style={{width:`${(p.value/kpi.count)*100}%`,height:"100%",
                      background:"#06b6d4",borderRadius:3}}/>
                  </div>
                  <span style={{fontSize:11,color:"#06b6d4",fontFamily:"'Orbitron',monospace",
                    fontWeight:700,width:20,textAlign:"right"}}>{p.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Score trend */}
          <div className="an-card">
            <div className="an-card-header">
              <div className="an-card-title">THREAT SCORE HISTORY (LAST 20 ANALYSES)</div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={scoreTrend} margin={{top:8,right:20,left:-20,bottom:0}}>
                <defs>
                  <linearGradient id="stG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#f97316" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="ptG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="i" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis yAxisId="s" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis yAxisId="p" orientation="right" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<Tip/>}/>
                <Legend wrapperStyle={{fontSize:10,color:"rgba(255,255,255,0.4)"}}/>
                <Area yAxisId="s" type="monotone" dataKey="score" stroke="#f97316" strokeWidth={2}
                  fill="url(#stG)" dot={false} name="Threat Score"/>
                <Area yAxisId="p" type="monotone" dataKey="pct" stroke="#06b6d4" strokeWidth={1.5}
                  fill="url(#ptG)" dot={false} name="Threat %"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </>
      )}

      {/* ══ TIMELINE ═════════════════════════════════════════════════════════ */}
      {activeTab === "timeline" && (
        <>
          <div className="an-card">
            <div className="an-card-header">
              <div className="an-card-title">ANALYSES PER DAY — MAX THREAT SCORE</div>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timeline} barCategoryGap="20%" margin={{top:8,right:20,left:-15,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis yAxisId="c" tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis yAxisId="s" orientation="right" tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<Tip/>}/>
                <Legend wrapperStyle={{fontSize:10,color:"rgba(255,255,255,0.4)"}}/>
                <Bar yAxisId="c" dataKey="count" fill="#06b6d4" radius={[3,3,0,0]} name="Analyses"
                  style={{filter:"drop-shadow(0 0 4px #06b6d488)"}}/>
                <Line yAxisId="s" type="monotone" dataKey="score" stroke="#f97316"
                  strokeWidth={2} dot={{r:3,fill:"#f97316"}} name="Max Score"/>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="an-row">
            <div className="an-card" style={{flex:1}}>
              <div className="an-card-header">
                <div className="an-card-title">LOGS PROCESSED PER DAY</div>
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={timeline} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <defs>
                    <linearGradient id="lgG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#10b981" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<Tip/>}/>
                  <Area type="monotone" dataKey="logs" stroke="#10b981" strokeWidth={2}
                    fill="url(#lgG)" dot={false} name="Logs"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="an-card" style={{flex:1}}>
              <div className="an-card-header">
                <div className="an-card-title">CRITICAL THREATS PER DAY</div>
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={timeline} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<Tip/>}/>
                  <Bar dataKey="criticals" fill="#ef4444" radius={[3,3,0,0]} name="Criticals"
                    style={{filter:"drop-shadow(0 0 4px #ef444466)"}}/>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </>
      )}

      {/* ══ NODE ANALYSIS ═══════════════════════════════════════════════════ */}
      {activeTab === "nodes" && (
        <>
          {nodeScores.length > 0 ? (<>
            <div className="an-card">
              <div className="an-card-header">
                <div className="an-card-title">CUMULATIVE NODE THREAT SCORES (ALL HISTORY)</div>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"rgba(255,255,255,0.25)"}}>
                  total accumulated across {kpi.count} analyses
                </span>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={nodeScores} barCategoryGap="20%" margin={{top:8,right:20,left:-15,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="name" tick={{fill:"rgba(255,255,255,0.35)",fontSize:11}} axisLine={false} tickLine={false}/>
                  <YAxis yAxisId="t" tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}/>
                  <YAxis yAxisId="a" orientation="right" tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<Tip/>}/>
                  <Legend wrapperStyle={{fontSize:10,color:"rgba(255,255,255,0.4)"}}/>
                  <Bar yAxisId="t" dataKey="total" name="Total Score" radius={[4,4,0,0]}>
                    {nodeScores.map((d,i) => (
                      <Cell key={i} fill={d.color} style={{filter:`drop-shadow(0 0 6px ${d.color}66)`}}/>
                    ))}
                  </Bar>
                  <Bar yAxisId="a" dataKey="avg" name="Avg Per Run" radius={[3,3,0,0]}
                    fill="rgba(255,255,255,0.15)"/>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="an-row">
              {nodeScores.map((n,i) => (
                <div key={i} className="an-card" style={{flex:1}}>
                  <div className="an-card-header" style={{marginBottom:10}}>
                    <div className="an-card-title">{n.name.toUpperCase()}</div>
                    <span className="an-chip" style={{borderColor:`${n.color}44`,color:n.color,
                      background:`${n.color}11`}}>
                      {n.count} runs
                    </span>
                  </div>
                  <div style={{fontFamily:"'Orbitron',monospace",fontSize:28,fontWeight:900,color:n.color,
                    textShadow:`0 0 16px ${n.color}66`}}>
                    <AnimCounter target={n.total}/>
                  </div>
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:11,color:"rgba(255,255,255,0.3)",
                    letterSpacing:2,marginTop:4}}>TOTAL SCORE</div>
                  <div style={{fontFamily:"'Orbitron',monospace",fontSize:14,color:n.color,
                    marginTop:8,opacity:0.7}}>
                    avg {fmtD(n.avg,1)}
                  </div>
                  <div style={{marginTop:10,height:6,background:"rgba(255,255,255,0.07)",borderRadius:3,overflow:"hidden"}}>
                    <div style={{width:`${Math.min((n.total/Math.max(...nodeScores.map(x=>x.total),1))*100,100)}%`,
                      height:"100%",background:n.color,boxShadow:`0 0 8px ${n.color}66`,borderRadius:3}}/>
                  </div>
                </div>
              ))}
            </div>
          </>) : (
            <div className="an-card" style={{textAlign:"center",padding:"40px"}}>
              <div style={{color:"rgba(255,255,255,0.2)",fontFamily:"'Orbitron',monospace",fontSize:12,letterSpacing:3}}>
                NO NODE DATA — analyses have no per-process scores
              </div>
            </div>
          )}
        </>
      )}

      {/* ══ HEATMAP ══════════════════════════════════════════════════════════ */}
      {activeTab === "heatmap" && (
        <div className="an-card">
          <div className="an-card-header">
            <div className="an-card-title">THREAT SCORE HEATMAP — DAY × HOUR</div>
            <div className="an-heatmap-legend">
              {["None","Low","Medium","High","Critical"].map((l,i)=>{
                const c=["rgba(255,255,255,0.03)","rgba(16,185,129,0.25)","rgba(245,158,11,0.4)","rgba(249,115,22,0.55)","rgba(239,68,68,0.8)"];
                return (
                  <div key={i} className="an-hm-leg-item">
                    <div className="an-hm-leg-swatch" style={{background:c[i]}}/>
                    <span>{l}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{overflowX:"auto"}}>
            <div style={{minWidth:600}}>
              {/* Hour labels */}
              <div style={{display:"flex",marginLeft:40,marginBottom:4}}>
                {heatmap.HOURS.filter((_,i)=>i%3===0).map(h=>(
                  <div key={h} style={{flex:3,fontFamily:"'Share Tech Mono',monospace",
                    fontSize:9,color:"rgba(255,255,255,0.3)",textAlign:"center"}}>{h}:00</div>
                ))}
              </div>
              {heatmap.DAYS.map((day,di) => (
                <div key={di} style={{display:"flex",alignItems:"center",marginBottom:4}}>
                  <div style={{width:36,fontFamily:"'Rajdhani',sans-serif",fontSize:12,
                    color:"rgba(255,255,255,0.45)",fontWeight:600}}>{day}</div>
                  <div style={{flex:1,display:"grid",gridTemplateColumns:"repeat(24,1fr)",gap:2}}>
                    {heatmap.grid[di].map((val,hi) => (
                      <div key={hi}
                        title={`${day} ${heatmap.HOURS[hi]}:00 — score ${val}`}
                        style={{height:28,borderRadius:3,background:hmColor(val),
                          cursor:"default",transition:"transform 0.15s ease"}}
                        onMouseEnter={e=>e.target.style.transform="scale(1.2)"}
                        onMouseLeave={e=>e.target.style.transform=""}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="an-heatmap-insight">
            <span className="insight-icon">💡</span>
            Showing accumulated threat scores from {fmt(kpi.count)} real analyses.
            Darker cells = higher threat activity at that day/hour combination.
          </div>
        </div>
      )}

      {/* ══ SCATTER ══════════════════════════════════════════════════════════ */}
      {activeTab === "scatter" && (
        <div className="an-card">
          <div className="an-card-header">
            <div className="an-card-title">LOGS vs EXECUTION TIME — BUBBLE SIZE = THREAT SCORE</div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"rgba(255,255,255,0.3)"}}>
              {scatterData.length} data points · hover for details
            </div>
          </div>
          {scatterData.length > 1 ? (
            <ResponsiveContainer width="100%" height={340}>
              <ScatterChart margin={{top:20,right:30,left:-10,bottom:20}}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)"/>
                <XAxis dataKey="x" name="Total Logs" type="number"
                  tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}
                  label={{value:"Total Logs Analyzed",position:"bottom",fill:"rgba(255,255,255,0.3)",fontSize:11}}/>
                <YAxis dataKey="y" name="Execution Time (s)" type="number"
                  tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}
                  label={{value:"Exec Time (s)",angle:-90,position:"insideLeft",fill:"rgba(255,255,255,0.3)",fontSize:11}}/>
                <ZAxis dataKey="z" range={[40,400]} name="Threat Score"/>
                <Tooltip cursor={{stroke:"rgba(255,255,255,0.1)"}}
                  content={({active,payload})=>{
                    if (!active||!payload?.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="an-tooltip">
                        <div style={{color:"rgba(255,255,255,0.5)",fontSize:10,marginBottom:4}}>{d.name}</div>
                        <div>Logs: <b style={{color:"#06b6d4"}}>{fmt(d.x)}</b></div>
                        <div>Exec: <b style={{color:"#ffea00"}}>{fmtD(d.y,3)}s</b></div>
                        <div>Score: <b style={{color:LEVEL_COLOR[d.level]}}>{d.z}</b></div>
                        <div>Throughput: <b style={{color:"#10b981"}}>{fmt(d.throughput)}/s</b></div>
                      </div>
                    );
                  }}/>
                <Scatter data={scatterData} name="Analyses">
                  {scatterData.map((d,i) => (
                    <Cell key={i} fill={LEVEL_COLOR[d.level]}
                      style={{filter:`drop-shadow(0 0 4px ${LEVEL_COLOR[d.level]}88)`,opacity:0.8}}/>
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          ) : (
            <div style={{textAlign:"center",padding:"40px",color:"rgba(255,255,255,0.2)",
              fontFamily:"'Share Tech Mono',monospace",fontSize:12,letterSpacing:2}}>
              NEED ≥2 ANALYSES WITH EXECUTION TIME DATA
            </div>
          )}
          <div style={{display:"flex",gap:12,marginTop:12,flexWrap:"wrap"}}>
            {LEVEL_ORDER.map(l => (
              <div key={l} style={{display:"flex",alignItems:"center",gap:6}}>
                <div style={{width:10,height:10,borderRadius:"50%",background:LEVEL_COLOR[l],
                  boxShadow:`0 0 6px ${LEVEL_COLOR[l]}`}}/>
                <span style={{fontFamily:"'Rajdhani',sans-serif",fontSize:11,
                  color:"rgba(255,255,255,0.5)"}}>{l}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ══ DRILL-DOWN ═══════════════════════════════════════════════════════ */}
      {activeTab === "drill" && (
        <div className="an-card an-drill-card">
          <div className="an-card-header">
            <div className="an-card-title">DRILL-DOWN ANALYSIS</div>
            <div className="an-drill-controls">
              {/* Level filter */}
              <div className="an-filter-group">
                {["All",...LEVEL_ORDER].map(f => (
                  <button key={f}
                    className={`an-filter-btn ${levelFilter===f?"an-filter-active":""}`}
                    style={levelFilter===f&&f!=="All"
                      ? {borderColor:`${LEVEL_COLOR[f]}44`,color:LEVEL_COLOR[f],background:`${LEVEL_COLOR[f]}11`}
                      : {}}
                    onClick={()=>setLevelFilter(f)}>{f}</button>
                ))}
              </div>
              {/* Format filter */}
              <div className="an-filter-group">
                {["All","TXT","JSON","CSV","LOG"].map(f => (
                  <button key={f}
                    className={`an-filter-btn ${fmtFilter===f?"an-filter-active":""}`}
                    onClick={()=>setFmtFilter(f)}>{f}</button>
                ))}
              </div>
              {/* Search */}
              <div className="an-table-search">
                <span>⌕</span>
                <input placeholder="Search file, level, score..."
                  value={drillSearch} onChange={e=>setDrillSearch(e.target.value)}/>
                {drillSearch && (
                  <button onClick={()=>setDrillSearch("")}
                    style={{background:"transparent",border:"none",color:"rgba(255,255,255,0.3)",cursor:"pointer",fontSize:12}}>✕</button>
                )}
              </div>
              <button className="an-export-btn" onClick={()=>exportCSV(drillFiltered)}
                style={{fontSize:11,padding:"5px 12px"}}>⬇ Export filtered</button>
            </div>
          </div>

          <div className="an-table-wrap">
            <table className="an-table">
              <thead>
                <tr>
                  <SortTh col="timestamp"           label="Timestamp"/>
                  <SortTh col="file_name"           label="File"/>
                  <SortTh col="file_format"         label="Fmt"/>
                  <SortTh col="threat_level"        label="Level"/>
                  <SortTh col="global_threat_score" label="Score"/>
                  <SortTh col="total_logs"          label="Logs"/>
                  <SortTh col="threat_percentage"   label="Threat%"/>
                  <SortTh col="execution_time"      label="Exec(s)"/>
                  <SortTh col="processors_used"     label="Procs"/>
                  <th>Nodes</th>
                </tr>
              </thead>
              <tbody>
                {drillFiltered.map((h,i) => (
                  <tr key={i} className={`an-tr ${selFile===i?"an-tr-selected":""}`}
                    onClick={()=>setSelFile(selFile===i?null:i)}
                    style={{cursor:"pointer"}}>
                    <td className="an-td-time">{h.timestamp}</td>
                    <td className="an-td-vec" style={{maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}
                      title={h.file_name}>{h.file_name}</td>
                    <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                      color:FORMAT_COLOR[h.file_format||"TXT"]||"#666"}}>{h.file_format||"TXT"}</td>
                    <td><RiskBadge level={h.threat_level}/></td>
                    <td style={{fontFamily:"'Orbitron',monospace",fontSize:13,fontWeight:700,
                      color:LEVEL_COLOR[h.threat_level]}}>{h.global_threat_score}</td>
                    <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,
                      color:"rgba(255,255,255,0.5)"}}>{fmt(h.total_logs)}</td>
                    <td>
                      <div style={{display:"flex",alignItems:"center",gap:6}}>
                        <div style={{width:50,height:5,background:"rgba(255,255,255,0.07)",borderRadius:3,overflow:"hidden"}}>
                          <div style={{width:`${Math.min(h.threat_percentage,100)}%`,height:"100%",
                            background:LEVEL_COLOR[h.threat_level],borderRadius:3}}/>
                        </div>
                        <span style={{fontSize:11,color:LEVEL_COLOR[h.threat_level],
                          fontFamily:"'Orbitron',monospace"}}>{fmtD(h.threat_percentage)}%</span>
                      </div>
                    </td>
                    <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                      color:"#ffea00"}}>{fmtD(h.execution_time,3)}</td>
                    <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,
                      color:"#76ff03"}}>{h.processors_used||"—"}</td>
                    <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                      color:"rgba(255,255,255,0.35)"}}>
                      {h.process_wise_scores?.length || "—"}
                    </td>
                  </tr>
                ))}
                {drillFiltered.length===0 && (
                  <tr><td colSpan={10} className="an-empty">No entries match the current filters</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Expanded row detail */}
          {selFile !== null && drillFiltered[selFile] && (
            <div style={{marginTop:16,padding:16,background:"rgba(6,182,212,0.05)",
              border:"1px solid rgba(6,182,212,0.15)",borderRadius:8}}>
              <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:10,letterSpacing:3,
                color:"rgba(255,255,255,0.3)",marginBottom:10}}>SELECTED ENTRY DETAILS</div>
              <div style={{display:"flex",gap:20,flexWrap:"wrap"}}>
                <div>
                  <div style={{fontSize:9,color:"rgba(255,255,255,0.3)",letterSpacing:2,fontFamily:"'Rajdhani',sans-serif"}}>FILE</div>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"#06b6d4"}}>
                    {drillFiltered[selFile].file_name}
                  </div>
                </div>
                <div>
                  <div style={{fontSize:9,color:"rgba(255,255,255,0.3)",letterSpacing:2,fontFamily:"'Rajdhani',sans-serif"}}>THROUGHPUT</div>
                  <div style={{fontFamily:"'Orbitron',monospace",fontSize:14,fontWeight:700,color:"#10b981"}}>
                    {drillFiltered[selFile].execution_time > 0
                      ? `${fmt(Math.round(drillFiltered[selFile].total_logs/drillFiltered[selFile].execution_time))}/s`
                      : "—"}
                  </div>
                </div>
                {drillFiltered[selFile].process_wise_scores?.length > 0 && (
                  <div style={{flex:1}}>
                    <div style={{fontSize:9,color:"rgba(255,255,255,0.3)",letterSpacing:2,
                      fontFamily:"'Rajdhani',sans-serif",marginBottom:6}}>NODE SCORES</div>
                    <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                      {drillFiltered[selFile].process_wise_scores.map((p,i) => {
                        const colors=["#06b6d4","#a855f7","#f97316","#10b981","#f59e0b","#ef4444"];
                        return (
                          <div key={i} style={{padding:"4px 10px",borderRadius:5,
                            background:`${colors[i%colors.length]}18`,
                            border:`1px solid ${colors[i%colors.length]}44`}}>
                            <span style={{fontFamily:"'Orbitron',monospace",fontSize:10,
                              color:colors[i%colors.length],fontWeight:700}}>
                              N{p.process_id}: {p.score}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="an-table-footer">
            Showing <strong>{drillFiltered.length}</strong> of <strong>{filtered.length}</strong> in range
          </div>
        </div>
      )}

      </>)}

      {/* ══ LOG QUEUE (FOLDER WATCHER) ═══════════════════════════════════════ */}
      {activeTab === "folder" && (
        <div style={{display:"flex",flexDirection:"column",gap:16}}>

          {/* Header card */}
          <div className="an-card">
            <div className="an-card-header">
              <div>
                <div className="an-card-title">📂 LOG GENERATOR QUEUE</div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                  color:"rgba(255,255,255,0.3)",marginTop:4,letterSpacing:1}}>
                  Drop SmartLog-generated files into{" "}
                  <span style={{color:"#f97316"}}>Uploads_From_Log_Generator/</span>{" "}
                  — new files appear here ready to analyse
                </div>
              </div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                {(folderData?.pending ?? 0) > 0 && (
                  <button onClick={analyzeAll}
                    style={{padding:"8px 18px",borderRadius:7,
                      border:"1px solid rgba(16,185,129,0.5)",
                      background:"rgba(16,185,129,0.1)",
                      color:"#10b981",fontFamily:"'Orbitron',monospace",
                      fontSize:11,fontWeight:700,letterSpacing:2,cursor:"pointer"}}>
                    ▶ ANALYSE ALL ({folderData.pending})
                  </button>
                )}
                <button onClick={fetchFolder}
                  style={{padding:"8px 14px",borderRadius:6,
                    border:"1px solid rgba(6,182,212,0.3)",
                    background:"rgba(6,182,212,0.07)",
                    color:"#06b6d4",fontFamily:"'Orbitron',monospace",
                    fontSize:11,letterSpacing:2,cursor:"pointer"}}>
                  {folderLoading ? "..." : "⟳ REFRESH"}
                </button>
              </div>
            </div>

            {/* Stats row */}
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              {[
                {label:"Total Files", val:folderData?.total??0,  color:"#06b6d4"},
                {label:"Pending",     val:folderData?.pending??0, color:"#f97316"},
                {label:"Analysed",    val:(folderData?.total??0)-(folderData?.pending??0), color:"#10b981"},
              ].map((s,i) => (
                <div key={i} style={{padding:"10px 18px",background:"rgba(255,255,255,0.03)",
                  border:"1px solid rgba(255,255,255,0.06)",borderRadius:8}}>
                  <div style={{fontFamily:"'Orbitron',monospace",fontSize:22,fontWeight:900,color:s.color}}>
                    {s.val}
                  </div>
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:10,
                    color:"rgba(255,255,255,0.3)",letterSpacing:2,marginTop:2}}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Error */}
          {folderData?.error && (
            <div className="an-card" style={{borderColor:"rgba(239,68,68,0.3)"}}>
              <span style={{color:"#ef4444",fontFamily:"'Share Tech Mono',monospace",fontSize:12}}>
                ⚠ {folderData.error}
              </span>
            </div>
          )}

          {/* Empty states */}
          {!folderLoading && folderData?.pending === 0 && (folderData?.total??0) === 0 && (
            <div className="an-card" style={{textAlign:"center",padding:"50px 20px"}}>
              <div style={{fontSize:42,marginBottom:12}}>📁</div>
              <div style={{fontFamily:"'Orbitron',monospace",fontSize:13,letterSpacing:4,
                color:"rgba(255,255,255,0.2)"}}>FOLDER IS EMPTY</div>
              <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:14,
                color:"rgba(255,255,255,0.25)",marginTop:8}}>
                Generate logs from SmartLog Generator and drop them into the watched folder.
              </div>
            </div>
          )}

          {!folderLoading && folderData?.pending === 0 && (folderData?.total??0) > 0 && (
            <div className="an-card" style={{textAlign:"center",padding:"40px 20px"}}>
              <div style={{fontSize:36,marginBottom:10}}>✅</div>
              <div style={{fontFamily:"'Orbitron',monospace",fontSize:13,letterSpacing:4,
                color:"#10b981"}}>ALL FILES ANALYSED</div>
              <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:14,
                color:"rgba(255,255,255,0.3)",marginTop:6}}>
                {folderData.total} file{folderData.total!==1?"s":""} in folder — all scored and stored in history.
                Drop new files to analyse them.
              </div>
            </div>
          )}

          {/* Only show PENDING files */}
          {folderData?.files?.filter(f => !f.analysed).map((file, i) => {
            const state  = analyzing[file.name];
            const result = analyzeResults[file.name];
            const isRunning = state === "running";
            const isDone    = state === "done";
            const isError   = typeof state === "string" && state.startsWith("error:");
            const errMsg    = isError ? state.replace("error:","") : "";
            const fmtColor  = {TXT:"#06b6d4",JSON:"#a855f7",CSV:"#10b981",LOG:"#f97316"}[file.ext]||"#666";

            return (
              <div key={i} className="an-card"
                style={{borderColor: file.analysed||isDone ? "rgba(16,185,129,0.2)"
                  : isError ? "rgba(239,68,68,0.2)"
                  : "rgba(255,255,255,0.07)"}}>
                <div style={{display:"flex",alignItems:"center",gap:16,flexWrap:"wrap"}}>

                  {/* Format badge */}
                  <div style={{width:44,height:44,borderRadius:8,flexShrink:0,
                    background:`${fmtColor}18`,border:`1px solid ${fmtColor}44`,
                    display:"flex",alignItems:"center",justifyContent:"center",
                    fontFamily:"'Orbitron',monospace",fontSize:10,color:fmtColor,fontWeight:700}}>
                    {file.ext}
                  </div>

                  {/* File info */}
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:13,
                      color:"#e2e8f0",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                      {file.name}
                    </div>
                    <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:11,
                      color:"rgba(255,255,255,0.35)",marginTop:3}}>
                      {file.size_kb} KB · Modified {file.modified}
                    </div>
                  </div>

                  {/* Status / result - shown after inline analysis completes */}
                  {isDone && result && !isRunning && (
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                        {[
                          {label:"SCORE", val:result.global_threat_score, color:LEVEL_COLOR[result.threat_level]},
                          {label:"LEVEL", val:result.threat_level,        color:LEVEL_COLOR[result.threat_level]},
                          {label:"LOGS",  val:Number(result.total_logs).toLocaleString(), color:"#06b6d4"},
                          {label:"TIME",  val:`${Number(result.execution_time).toFixed(3)}s`, color:"#ffea00"},
                        ].map((r,j) => (
                          <div key={j} style={{textAlign:"center"}}>
                            <div style={{fontFamily:"'Orbitron',monospace",fontSize:12,fontWeight:700,color:r.color}}>{r.val}</div>
                            <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:9,color:"rgba(255,255,255,0.3)",letterSpacing:2}}>{r.label}</div>
                          </div>
                        ))}
                      </div>
                      <span style={{padding:"4px 12px",borderRadius:4,fontSize:11,fontWeight:700,
                        background:"rgba(16,185,129,0.12)",color:"#10b981",
                        border:"1px solid rgba(16,185,129,0.3)",fontFamily:"'Orbitron',monospace",
                        letterSpacing:1,whiteSpace:"nowrap"}}>
                        ✓ DONE
                      </span>
                    </div>
                  )}

                  {isError && (
                    <div style={{padding:"6px 14px",borderRadius:6,fontSize:11,
                      background:"rgba(239,68,68,0.08)",color:"#ef4444",
                      border:"1px solid rgba(239,68,68,0.25)",fontFamily:"'Share Tech Mono',monospace",
                      maxWidth:260,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                      ⚠ {errMsg}
                    </div>
                  )}

                  {isRunning && (
                    <div style={{display:"flex",alignItems:"center",gap:10,
                      fontFamily:"'Orbitron',monospace",fontSize:11,color:"#06b6d4",letterSpacing:2}}>
                      <div style={{width:18,height:18,borderRadius:"50%",
                        border:"2px solid rgba(6,182,212,0.3)",borderTop:"2px solid #06b6d4",
                        animation:"spin 0.8s linear infinite"}}/>
                      ANALYSING...
                    </div>
                  )}

                  {/* Analyse button — only for files not yet running/done */}
                  {!isDone && !isRunning && (
                    <button onClick={() => analyzeFile(file.name)}
                      style={{padding:"9px 22px",borderRadius:7,
                        border:"1px solid rgba(249,115,22,0.5)",
                        background:"rgba(249,115,22,0.1)",
                        color:"#f97316",fontFamily:"'Orbitron',monospace",
                        fontSize:11,fontWeight:700,letterSpacing:2,
                        cursor:"pointer",flexShrink:0,
                        boxShadow:"0 0 12px rgba(249,115,22,0.1)",
                        transition:"all 0.2s ease"}}>
                      ▶ ANALYSE
                    </button>
                  )}
                </div>

                {/* Progress bar while running */}
                {isRunning && (
                  <div style={{marginTop:12,height:4,background:"rgba(255,255,255,0.05)",
                    borderRadius:2,overflow:"hidden"}}>
                    <div style={{height:"100%",background:"linear-gradient(90deg,#06b6d4,#10b981)",
                      borderRadius:2,animation:"progressPulse 1.5s ease-in-out infinite"}}/>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <style>{`
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes progressPulse{
          0%{width:10%;margin-left:0%}
          50%{width:40%;margin-left:30%}
          100%{width:10%;margin-left:90%}
        }
      `}</style>
    </div>
  );
}