import React, { useState, useEffect, useRef } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ScatterChart, Scatter, ZAxis, Legend
} from "recharts";
import "./Analytics.css";
import { useMpiConfig, useApiConfig, useThresholds, useClassifyThreat } from './Settingscontext';
           // → classify(score) uses live thresholds
// ─── Data ────────────────────────────────────────────────────────────────────
const RISK_TIMELINE = Array.from({ length: 31 }, (_, i) => ({
  day: String(i).padStart(2, "0"),
  alerts: Math.floor(Math.sin(i * 0.4) * 30 + 50 + Math.random() * 20),
  risk:   Math.floor(Math.cos(i * 0.3) * 25 + 60 + Math.random() * 15),
}));

const ATTACK_VECTORS = [
  { rank: 1, name: "Vulnerable Services",   count: 109, trend: [3,5,4,8,6,9,7],  change: "+12%" },
  { rank: 2, name: "Compromised Credentials",count: 56, trend: [2,3,5,3,6,4,5],  change: "+8%"  },
  { rank: 3, name: "Social Engineering",    count: 26,  trend: [4,2,3,4,2,3,3],  change: "-3%"  },
  { rank: 4, name: "DDoS (20%)",            count: 20,  trend: [1,3,2,4,3,2,4],  change: "+5%"  },
  { rank: 5, name: "SQLi",                  count: 17,  trend: [2,1,3,2,3,2,2],  change: "-1%"  },
  { rank: 6, name: "Other",                 count: 7,   trend: [1,1,2,1,1,1,2],  change: "+2%"  },
];

const PIE_DATA = [
  { name: "Malware",      value: 18, color: "#f97316" },
  { name: "DDos",         value: 20, color: "#06b6d4" },
  { name: "SQU",          value: 17, color: "#a855f7" },
  { name: "DDoS",         value: 20, color: "#3b82f6" },
  { name: "Brute Force",  value: 15, color: "#10b981" },
  { name: "CSRF",         value: 8,  color: "#f59e0b" },
  { name: "XSS",          value: 12, color: "#ef4444" },
];

const GEO_DATA = [
  { country: "Russia",  code: "RU", count: 276, color: "#ef4444" },
  { country: "China",   code: "CN", count: 136, color: "#f97316" },
  { country: "USA",     code: "US", count: 25,  color: "#06b6d4" },
  { country: "Brazil",  code: "BR", count: 18,  color: "#a855f7" },
  { country: "N.Korea", code: "KP", count: 15,  color: "#ef4444" },
  { country: "Iran",    code: "IR", count: 11,  color: "#f59e0b" },
];

const RADAR_DATA = [
  { metric: "Network",    score: 82, max: 100 },
  { metric: "Endpoint",   score: 74, max: 100 },
  { metric: "Cloud",      score: 91, max: 100 },
  { metric: "Identity",   score: 65, max: 100 },
  { metric: "Data",       score: 88, max: 100 },
  { metric: "Application",score: 70, max: 100 },
];

const SCORE_BREAKDOWN = [
  { label: "Network Scores",   value: 82, color: "#ef4444", icon: "⬡" },
  { label: "Endpoints Scores", value: 80, color: "#f97316", icon: "◈" },
  { label: "Cloud Scores",     value: 91, color: "#f59e0b", icon: "☁" },
];

const DRILL_DATA = [
  { id: "Alert 92501", risk: "Critical", time: "2023-05-21 15:29:00", vector: "Vulnerable Services",    ip: "192.168.1.41", asset: "Target Asset",            score: "91%" },
  { id: "Alert 92802", risk: "High",     time: "2023-05-21 15:29:00", vector: "Compromised Credentials",ip: "192.168.1.23", asset: "Target Asset",            score: "86%" },
  { id: "Alert 92503", risk: "Medium",   time: "2023-05-21 15:30:00", vector: "Social Engineering",     ip: "192.168.1.52", asset: "Target Asset (Retarg...)", score: "70%" },
  { id: "Alert 92504", risk: "Low",      time: "2023-05-21 15:39:00", vector: "Vulnerable Services",    ip: "192.168.1.31", asset: "Target Asset",            score: "60%" },
  { id: "Alert 92505", risk: "Critical", time: "2023-05-21 15:41:00", vector: "DDos Attack",            ip: "203.45.67.89", asset: "Core Infrastructure",     score: "95%" },
  { id: "Alert 92506", risk: "High",     time: "2023-05-21 15:44:00", vector: "SQLi Injection",         ip: "185.199.110.5",asset: "DB Server A",             score: "88%" },
];

const HEATMAP_HOURS  = ["00","02","04","06","08","10","12","14","16","18","20","22"];
const HEATMAP_DAYS   = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
const HEATMAP_MATRIX = HEATMAP_DAYS.map(() =>
  HEATMAP_HOURS.map(() => Math.floor(Math.random() * 100))
);

const SCATTER_DATA = Array.from({ length: 40 }, () => ({
  frequency: Math.floor(Math.random() * 100),
  severity:  Math.floor(Math.random() * 100),
  size:       Math.floor(Math.random() * 200) + 50,
  type:       ["Malware","DDoS","SQLi","XSS"][Math.floor(Math.random()*4)],
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────
const RiskBadge = ({ level }) => {
  const map = { Critical:"#ff1744", High:"#ef5350", Medium:"#ffa726", Low:"#29b6f6" };
  return <span className="an-badge" style={{ background: map[level] || "#666" }}>{level}</span>;
};

const SparkLine = ({ data, color }) => {
  const max = Math.max(...data);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * 60;
    const y = 18 - (v / max) * 16;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width="64" height="20" viewBox="0 0 64 20">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 3px ${color})` }} />
    </svg>
  );
};

const MiniAreaChart = ({ data, color }) => (
  <ResponsiveContainer width="100%" height={50}>
    <AreaChart data={data.map((v, i) => ({ v, i }))} margin={{ top:2, right:0, left:0, bottom:0 }}>
      <defs>
        <linearGradient id={`ag${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="5%"  stopColor={color} stopOpacity={0.3} />
          <stop offset="95%" stopColor={color} stopOpacity={0}   />
        </linearGradient>
      </defs>
      <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5}
        fill={`url(#ag${color.replace("#","")})`} dot={false} />
    </AreaChart>
  </ResponsiveContainer>
);

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="an-tooltip">
      <div className="an-tt-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.stroke }}>
          {p.name}: <b>{p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Animated Counter ────────────────────────────────────────────────────────
function AnimCounter({ target, duration = 1200 }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = target / (duration / 16);
    const t = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(t); }
      else setVal(Math.floor(start));
    }, 16);
    return () => clearInterval(t);
  }, [target, duration]);
  return <>{val}</>;
}

// ─── Global Analytics Score ───────────────────────────────────────────────────
function GlobalScore({ score = 91 }) {
  const R    = 80;
  const circ = 2 * Math.PI * R;
  const pct  = score / 100;
  return (
    <div className="an-score-wrap">
      <div className="an-score-ring">
        <svg width="200" height="200" viewBox="0 0 200 200">
          <defs>
            <linearGradient id="scoreGrad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#ef4444"/>
              <stop offset="100%" stopColor="#f97316"/>
            </linearGradient>
            <filter id="scoreGlow">
              <feGaussianBlur stdDeviation="4" result="b"/>
              <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>
          {/* Track segments */}
          {[...Array(36)].map((_, i) => {
            const a = (i / 36) * Math.PI * 2 - Math.PI / 2;
            const x1 = 100 + 90 * Math.cos(a), y1 = 100 + 90 * Math.sin(a);
            const x2 = 100 + 82 * Math.cos(a), y2 = 100 + 82 * Math.sin(a);
            const active = i / 36 < pct;
            return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={active ? "url(#scoreGrad)" : "rgba(255,255,255,0.07)"}
              strokeWidth="3" strokeLinecap="round"
              style={active ? { filter: "drop-shadow(0 0 3px #f97316)" } : {}}
            />;
          })}
          <circle cx="100" cy="100" r="68" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="1"/>
        </svg>
        <div className="an-score-center">
          <div className="an-score-label">Score</div>
          <div className="an-score-val"><AnimCounter target={score} /></div>
          <div className="an-score-sub">OVERALL POSTURE: <span className="posture-strong">STRONG</span></div>
        </div>
      </div>
      <div className="an-score-breakdown">
        {SCORE_BREAKDOWN.map((s, i) => (
          <div key={i} className="an-score-row">
            <div className="an-score-icon" style={{ color: s.color }}>{s.icon}</div>
            <div className="an-score-info">
              <div className="an-score-name">{s.label}</div>
              <div className="an-score-bar-wrap">
                <div className="an-score-bar-track">
                  <div className="an-score-bar-fill"
                    style={{ width: `${s.value}%`, background: s.color, boxShadow:`0 0 8px ${s.color}` }}/>
                </div>
                <span className="an-score-num" style={{ color: s.color }}>{s.value}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── KPI Strip ────────────────────────────────────────────────────────────────
function KpiStrip() {
  const kpis = [
    { label: "Total Incidents",   val: 1248, color: "#ef4444", icon: "⚠", delta: "+14%",  up: true  },
    { label: "Avg Response Time", val: "4.2m",color:"#f97316", icon: "⏱", delta: "-22%",  up: false },
    { label: "Blocked Threats",   val: 9871,  color:"#10b981", icon: "🛡", delta: "+31%",  up: true  },
    { label: "Active Indicators", val: 342,   color:"#a855f7", icon: "◉", delta: "+7%",   up: true  },
    { label: "MTTD (min)",        val: 12,    color:"#06b6d4", icon: "⬡", delta: "-8%",   up: false },
  ];
  return (
    <div className="an-kpi-strip">
      {kpis.map((k, i) => (
        <div key={i} className="an-kpi-card" style={{ animationDelay: `${i*0.08}s` }}>
          <div className="an-kpi-top">
            <span className="an-kpi-icon" style={{ color: k.color }}>{k.icon}</span>
            <span className={`an-kpi-delta ${k.up ? "delta-up" : "delta-dn"}`}>{k.delta}</span>
          </div>
          <div className="an-kpi-val" style={{ color: k.color }}>
            {typeof k.val === "number" ? <AnimCounter target={k.val} /> : k.val}
          </div>
          <div className="an-kpi-label">{k.label}</div>
          <MiniAreaChart
            data={Array.from({length:8},()=>Math.floor(Math.random()*80)+20)}
            color={k.color}
          />
        </div>
      ))}
    </div>
  );
}

// ─── Heatmap ─────────────────────────────────────────────────────────────────
function ThreatHeatmap() {
  const getColor = (v) => {
    if (v < 20)  return "rgba(16,185,129,0.15)";
    if (v < 40)  return "rgba(245,158,11,0.25)";
    if (v < 60)  return "rgba(249,115,22,0.4)";
    if (v < 80)  return "rgba(239,68,68,0.55)";
    return "rgba(239,68,68,0.85)";
  };
  return (
    <div className="an-heatmap-wrap">
      <div className="an-heatmap-yaxis">
        {HEATMAP_DAYS.map(d => <div key={d} className="an-hm-ylabel">{d}</div>)}
      </div>
      <div className="an-heatmap-grid">
        <div className="an-hm-xaxis">
          {HEATMAP_HOURS.map(h => <div key={h} className="an-hm-xlabel">{h}:00</div>)}
        </div>
        {HEATMAP_MATRIX.map((row, ri) => (
          <div key={ri} className="an-hm-row">
            {row.map((val, ci) => (
              <div key={ci} className="an-hm-cell" style={{ background: getColor(val) }}
                title={`${HEATMAP_DAYS[ri]} ${HEATMAP_HOURS[ci]}:00 — ${val} threats`}>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main Analytics Component ─────────────────────────────────────────────────
export default function Analytics() {
  const [drillSearch,  setDrillSearch]  = useState("");
  const [riskFilter,   setRiskFilter]   = useState("All");
  const [timeRange,    setTimeRange]    = useState("30d");
  const [activeTab,    setActiveTab]    = useState("overview");
  const [sortCol,      setSortCol]      = useState("id");
  const [sortDir,      setSortDir]      = useState("asc");
  const [selectedVector, setSelectedVector] = useState(null);
  const { processors } = useMpiConfig();
  const filtered = DRILL_DATA.filter(d => {
    const matchSearch = d.id.toLowerCase().includes(drillSearch.toLowerCase()) ||
      d.vector.toLowerCase().includes(drillSearch.toLowerCase()) ||
      d.ip.includes(drillSearch);
    const matchRisk = riskFilter === "All" || d.risk === riskFilter;
    return matchSearch && matchRisk;
  });

  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortCol] ?? "", bv = b[sortCol] ?? "";
    return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
  });

  const toggleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("asc"); }
  };

  const ThHead = ({ col, label }) => (
    <th className={`sortable ${sortCol === col ? "sorted" : ""}`}
      onClick={() => toggleSort(col)}>
      {label} <span className="sort-arrow">{sortCol === col ? (sortDir === "asc" ? "↑" : "↓") : "⇅"}</span>
    </th>
  );

  return (
    <div className="an-page">

      {/* ── Page Header ── */}
      <div className="an-header">
        <div>
          <div className="an-page-title">Analytics</div>
          <div className="an-page-sub">Advanced threat intelligence & risk analysis</div>
        </div>
        <div className="an-header-controls">
          {["24h","7d","30d","90d"].map(t => (
            <button key={t} className={`an-time-btn ${timeRange===t?"active":""}`}
              onClick={() => setTimeRange(t)}>{t}</button>
          ))}
          <button className="an-export-btn">⬇ Export Report</button>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="an-tabs">
        {[
          { id:"overview",  label:"Overview"        },
          { id:"threats",   label:"Threat Intel"    },
          { id:"heatmap",   label:"Attack Heatmap"  },
          { id:"correlate", label:"Correlation"     },
        ].map(t => (
          <button key={t.id} className={`an-tab ${activeTab===t.id?"an-tab-active":""}`}
            onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── KPI Strip (always visible) ── */}
      <KpiStrip />

      {/* ══════════ OVERVIEW TAB ════════════════════════════════════════════ */}
      {activeTab === "overview" && (
        <>
          {/* Row 1: Score + Risk Timeline */}
          <div className="an-row">
            <div className="an-card" style={{ flex:"0 0 420px" }}>
              <div className="an-card-header">
                <div className="an-card-title">GLOBAL ANALYTICS SCORE</div>
              </div>
              <GlobalScore score={91} />
            </div>

            <div className="an-card" style={{ flex: 1 }}>
              <div className="an-card-header">
                <div className="an-card-title">RISK DISTRIBUTION OVER TIME</div>
                <div className="an-card-chips">
                  <span className="an-chip">Last {timeRange}</span>
                  <span className="an-chip-outline">Mar 1 – Mar 30, 2023</span>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={RISK_TIMELINE} margin={{ top:10, right:20, left:-15, bottom:0 }}>
                  <defs>
                    <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#a855f7" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)"/>
                  <XAxis dataKey="day" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:11 }}
                    axisLine={false} tickLine={false}/>
                  <YAxis tick={{ fill:"rgba(255,255,255,0.3)", fontSize:11 }}
                    axisLine={false} tickLine={false} domain={[0,100]}/>
                  <Tooltip content={<CustomTooltip />}/>
                  <Legend wrapperStyle={{ fontSize:12, color:"rgba(255,255,255,0.5)", paddingTop:8 }}/>
                  <Area type="monotone" dataKey="alerts" stroke="#06b6d4" strokeWidth={2}
                    fill="url(#alertGrad)" dot={false} name="Alerts"/>
                  <Area type="monotone" dataKey="risk" stroke="#a855f7" strokeWidth={2}
                    fill="url(#riskGrad)" dot={false} name="Risk events"/>
                </AreaChart>
              </ResponsiveContainer>
              {/* Risk event dots row */}
              <div className="an-risk-dots">
                {RISK_TIMELINE.slice(0,16).map((_, i) => (
                  <div key={i} className="an-risk-dot"
                    style={{ opacity: Math.random() > 0.3 ? 1 : 0.2 }}/>
                ))}
              </div>
            </div>
          </div>

          {/* Row 2: Pie + Attack Vectors + Geo */}
          <div className="an-row">
            <div className="an-card" style={{ flex:"0 0 320px" }}>
              <div className="an-card-header">
                <div className="an-card-title">ADVANCED THREAT DETECTION</div>
              </div>
              <div className="an-pie-wrap">
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={PIE_DATA} cx="50%" cy="50%"
                      innerRadius={60} outerRadius={100}
                      dataKey="value" paddingAngle={2}
                      startAngle={90} endAngle={-270}>
                      {PIE_DATA.map((d, i) => (
                        <Cell key={i} fill={d.color}
                          style={{ filter:`drop-shadow(0 0 5px ${d.color}66)` }}/>
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />}/>
                  </PieChart>
                </ResponsiveContainer>
                {/* Shield icon center */}
                <div className="an-pie-center">🛡</div>
              </div>
              <div className="an-pie-legend">
                {PIE_DATA.map((d, i) => (
                  <div key={i} className="an-pie-leg-row">
                    <div className="an-pie-dot" style={{ background: d.color }}/>
                    <span>{d.name}</span>
                    <span className="an-pie-pct" style={{ color: d.color }}>{d.value}%</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="an-card" style={{ flex: 1 }}>
              <div className="an-card-header">
                <div className="an-card-title">TOP ATTACK VECTORS</div>
                <div className="an-card-chips">
                  <span className="an-chip-outline">Live</span>
                </div>
              </div>
              <div className="an-vector-list">
                {ATTACK_VECTORS.map((v, i) => (
                  <div key={i}
                    className={`an-vector-row ${selectedVector===i?"an-vector-selected":""}`}
                    onClick={() => setSelectedVector(selectedVector===i?null:i)}>
                    <div className="an-vec-rank">{v.rank}</div>
                    <div className="an-vec-name">{v.name}</div>
                    <div className="an-vec-bar-wrap">
                      <div className="an-vec-track">
                        <div className="an-vec-fill"
                          style={{
                            width:`${(v.count/109)*100}%`,
                            background:`linear-gradient(90deg,#3b82f688,#06b6d4)`
                          }}/>
                      </div>
                    </div>
                    <div className="an-vec-count">{v.count}</div>
                    <SparkLine data={v.trend} color="#06b6d4"/>
                    <div className={`an-vec-change ${v.change.startsWith("+")?"chg-up":"chg-dn"}`}>
                      {v.change}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="an-card" style={{ flex:"0 0 280px" }}>
              <div className="an-card-header">
                <div className="an-card-title">GEOGRAPHIC THREAT MAP</div>
              </div>
              <div className="an-geo-map">
                {/* Stylized world map SVG placeholder */}
                <div className="an-world-placeholder">
                  <svg viewBox="0 0 280 160" className="an-world-svg">
                    <rect width="280" height="160" fill="none"/>
                    {/* Grid lines */}
                    {[40,80,120,160,200,240].map(x=>(
                      <line key={x} x1={x} y1="0" x2={x} y2="160"
                        stroke="rgba(6,182,212,0.08)" strokeWidth="0.5"/>
                    ))}
                    {[40,80,120].map(y=>(
                      <line key={y} x1="0" y1={y} x2="280" y2={y}
                        stroke="rgba(6,182,212,0.08)" strokeWidth="0.5"/>
                    ))}
                    {/* Threat origin pulses */}
                    {[
                      {cx:190,cy:55,r:8,c:"#ef4444"},
                      {cx:210,cy:65,r:6,c:"#f97316"},
                      {cx:85, cy:70,r:5,c:"#06b6d4"},
                      {cx:72, cy:100,r:4,c:"#a855f7"},
                      {cx:205,cy:72,r:5,c:"#ef4444"},
                    ].map((p,i)=>(
                      <g key={i}>
                        <circle cx={p.cx} cy={p.cy} r={p.r}
                          fill={`${p.c}33`} stroke={p.c} strokeWidth="1">
                          <animate attributeName="r" values={`${p.r};${p.r*2.5};${p.r}`}
                            dur={`${1.5+i*0.3}s`} repeatCount="indefinite"/>
                          <animate attributeName="opacity" values="0.8;0.1;0.8"
                            dur={`${1.5+i*0.3}s`} repeatCount="indefinite"/>
                        </circle>
                        <circle cx={p.cx} cy={p.cy} r="3"
                          fill={p.c} style={{filter:`drop-shadow(0 0 4px ${p.c})`}}/>
                      </g>
                    ))}
                    {/* Connection lines */}
                    {[
                      {x1:190,y1:55,x2:85,y2:70},
                      {x1:210,y1:65,x2:85,y2:70},
                      {x1:205,y1:72,x2:72,y2:100},
                    ].map((l,i)=>(
                      <line key={i} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2}
                        stroke="rgba(6,182,212,0.2)" strokeWidth="0.8" strokeDasharray="4 3"/>
                    ))}
                  </svg>
                </div>
              </div>
              <div className="an-geo-title">Top Threat Origin Countries</div>
              <div className="an-geo-list">
                {GEO_DATA.map((g, i) => (
                  <div key={i} className="an-geo-row">
                    <div className="an-geo-flag">{g.code}</div>
                    <div className="an-geo-country">{g.country}</div>
                    <div className="an-geo-bar-wrap">
                      <div className="an-geo-bar" style={{
                        width:`${(g.count/276)*90}%`,
                        background: g.color, boxShadow:`0 0 6px ${g.color}55`
                      }}/>
                    </div>
                    <div className="an-geo-count" style={{ color: g.color }}>{g.count}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}

      {/* ══════════ THREAT INTEL TAB ═══════════════════════════════════════ */}
      {activeTab === "threats" && (
        <>
          <div className="an-row">
            <div className="an-card" style={{ flex: 1 }}>
              <div className="an-card-header">
                <div className="an-card-title">THREAT CATEGORY RADAR</div>
              </div>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart data={RADAR_DATA} margin={{ top:20, right:30, left:30, bottom:20 }}>
                  <PolarGrid stroke="rgba(255,255,255,0.08)"/>
                  <PolarAngleAxis dataKey="metric"
                    tick={{ fill:"rgba(255,255,255,0.5)", fontSize:12, fontFamily:"Rajdhani",fontWeight:600 }}/>
                  <PolarRadiusAxis angle={30} domain={[0,100]}
                    tick={{ fill:"rgba(255,255,255,0.2)", fontSize:10 }} axisLine={false}/>
                  <Radar name="Threat Score" dataKey="score" stroke="#06b6d4"
                    fill="#06b6d4" fillOpacity={0.18} strokeWidth={2}
                    dot={{ fill:"#06b6d4", r:4 }}/>
                  <Tooltip content={<CustomTooltip />}/>
                </RadarChart>
              </ResponsiveContainer>
            </div>

            <div className="an-card" style={{ flex: 1 }}>
              <div className="an-card-header">
                <div className="an-card-title">ATTACK FREQUENCY BY HOUR</div>
              </div>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={HEATMAP_HOURS.map(h => ({
                    hour: h+":00",
                    attacks: Math.floor(Math.random()*80)+10,
                    blocked: Math.floor(Math.random()*60)+5,
                  }))}
                  margin={{ top:10, right:20, left:-15, bottom:0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false}/>
                  <XAxis dataKey="hour" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                    axisLine={false} tickLine={false}/>
                  <YAxis tick={{ fill:"rgba(255,255,255,0.3)", fontSize:10 }}
                    axisLine={false} tickLine={false}/>
                  <Tooltip content={<CustomTooltip />}/>
                  <Legend wrapperStyle={{ fontSize:11, color:"rgba(255,255,255,0.4)" }}/>
                  <Bar dataKey="attacks" fill="#ef4444" radius={[3,3,0,0]} name="Attacks"
                    style={{ filter:"drop-shadow(0 0 4px #ef444488)" }}/>
                  <Bar dataKey="blocked" fill="#10b981" radius={[3,3,0,0]} name="Blocked"
                    style={{ filter:"drop-shadow(0 0 4px #10b98188)" }}/>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat feed */}
          <div className="an-card">
            <div className="an-card-header">
              <div className="an-card-title">LIVE THREAT INTELLIGENCE FEED</div>
              <div className="an-live-pulse"><div className="an-live-dot"/>LIVE</div>
            </div>
            <div className="an-feed-list">
              {[
                { time:"15:42:01", type:"MALWARE",  ip:"185.199.110.5",  msg:"Trojan.GenericKD detected — quarantined",     sev:"critical" },
                { time:"15:41:38", type:"BRUTEFORCE",ip:"203.45.67.89",  msg:"SSH brute force — 847 attempts blocked",       sev:"high"     },
                { time:"15:40:12", type:"SQLi",     ip:"10.0.0.55",      msg:"SQL injection in /api/search — sanitized",     sev:"medium"   },
                { time:"15:39:55", type:"DDOS",     ip:"45.33.32.156",   msg:"DDoS flood 2.4Gbps — mitigation active",       sev:"critical" },
                { time:"15:38:22", type:"XSS",      ip:"172.16.0.99",    msg:"Reflected XSS in login form — blocked",        sev:"medium"   },
                { time:"15:37:01", type:"RECON",    ip:"198.51.100.7",   msg:"Port scan 1-65535 from external IP",           sev:"low"      },
              ].map((f, i) => {
                const sc = { critical:"#ef4444", high:"#f97316", medium:"#ffa726", low:"#29b6f6" };
                return (
                  <div key={i} className="an-feed-row">
                    <div className="an-feed-time">{f.time}</div>
                    <div className="an-feed-type" style={{ color: sc[f.sev] }}>{f.type}</div>
                    <div className="an-feed-ip">{f.ip}</div>
                    <div className="an-feed-msg">{f.msg}</div>
                    <div className="an-feed-sev">
                      <span className="an-feed-badge" style={{ background:`${sc[f.sev]}22`, color:sc[f.sev], border:`1px solid ${sc[f.sev]}44` }}>
                        {f.sev}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* ══════════ HEATMAP TAB ════════════════════════════════════════════ */}
      {activeTab === "heatmap" && (
        <div className="an-card">
          <div className="an-card-header">
            <div className="an-card-title">ATTACK INTENSITY HEATMAP — HOUR × DAY</div>
            <div className="an-heatmap-legend">
              {["Low","Med","High","Critical"].map((l,i) => {
                const c = ["rgba(16,185,129,0.5)","rgba(245,158,11,0.5)","rgba(249,115,22,0.6)","rgba(239,68,68,0.85)"];
                return (
                  <div key={i} className="an-hm-leg-item">
                    <div className="an-hm-leg-swatch" style={{ background: c[i] }}/>
                    <span>{l}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <ThreatHeatmap />
          <div className="an-heatmap-insight">
            <span className="insight-icon">💡</span>
            Peak attack activity detected between <strong>08:00–12:00</strong> on weekdays.
            Tuesday shows highest concentration of critical threats.
          </div>
        </div>
      )}

      {/* ══════════ CORRELATION TAB ════════════════════════════════════════ */}
      {activeTab === "correlate" && (
        <div className="an-row" style={{ flexDirection:"column" }}>
          <div className="an-card">
            <div className="an-card-header">
              <div className="an-card-title">THREAT FREQUENCY vs SEVERITY CORRELATION</div>
              <div className="an-card-chips">
                {["Malware","DDoS","SQLi","XSS"].map((t,i)=>{
                  const c=["#f97316","#06b6d4","#a855f7","#ef4444"];
                  return <span key={i} className="an-chip" style={{ borderColor:c[i], color:c[i] }}>{t}</span>;
                })}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <ScatterChart margin={{ top:20, right:30, left:-10, bottom:20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)"/>
                <XAxis dataKey="frequency" name="Frequency" type="number"
                  tick={{ fill:"rgba(255,255,255,0.3)", fontSize:11 }}
                  label={{ value:"Attack Frequency", position:"bottom", fill:"rgba(255,255,255,0.3)", fontSize:12 }}
                  axisLine={false} tickLine={false}/>
                <YAxis dataKey="severity" name="Severity" type="number"
                  tick={{ fill:"rgba(255,255,255,0.3)", fontSize:11 }}
                  label={{ value:"Severity Score", angle:-90, position:"insideLeft", fill:"rgba(255,255,255,0.3)", fontSize:12 }}
                  axisLine={false} tickLine={false}/>
                <ZAxis dataKey="size" range={[40,400]}/>
                <Tooltip cursor={{ stroke:"rgba(255,255,255,0.1)" }} content={<CustomTooltip />}/>
                <Scatter data={SCATTER_DATA} fill="#06b6d4"
                  style={{ filter:"drop-shadow(0 0 4px #06b6d4)" }}/>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ── Drill-Down Table (always visible) ── */}
      <div className="an-card an-drill-card">
        <div className="an-card-header">
          <div className="an-card-title">DRILL-DOWN ANALYTICS</div>
          <div className="an-drill-controls">
            <div className="an-filter-group">
              {["All","Critical","High","Medium","Low"].map(f => (
                <button key={f}
                  className={`an-filter-btn ${riskFilter===f?"an-filter-active":""}`}
                  onClick={() => setRiskFilter(f)}>{f}</button>
              ))}
            </div>
            <div className="an-table-search">
              <span>⌕</span>
              <input placeholder="Search incidents..."
                value={drillSearch} onChange={e => setDrillSearch(e.target.value)}/>
            </div>
          </div>
        </div>

        <div className="an-table-wrap">
          <table className="an-table">
            <thead>
              <tr>
                <ThHead col="id"     label="Incident ID"        />
                <ThHead col="risk"   label="Risk Level"         />
                <ThHead col="time"   label="Timestamp"          />
                <ThHead col="vector" label="Attack Vector"      />
                <ThHead col="ip"     label="Source IP"          />
                <ThHead col="asset"  label="Target Asset"       />
                <ThHead col="score"  label="Correlation Score"  />
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((d, i) => (
                <tr key={i} className="an-tr">
                  <td className="an-td-id">{d.id}</td>
                  <td><RiskBadge level={d.risk} /></td>
                  <td className="an-td-time">{d.time}</td>
                  <td className="an-td-vec">{d.vector}</td>
                  <td className="an-td-ip">{d.ip}</td>
                  <td className="an-td-asset">{d.asset}</td>
                  <td>
                    <div className="an-corr-wrap">
                      <div className="an-corr-bar">
                        <div className="an-corr-fill" style={{
                          width: d.score,
                          background: parseInt(d.score)>=90?"#ef4444":parseInt(d.score)>=70?"#f97316":"#ffa726"
                        }}/>
                      </div>
                      <span className="an-corr-val">{d.score}</span>
                    </div>
                  </td>
                  <td>
                    <div className="an-act-row">
                      <button className="an-act-btn an-inv">Investigate</button>
                      <button className="an-act-btn an-log">View Logs</button>
                    </div>
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr><td colSpan={8} className="an-empty">No incidents match the current filters</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="an-table-footer">
          Showing <strong>{sorted.length}</strong> of <strong>{DRILL_DATA.length}</strong> incidents
        </div>
      </div>

    </div>
  );
}