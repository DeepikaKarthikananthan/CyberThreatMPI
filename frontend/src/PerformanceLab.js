import React, { useState, useEffect, useRef } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, ComposedChart,
  ReferenceLine
} from "recharts";
import "./PerformanceLab.css";
// ── Context import (hooks used INSIDE component only, never at module level) ──
import { useUiConfig, useMpiConfig } from "./Settingscontext";

// ─── Live data generator ──────────────────────────────────────────────────────
const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const generateTick = (prev) => ({
  t:          Date.now(),
  cpu:        Math.min(100, Math.max(5,  (prev?.cpu        ?? 40) + rand(-8,  8))),
  memory:     Math.min(100, Math.max(10, (prev?.memory     ?? 55) + rand(-4,  4))),
  network:    Math.min(100, Math.max(0,  (prev?.network    ?? 30) + rand(-15, 15))),
  mpiOps:     Math.min(100, Math.max(5,  (prev?.mpiOps     ?? 60) + rand(-10, 10))),
  latency:    Math.max(0.5, (prev?.latency    ?? 4)   + (Math.random() - 0.5) * 1.5),
  throughput: Math.max(10,  (prev?.throughput ?? 340) + rand(-40, 40)),
  label:      new Date().toLocaleTimeString([], { hour:"2-digit", minute:"2-digit", second:"2-digit" }),
});

const NODES = [
  { id:0, name:"NODE_00", role:"Master", color:"#00e5ff" },
  { id:1, name:"NODE_01", role:"Worker", color:"#76ff03" },
  { id:2, name:"NODE_02", role:"Worker", color:"#ff6d00" },
  { id:3, name:"NODE_03", role:"Worker", color:"#d500f9" },
];

const BENCHMARK_RESULTS = [
  { test:"Log Parsing Speed",     score:9840, unit:"lines/s", grade:"A+", color:"#00e5ff" },
  { test:"MPI Reduce Latency",    score:0.82, unit:"ms",      grade:"A",  color:"#76ff03" },
  { test:"Pattern Match Rate",    score:98.4, unit:"%",       grade:"A+", color:"#00e5ff" },
  { test:"Memory Efficiency",     score:87.2, unit:"%",       grade:"B+", color:"#ff6d00" },
  { test:"Inter-node Bandwidth",  score:3.2,  unit:"GB/s",    grade:"A",  color:"#76ff03" },
  { test:"Fault Tolerance Score", score:94.7, unit:"%",       grade:"A",  color:"#00e5ff" },
];

const PROCESS_LOG = [
  { pid:"PID-4821", node:"NODE_00", status:"running",   cpu:22, mem:418, task:"Log ingestion",        start:"14:30:01" },
  { pid:"PID-4822", node:"NODE_01", status:"running",   cpu:31, mem:512, task:"Pattern matching",     start:"14:30:01" },
  { pid:"PID-4823", node:"NODE_02", status:"running",   cpu:19, mem:380, task:"Threat scoring",       start:"14:30:02" },
  { pid:"PID-4824", node:"NODE_03", status:"running",   cpu:27, mem:445, task:"Score aggregation",    start:"14:30:02" },
  { pid:"PID-4810", node:"NODE_00", status:"completed", cpu:0,  mem:0,   task:"File validation",      start:"14:29:55" },
  { pid:"PID-4811", node:"NODE_01", status:"completed", cpu:0,  mem:0,   task:"MPI_Init",             start:"14:29:56" },
  { pid:"PID-4825", node:"NODE_02", status:"waiting",   cpu:0,  mem:128, task:"Result serialization", start:"—"        },
];

const MEMORY_SEGMENTS = [
  { label:"MPI Buffers",   pct:28, color:"#00e5ff", bytes:"1.12 GB" },
  { label:"Log Cache",     pct:22, color:"#76ff03", bytes:"0.88 GB" },
  { label:"Pattern Index", pct:18, color:"#ff6d00", bytes:"0.72 GB" },
  { label:"OS Reserved",   pct:15, color:"#d500f9", bytes:"0.60 GB" },
  { label:"Free",          pct:17, color:"rgba(255,255,255,0.08)", bytes:"0.68 GB" },
];

const COMM_MATRIX = [
  [0, 42, 18, 31],
  [42, 0, 55, 22],
  [18, 55, 0, 38],
  [31, 22, 38, 0],
];

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
const PerfTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="pl-tooltip">
      <div className="pl-tt-time">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.stroke || p.color }}>
          {p.name}: <b>{typeof p.value === "number" ? p.value.toFixed(1) : p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Animated Gauge ───────────────────────────────────────────────────────────
function Gauge({ value, max = 100, label, unit, color, size = 120 }) {
  const R = size * 0.38, cx = size / 2, cy = size / 2;
  const pct = value / max;
  const startAngle = (210 * Math.PI) / 180;
  const sweep = (240 * Math.PI) / 180;
  const endAngle = startAngle - sweep * pct;
  const arcPath = (a1, a2) => {
    const x1 = cx - R * Math.cos(a1), y1 = cy + R * Math.sin(a1);
    const x2 = cx - R * Math.cos(a2), y2 = cy + R * Math.sin(a2);
    const large = Math.abs(a1 - a2) > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${R} ${R} 0 ${large} 1 ${x2} ${y2}`;
  };
  const trackPath  = arcPath(startAngle, startAngle - sweep);
  const activePath = pct > 0 ? arcPath(startAngle, endAngle) : "";
  const warnColor  = value > 85 ? "#ff1744" : value > 70 ? "#ff6d00" : color;
  return (
    <div className="pl-gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <filter id={`gf${label}`}>
            <feGaussianBlur stdDeviation="2" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <path d={trackPath} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" strokeLinecap="round"/>
        {activePath && (
          <path d={activePath} fill="none" stroke={warnColor} strokeWidth="8" strokeLinecap="round"
            filter={`url(#gf${label})`}
            style={{ transition:"d 0.5s ease, stroke 0.5s ease" }}/>
        )}
        {activePath && (() => {
          const nx = cx - R * Math.cos(endAngle), ny = cy + R * Math.sin(endAngle);
          return <circle cx={nx} cy={ny} r="5" fill={warnColor}
            style={{ filter:`drop-shadow(0 0 4px ${warnColor})` }}/>;
        })()}
      </svg>
      <div className="pl-gauge-center">
        <div className="pl-gauge-val" style={{ color: warnColor }}>
          {typeof value === "number" ? value.toFixed(value < 10 ? 1 : 0) : value}
        </div>
        <div className="pl-gauge-unit">{unit}</div>
        <div className="pl-gauge-label">{label}</div>
      </div>
    </div>
  );
}

// ─── Node Topology ────────────────────────────────────────────────────────────
function NodeTopology({ liveData }) {
  const last = liveData[liveData.length - 1] || {};
  const nodeMetrics = [
    { ...NODES[0], cpu: last.cpu      ?? 40 },
    { ...NODES[1], cpu: last.mpiOps   ?? 60 },
    { ...NODES[2], cpu: last.memory   ?? 55 },
    { ...NODES[3], cpu: last.network  ?? 30 },
  ];
  return (
    <div className="pl-topology">
      <svg width="100%" height="260" viewBox="0 0 520 260" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="arrow" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="rgba(0,229,255,0.4)"/>
          </marker>
        </defs>
        {[[260,50,80,150],[260,50,440,150],[80,150,440,150],[80,150,260,210],[440,150,260,210]]
          .map(([x1,y1,x2,y2],i) => (
          <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
            stroke="rgba(0,229,255,0.15)" strokeWidth="1.5" strokeDasharray="6 4"
            markerEnd="url(#arrow)">
            <animate attributeName="stroke-dashoffset" values="20;0" dur="2s" repeatCount="indefinite"/>
          </line>
        ))}
        {[[260,50,80,150],[260,50,440,150]].map(([x1,y1,x2,y2],i) => (
          <circle key={i} r="4" fill="#00e5ff" opacity="0.8">
            <animateMotion dur={`${1.8+i*0.4}s`} repeatCount="indefinite"
              path={`M${x1},${y1} L${x2},${y2}`}/>
          </circle>
        ))}
        {[{x:260,y:50,n:nodeMetrics[0]},{x:80,y:150,n:nodeMetrics[1]},
          {x:440,y:150,n:nodeMetrics[2]},{x:260,y:210,n:nodeMetrics[3]}]
          .map(({ x, y, n }, i) => (
          <g key={i}>
            <circle cx={x} cy={y} r="32" fill="none" stroke={n.color} strokeWidth="1" opacity="0.2">
              <animate attributeName="r" values="30;40;30" dur={`${2+i*0.5}s`} repeatCount="indefinite"/>
              <animate attributeName="opacity" values="0.3;0;0.3" dur={`${2+i*0.5}s`} repeatCount="indefinite"/>
            </circle>
            <circle cx={x} cy={y} r="28" fill={`${n.color}15`} stroke={n.color} strokeWidth="2"
              style={{ filter:`drop-shadow(0 0 8px ${n.color}66)` }}/>
            <circle cx={x} cy={y} r="22" fill="none" stroke={n.color} strokeWidth="3"
              strokeLinecap="round"
              strokeDasharray={`${(n.cpu/100)*138} 138`}
              strokeDashoffset="34.5" opacity="0.6"/>
            <text x={x} y={y-4} textAnchor="middle" fill={n.color}
              fontSize="9" fontFamily="Share Tech Mono" fontWeight="700">{n.name}</text>
            <text x={x} y={y+8} textAnchor="middle" fill="rgba(255,255,255,0.5)"
              fontSize="8" fontFamily="Share Tech Mono">{n.cpu.toFixed(0)}%</text>
            <text x={x} y={y+19} textAnchor="middle" fill="rgba(255,255,255,0.3)"
              fontSize="7" fontFamily="Rajdhani" fontWeight="600">{n.role}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

// ─── Memory Map ───────────────────────────────────────────────────────────────
function MemoryMap() {
  return (
    <div className="pl-memmap">
      <div className="pl-memmap-bar">
        {MEMORY_SEGMENTS.map((s, i) => (
          <div key={i} className="pl-mem-seg"
            style={{ flex:s.pct, background:s.color }} title={`${s.label}: ${s.bytes}`}/>
        ))}
      </div>
      <div className="pl-memmap-legend">
        {MEMORY_SEGMENTS.map((s, i) => (
          <div key={i} className="pl-mem-leg-row">
            <div className="pl-mem-dot" style={{ background:s.color }}/>
            <span className="pl-mem-name">{s.label}</span>
            <span className="pl-mem-pct">{s.pct}%</span>
            <span className="pl-mem-bytes">{s.bytes}</span>
          </div>
        ))}
      </div>
      <div className="pl-memmap-total">
        TOTAL: <strong>4.00 GB</strong> · USED: <strong>3.32 GB (83%)</strong>
      </div>
    </div>
  );
}

// ─── Communication Matrix ─────────────────────────────────────────────────────
function CommMatrix() {
  const maxVal = Math.max(...COMM_MATRIX.flat().filter(v => v > 0));
  return (
    <div className="pl-matrix">
      <div className="pl-matrix-table">
        <div className="pl-mat-row">
          <div className="pl-mat-cell pl-mat-corner"/>
          {NODES.map(n => (
            <div key={n.id} className="pl-mat-hdr" style={{ color:n.color }}>N{n.id}</div>
          ))}
        </div>
        {COMM_MATRIX.map((row, ri) => (
          <div key={ri} className="pl-mat-row">
            <div className="pl-mat-hdr" style={{ color:NODES[ri].color }}>N{ri}</div>
            {row.map((val, ci) => {
              const intensity = val / maxVal;
              const bg = val === 0 ? "rgba(255,255,255,0.02)" : `rgba(0,229,255,${intensity*0.6})`;
              return (
                <div key={ci} className="pl-mat-cell" style={{ background:bg }}
                  title={`N${ri} → N${ci}: ${val} MB/s`}>
                  {val > 0
                    ? <span style={{ color:"#fff", opacity:0.6+intensity*0.4 }}>{val}</span>
                    : "—"}
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div className="pl-matrix-note">Values in MB/s · Inter-node MPI traffic</div>
    </div>
  );
}

// ─── Benchmark Panel ──────────────────────────────────────────────────────────
function BenchmarkPanel({ running, onRun }) {
  const [progress, setProgress] = useState(0);
  const [done,     setDone]     = useState(false);
  useEffect(() => {
    if (!running) { setProgress(0); setDone(false); return; }
    setDone(false);
    let p = 0;
    const t = setInterval(() => {
      p += rand(2, 6);
      if (p >= 100) { p = 100; setDone(true); clearInterval(t); }
      setProgress(p);
    }, 120);
    return () => clearInterval(t);
  }, [running]);
  const gradeColor = g => ({ "A+":"#00e5ff","A":"#76ff03","B+":"#ff6d00","B":"#ffa726" }[g] || "#aaa");
  return (
    <div className="pl-bench">
      {running && !done && (
        <div className="pl-bench-running">
          <div className="pl-bench-prog-bar">
            <div className="pl-bench-prog-fill" style={{ width:`${progress}%` }}/>
          </div>
          <div className="pl-bench-prog-label">RUNNING BENCHMARK SUITE... {progress}%</div>
        </div>
      )}
      <div className="pl-bench-results">
        {BENCHMARK_RESULTS.map((b, i) => (
          <div key={i} className="pl-bench-row" style={{ animationDelay:`${i*0.06}s` }}>
            <div className="pl-bench-test">{b.test}</div>
            <div className="pl-bench-score-wrap">
              <div className="pl-bench-bar-track">
                <div className="pl-bench-bar-fill"
                  style={{
                    width: done || !running
                      ? `${Math.min((b.score / (b.unit==="ms"?2:b.unit==="GB/s"?5:100))*100,100)}%`
                      : "0%",
                    background:`linear-gradient(90deg,${b.color}66,${b.color})`,
                    boxShadow:`0 0 8px ${b.color}55`,
                  }}/>
              </div>
              <div className="pl-bench-score" style={{ color:b.color }}>
                {b.score} <span className="pl-bench-unit">{b.unit}</span>
              </div>
            </div>
            <div className="pl-bench-grade"
              style={{ color:gradeColor(b.grade), borderColor:`${gradeColor(b.grade)}44` }}>
              {b.grade}
            </div>
          </div>
        ))}
      </div>
      <button className={`pl-run-btn ${running && !done ? "pl-run-running":""}`}
        onClick={onRun} disabled={running && !done}>
        {running && !done ? "⟳ BENCHMARKING..." : done ? "✓ RE-RUN BENCHMARK" : "▶ RUN BENCHMARK SUITE"}
      </button>
    </div>
  );
}

// ═══ MAIN PerformanceLab ══════════════════════════════════════════════════════
export default function PerformanceLab() {
  // ── Read settings from context INSIDE the component (this is the correct place) ──
  const { chartRefreshRate } = useUiConfig();
  const { processors }       = useMpiConfig();

  const [liveData,   setLiveData]   = useState(() => {
    const seed = generateTick(null);
    return Array.from({ length:30 }, (_, i) => ({
      ...generateTick(seed),
      label:`${String(i).padStart(2,"0")}:00`,
    }));
  });
  const [isPaused,   setIsPaused]   = useState(false);
  const [benchRun,   setBenchRun]   = useState(false);
  const [activeTab,  setActiveTab]  = useState("realtime");
  const [procFilter, setProcFilter] = useState("all");
  const intervalRef = useRef(null);

  // Live tick — uses chartRefreshRate from settings
  useEffect(() => {
    if (isPaused) return;
    intervalRef.current = setInterval(() => {
      setLiveData(prev => {
        const next = generateTick(prev[prev.length - 1]);
        return [...prev.slice(-59), next];
      });
    }, chartRefreshRate);
    return () => clearInterval(intervalRef.current);
  }, [isPaused, chartRefreshRate]);

  const last = liveData[liveData.length - 1] || {};
  const displayData = liveData.slice(-30);
  const filteredProcs = PROCESS_LOG.filter(p =>
    procFilter === "all" || p.status === procFilter
  );

  return (
    <div className="pl-page">

      {/* ── Header ── */}
      <div className="pl-header">
        <div>
          <div className="pl-title">Performance Lab</div>
          <div className="pl-subtitle">
            Real-time MPI cluster monitoring &amp; benchmarking · {processors} processors active
          </div>
        </div>
        <div className="pl-header-right">
          <div className="pl-live-badge">
            <div className={`pl-live-dot ${isPaused ? "pl-paused-dot":""}`}/>
            {isPaused ? "PAUSED" : "LIVE"}
          </div>
          <button className="pl-ctrl-btn" onClick={() => setIsPaused(v => !v)}>
            {isPaused ? "▶ Resume" : "⏸ Pause"}
          </button>
          <button className="pl-ctrl-btn pl-reset-btn" onClick={() => setLiveData([])}>↺ Reset</button>
        </div>
      </div>

      {/* ── Gauge Row ── */}
      <div className="pl-gauge-row">
        {[
          { label:"CPU",        value:last.cpu       ?? 40,  unit:"%",   color:"#00e5ff", max:100 },
          { label:"MEMORY",     value:last.memory    ?? 55,  unit:"%",   color:"#76ff03", max:100 },
          { label:"NETWORK I/O",value:last.network   ?? 30,  unit:"%",   color:"#ff6d00", max:100 },
          { label:"MPI OPS",    value:last.mpiOps    ?? 60,  unit:"%",   color:"#d500f9", max:100 },
          { label:"LATENCY",    value:last.latency   ?? 4,   unit:"ms",  color:"#ffea00", max:20  },
          { label:"THROUGHPUT", value:last.throughput?? 340, unit:"r/s", color:"#00e5ff", max:500 },
        ].map((g, i) => (
          <div key={i} className="pl-gauge-card" style={{ animationDelay:`${i*0.07}s` }}>
            <Gauge {...g} size={130}/>
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div className="pl-tabs">
        {[
          { id:"realtime",  label:"Real-time Charts" },
          { id:"topology",  label:"Node Topology"    },
          { id:"memory",    label:"Memory Map"       },
          { id:"processes", label:"Process Monitor"  },
          { id:"bench",     label:"Benchmarks"       },
        ].map(t => (
          <button key={t.id}
            className={`pl-tab ${activeTab===t.id?"pl-tab-active":""}`}
            onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══ REAL-TIME CHARTS ══════════════════════════════════════════════════ */}
      {activeTab === "realtime" && (
        <>
          <div className="pl-chart-grid-2">
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">CPU &amp; MEMORY UTILIZATION</div>
                <div className="pl-chart-legend">
                  <span className="pl-leg-dot" style={{ background:"#00e5ff" }}/>CPU
                  <span className="pl-leg-dot" style={{ background:"#76ff03", marginLeft:14 }}/>MEM
                </div>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <ComposedChart data={displayData} margin={{ top:10,right:20,left:-15,bottom:0 }}>
                  <defs>
                    <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#76ff03" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#76ff03" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false} interval={5}/>
                  <YAxis domain={[0,100]} tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTooltip/>}/>
                  <ReferenceLine y={80} stroke="#ff1744" strokeDasharray="4 4" strokeOpacity={0.4}/>
                  <Area type="monotone" dataKey="cpu"    stroke="#00e5ff" strokeWidth={2}
                    fill="url(#cpuGrad)" dot={false} name="CPU %"/>
                  <Area type="monotone" dataKey="memory" stroke="#76ff03" strokeWidth={2}
                    fill="url(#memGrad)" dot={false} name="MEM %"/>
                </ComposedChart>
              </ResponsiveContainer>
            </div>

            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">MPI OPS &amp; NETWORK I/O</div>
                <div className="pl-chart-legend">
                  <span className="pl-leg-dot" style={{ background:"#d500f9" }}/>MPI OPS
                  <span className="pl-leg-dot" style={{ background:"#ff6d00", marginLeft:14 }}/>NET I/O
                </div>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={displayData} margin={{ top:10,right:20,left:-15,bottom:0 }}>
                  <defs>
                    <linearGradient id="mpiGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#d500f9" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#d500f9" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="netGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ff6d00" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#ff6d00" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false} interval={5}/>
                  <YAxis domain={[0,100]} tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTooltip/>}/>
                  <Area type="monotone" dataKey="mpiOps"  stroke="#d500f9" strokeWidth={2}
                    fill="url(#mpiGrad)" dot={false} name="MPI Ops %"/>
                  <Area type="monotone" dataKey="network" stroke="#ff6d00" strokeWidth={2}
                    fill="url(#netGrad)" dot={false} name="Net I/O %"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="pl-chart-grid-2">
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">MPI REDUCE LATENCY (ms)</div>
                <div className={`pl-chart-badge ${(last.latency??4)>8?"badge-warn":"badge-ok"}`}>
                  {(last.latency??4)>8 ? "⚠ HIGH" : "✓ NORMAL"}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={displayData} margin={{ top:10,right:20,left:-15,bottom:0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false} interval={5}/>
                  <YAxis tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTooltip/>}/>
                  <ReferenceLine y={8} stroke="#ff6d00" strokeDasharray="4 4" strokeOpacity={0.5}
                    label={{ value:"Threshold", fill:"#ff6d00", fontSize:9, position:"right" }}/>
                  <Line type="monotone" dataKey="latency" stroke="#ffea00" strokeWidth={2}
                    dot={false} name="Latency ms"
                    style={{ filter:"drop-shadow(0 0 4px #ffea0088)" }}/>
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">LOG THROUGHPUT (records/sec)</div>
                <div className="pl-chart-badge badge-ok">
                  {(last.throughput??340).toFixed(0)} r/s
                </div>
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={displayData} margin={{ top:10,right:20,left:-15,bottom:0 }}>
                  <defs>
                    <linearGradient id="tpGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                    axisLine={false} tickLine={false} interval={5}/>
                  <YAxis tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTooltip/>}/>
                  <Area type="monotone" dataKey="throughput" stroke="#00e5ff" strokeWidth={2}
                    fill="url(#tpGrad)" dot={false} name="Throughput r/s"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </>
      )}

      {/* ══ NODE TOPOLOGY ═════════════════════════════════════════════════════ */}
      {activeTab === "topology" && (
        <div className="pl-topo-layout">
          <div className="pl-chart-card pl-topo-card">
            <div className="pl-chart-header">
              <div className="pl-chart-title">MPI NODE TOPOLOGY — LIVE</div>
              <div className="pl-chart-legend">
                {NODES.map(n => (
                  <span key={n.id} style={{ color:n.color, marginLeft:12, fontSize:12, fontFamily:"Rajdhani", fontWeight:700 }}>
                    ◉ {n.name}
                  </span>
                ))}
              </div>
            </div>
            <NodeTopology liveData={liveData}/>
          </div>
          <div className="pl-chart-card">
            <div className="pl-chart-header">
              <div className="pl-chart-title">INTER-NODE COMMUNICATION MATRIX</div>
            </div>
            <CommMatrix/>
          </div>
        </div>
      )}

      {/* ══ MEMORY MAP ════════════════════════════════════════════════════════ */}
      {activeTab === "memory" && (
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">HEAP MEMORY ALLOCATION MAP</div>
            <div className="pl-chart-badge badge-ok">4.00 GB TOTAL</div>
          </div>
          <MemoryMap/>
          <div className="pl-mem-timeline">
            <div className="pl-chart-title" style={{ marginBottom:14 }}>MEMORY PRESSURE OVER TIME</div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={displayData} margin={{ top:8,right:20,left:-15,bottom:0 }}>
                <defs>
                  <linearGradient id="memPressGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#76ff03" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#76ff03" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="label" tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                  axisLine={false} tickLine={false} interval={5}/>
                <YAxis domain={[0,100]} tick={{ fill:"rgba(255,255,255,0.2)",fontSize:9 }}
                  axisLine={false} tickLine={false}/>
                <Tooltip content={<PerfTooltip/>}/>
                <ReferenceLine y={90} stroke="#ff1744" strokeDasharray="4 4" strokeOpacity={0.4}/>
                <Area type="monotone" dataKey="memory" stroke="#76ff03" strokeWidth={2}
                  fill="url(#memPressGrad)" dot={false} name="Memory %"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ══ PROCESS MONITOR ═══════════════════════════════════════════════════ */}
      {activeTab === "processes" && (
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">MPI PROCESS MONITOR</div>
            <div className="pl-proc-filters">
              {["all","running","completed","waiting"].map(f => (
                <button key={f}
                  className={`pl-proc-filter ${procFilter===f?"pl-pf-active":""}`}
                  onClick={() => setProcFilter(f)}>
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <table className="pl-proc-table">
            <thead>
              <tr><th>PID</th><th>NODE</th><th>STATUS</th><th>CPU %</th><th>MEM (MB)</th><th>TASK</th><th>STARTED</th></tr>
            </thead>
            <tbody>
              {filteredProcs.map((p, i) => {
                const sc = { running:"#76ff03", completed:"#00e5ff", waiting:"#ffa726" };
                const nc = NODES.find(n => n.name === p.node)?.color ?? "#aaa";
                return (
                  <tr key={i} className="pl-proc-row">
                    <td className="pl-proc-pid">{p.pid}</td>
                    <td style={{ color:nc, fontFamily:"Share Tech Mono", fontSize:13 }}>{p.node}</td>
                    <td>
                      <span className="pl-status-badge"
                        style={{ background:`${sc[p.status]}18`, color:sc[p.status], border:`1px solid ${sc[p.status]}44` }}>
                        {p.status==="running" && <span className="pl-status-spin">◌ </span>}
                        {p.status}
                      </span>
                    </td>
                    <td>
                      {p.cpu > 0 ? (
                        <div className="pl-cpu-cell">
                          <div className="pl-cpu-bar">
                            <div style={{ width:`${p.cpu}%`, background:p.cpu>70?"#ff1744":"#00e5ff", height:"100%", borderRadius:2 }}/>
                          </div>
                          <span>{p.cpu}%</span>
                        </div>
                      ) : <span style={{ color:"rgba(255,255,255,0.2)" }}>—</span>}
                    </td>
                    <td style={{ fontFamily:"Share Tech Mono", fontSize:13, color:"rgba(255,255,255,0.6)" }}>
                      {p.mem > 0 ? p.mem : "—"}
                    </td>
                    <td style={{ fontSize:13, color:"rgba(255,255,255,0.7)", fontFamily:"Rajdhani", fontWeight:600 }}>{p.task}</td>
                    <td style={{ fontFamily:"Share Tech Mono", fontSize:12, color:"rgba(255,255,255,0.35)" }}>{p.start}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="pl-proc-footer">
            {PROCESS_LOG.filter(p=>p.status==="running").length} running ·{" "}
            {PROCESS_LOG.filter(p=>p.status==="completed").length} completed ·{" "}
            {PROCESS_LOG.filter(p=>p.status==="waiting").length} waiting
          </div>
        </div>
      )}

      {/* ══ BENCHMARKS ════════════════════════════════════════════════════════ */}
      {activeTab === "bench" && (
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">MPI BENCHMARK SUITE</div>
            <div className="pl-chart-badge badge-ok">{processors} NODES · PARALLEL</div>
          </div>
          <BenchmarkPanel running={benchRun} onRun={() => setBenchRun(v => !v || true)}/>
        </div>
      )}

    </div>
  );
}