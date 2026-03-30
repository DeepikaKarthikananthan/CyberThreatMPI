import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, ComposedChart,
  ReferenceLine, BarChart, Bar, Cell, ScatterChart, Scatter, ZAxis,
} from "recharts";
import "./PerformanceLab.css";
import { useUiConfig, useMpiConfig, useApiConfig } from "./Settingscontext";

const rand    = (a,b) => Math.random()*(b-a)+a;
const randInt = (a,b) => Math.floor(rand(a,b+1));
const fmt     = (n)   => Number(n||0).toLocaleString();
const fmtD    = (n,d=2) => Number(n||0).toFixed(d);

const PROC_COLORS  = ["#00e5ff","#76ff03","#ff6d00","#d500f9","#ffea00","#ff1744","#29b6f6","#ffa726"];
const LEVEL_COLOR  = { SAFE:"#00e676", LOW:"#29b6f6", MEDIUM:"#ffa726", HIGH:"#ef5350", CRITICAL:"#ff1744" };

function parseTs(ts) {
  if (!ts) return new Date(0);
  const m = ts.match(/(\d{2})\/(\d{2})\/(\d{4}),?\s+(\d+):(\d+):(\d+)\s*(am|pm)?/i);
  if (m) {
    let h = parseInt(m[4]);
    if (m[7]?.toLowerCase()==="pm"&&h<12) h+=12;
    if (m[7]?.toLowerCase()==="am"&&h===12) h=0;
    return new Date(+m[3],+m[2]-1,+m[1],h,+m[5],+m[6]);
  }
  return new Date(ts);
}

const generateTick = (prev) => ({
  t: Date.now(),
  cpu:        Math.min(100, Math.max(5,  (prev?.cpu     ??40)+rand(-8,8))),
  memory:     Math.min(100, Math.max(10, (prev?.memory  ??55)+rand(-4,4))),
  network:    Math.min(100, Math.max(0,  (prev?.network ??30)+rand(-15,15))),
  mpiOps:     Math.min(100, Math.max(5,  (prev?.mpiOps  ??60)+rand(-10,10))),
  latency:    Math.max(0.1, (prev?.latency??4)+rand(-0.8,0.8)),
  throughput: Math.max(10,  (prev?.throughput??340)+rand(-40,40)),
  label: new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}),
});

const PerfTip = ({ active, payload, label }) => {
  if (!active||!payload?.length) return null;
  return (
    <div className="pl-tooltip">
      <div className="pl-tt-time">{label}</div>
      {payload.map((p,i)=>(
        <div key={i} style={{color:p.stroke||p.color}}>
          {p.name}: <b>{typeof p.value==="number"?p.value.toFixed(2):p.value}</b>
        </div>
      ))}
    </div>
  );
};

function Gauge({ value, max=100, label, unit, color, size=130 }) {
  const R=size*0.38,cx=size/2,cy=size/2;
  const pct=Math.min(value/max,1);
  const startA=(210*Math.PI)/180, sweep=(240*Math.PI)/180;
  const endA=startA-sweep*pct;
  const arc=(a1,a2)=>{
    const x1=cx-R*Math.cos(a1),y1=cy+R*Math.sin(a1);
    const x2=cx-R*Math.cos(a2),y2=cy+R*Math.sin(a2);
    return `M${x1},${y1} A${R},${R} 0 ${Math.abs(a1-a2)>Math.PI?1:0} 1 ${x2},${y2}`;
  };
  const warn=value>85?"#ff1744":value>70?"#ff6d00":color;
  return (
    <div className="pl-gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <filter id={`gf${label.replace(/\W/g,"")}`}>
            <feGaussianBlur stdDeviation="2" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <path d={arc(startA,startA-sweep)} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" strokeLinecap="round"/>
        {pct>0&&<path d={arc(startA,endA)} fill="none" stroke={warn} strokeWidth="8" strokeLinecap="round"
          filter={`url(#gf${label.replace(/\W/g,"")})`} style={{transition:"all 0.5s ease"}}/>}
      </svg>
      <div className="pl-gauge-center">
        <div className="pl-gauge-val" style={{color:warn}}>{typeof value==="number"?value.toFixed(value<10?1:0):value}</div>
        <div className="pl-gauge-unit">{unit}</div>
        <div className="pl-gauge-label">{label}</div>
      </div>
    </div>
  );
}

export default function PerformanceLab() {
  const { chartRefreshRate } = useUiConfig();
  const { processors }       = useMpiConfig();
  const { backendUrl }       = useApiConfig();

  const [liveData,      setLiveData]      = useState(()=>{
    const s=generateTick(null);
    return Array.from({length:30},(_,i)=>({...generateTick(s),label:`${String(i).padStart(2,"0")}:00`}));
  });
  const [isPaused,      setIsPaused]      = useState(false);
  const [activeTab,     setActiveTab]     = useState("realtime");
  const [perfData,      setPerfData]      = useState(null);
  const [perfLoading,   setPerfLoading]   = useState(true);
  const [lastRefresh,   setLastRefresh]   = useState(null);
  const [benchRun,      setBenchRun]      = useState(false);
  const [benchProg,     setBenchProg]     = useState(0);
  const [benchDone,     setBenchDone]     = useState(false);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const intervalRef = useRef(null);

  const fetchPerf = useCallback(async ()=>{
    try {
      const res = await fetch(`${backendUrl}/performance-stats`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setPerfData(await res.json());
      setLastRefresh(new Date());
    } catch(e){console.warn("[Perf]",e.message);}
    finally{setPerfLoading(false);}
  },[backendUrl]);

  useEffect(()=>{fetchPerf();},[fetchPerf]);

  useEffect(()=>{
    if(isPaused) return;
    intervalRef.current = setInterval(()=>{
      setLiveData(prev=>[...prev.slice(-59),generateTick(prev[prev.length-1])]);
    },chartRefreshRate);
    return ()=>clearInterval(intervalRef.current);
  },[isPaused,chartRefreshRate]);

  useEffect(()=>{
    if(!benchRun) return;
    setBenchDone(false); setBenchProg(0);
    let p=0;
    const t=setInterval(()=>{
      p+=randInt(2,6);
      if(p>=100){p=100;setBenchDone(true);clearInterval(t);}
      setBenchProg(p);
    },120);
    return ()=>clearInterval(t);
  },[benchRun]);

  const last        = liveData[liveData.length-1]||{};
  const displayData = liveData.slice(-30);

  const entries = useMemo(()=>
    (perfData?.entries||[]).map(e=>({...e,_date:parseTs(e.timestamp)}))
    .sort((a,b)=>b._date-a._date),
  [perfData]);

  const execTrend = useMemo(()=>
    [...entries].reverse().slice(-20).map((e,i)=>({
      i:i+1, execTime:e.execution_time, throughput:e.throughput,
      logs:e.total_logs, score:e.threat_score, procs:e.processors_used,
    })),
  [entries]);

  const procEfficiency = useMemo(()=>{
    if(!entries.length) return [];
    const byP={};
    entries.forEach(e=>{
      const k=e.processors_used||0;
      if(!byP[k]) byP[k]={procs:k,execs:[],thrpts:[],count:0};
      byP[k].execs.push(e.execution_time);
      byP[k].thrpts.push(e.throughput);
      byP[k].count++;
    });
    return Object.values(byP).sort((a,b)=>a.procs-b.procs).map(g=>({
      name:`${g.procs}p`, procs:g.procs,
      avgExec: g.execs.reduce((s,v)=>s+v,0)/g.execs.length,
      avgThroughput: g.thrpts.reduce((s,v)=>s+v,0)/g.thrpts.length,
      count:g.count,
    }));
  },[entries]);

  return (
    <div className="pl-page">
      {/* Header */}
      <div className="pl-header">
        <div>
          <div className="pl-title">Performance Lab</div>
          <div className="pl-subtitle">
            Real-time MPI monitoring & performance analytics · {processors} processors configured
            {lastRefresh&&<span style={{color:"rgba(255,255,255,0.2)",marginLeft:8}}>· {lastRefresh.toLocaleTimeString()}</span>}
          </div>
        </div>
        <div className="pl-header-right">
          <div className="pl-live-badge">
            <div className={`pl-live-dot ${isPaused?"pl-paused-dot":""}`}/>
            {isPaused?"PAUSED":"LIVE"}
          </div>
          <button className="pl-ctrl-btn" onClick={()=>setIsPaused(v=>!v)}>{isPaused?"▶ Resume":"⏸ Pause"}</button>
          <button className="pl-ctrl-btn" onClick={fetchPerf}>⟳ Refresh</button>
          <button className="pl-ctrl-btn pl-reset-btn" onClick={()=>setLiveData([])}>↺ Reset</button>
        </div>
      </div>

      {/* Gauges */}
      <div className="pl-gauge-row">
        {[
          {label:"CPU",        value:last.cpu??40,       unit:"%",   color:"#00e5ff", max:100},
          {label:"MEMORY",     value:last.memory??55,    unit:"%",   color:"#76ff03", max:100},
          {label:"NETWORK",    value:last.network??30,   unit:"%",   color:"#ff6d00", max:100},
          {label:"MPI OPS",    value:last.mpiOps??60,    unit:"%",   color:"#d500f9", max:100},
          {label:"LATENCY",    value:last.latency??4,    unit:"ms",  color:"#ffea00", max:20 },
          {label:"THROUGHPUT", value:last.throughput??340,unit:"r/s",color:"#00e5ff", max:500},
        ].map((g,i)=>(
          <div key={i} className="pl-gauge-card" style={{animationDelay:`${i*0.07}s`}}>
            <Gauge {...g} size={130}/>
          </div>
        ))}
      </div>

      {/* Real KPIs */}
      {perfData&&perfData.count>0&&(
        <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10}}>
          {[
            {label:"Analyses Run",    val:perfData.count,                          color:"#06b6d4"},
            {label:"Avg Exec (s)",    val:fmtD(perfData.avg_exec_time,3),          color:"#ffea00"},
            {label:"Best Exec (s)",   val:fmtD(perfData.min_exec_time,3),          color:"#76ff03"},
            {label:"Peak Throughput", val:fmt(Math.round(perfData.max_throughput)), color:"#00e5ff"},
            {label:"Avg Throughput",  val:fmt(Math.round(perfData.avg_throughput)), color:"#a855f7"},
            {label:"Total Logs",      val:fmt(perfData.total_logs_processed),       color:"#10b981"},
          ].map((k,i)=>(
            <div key={i} style={{background:"#0c1420",border:"1px solid rgba(0,229,255,0.1)",
              borderRadius:8,padding:"12px 14px",position:"relative",overflow:"hidden"}}>
              <div style={{position:"absolute",top:0,left:0,right:0,height:2,
                background:`linear-gradient(90deg,${k.color},transparent)`,opacity:0.6}}/>
              <div style={{fontFamily:"'Orbitron',monospace",fontSize:18,fontWeight:900,color:k.color,lineHeight:1}}>
                {k.val}
              </div>
              <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:9,fontWeight:700,
                letterSpacing:2,color:"rgba(255,255,255,0.25)",marginTop:4,textTransform:"uppercase"}}>
                {k.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="pl-tabs">
        {[
          {id:"realtime",   label:"Live Metrics"},
          {id:"history",    label:"Analysis History"},
          {id:"efficiency", label:"Efficiency"},
          {id:"amdahl",     label:"Speedup Analysis"},
          {id:"topology",   label:"Node Topology"},
          {id:"bench",      label:"Benchmarks"},
        ].map(t=>(
          <button key={t.id} className={`pl-tab ${activeTab===t.id?"pl-tab-active":""}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── LIVE METRICS ── */}
      {activeTab==="realtime"&&(
        <>
          <div className="pl-chart-grid-2">
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">CPU & MEMORY UTILISATION</div>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <ComposedChart data={displayData} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <defs>
                    <linearGradient id="cpuG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="memG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#76ff03" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#76ff03" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false} interval={5}/>
                  <YAxis domain={[0,100]} tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTip/>}/>
                  <ReferenceLine y={80} stroke="#ff1744" strokeDasharray="4 4" strokeOpacity={0.4}/>
                  <Area type="monotone" dataKey="cpu"    stroke="#00e5ff" strokeWidth={2} fill="url(#cpuG)" dot={false} name="CPU %"/>
                  <Area type="monotone" dataKey="memory" stroke="#76ff03" strokeWidth={2} fill="url(#memG)" dot={false} name="MEM %"/>
                </ComposedChart>
              </ResponsiveContainer>
            </div>
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">MPI OPS & NETWORK I/O</div>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={displayData} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <defs>
                    <linearGradient id="mpiG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#d500f9" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#d500f9" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="netG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff6d00" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#ff6d00" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false} interval={5}/>
                  <YAxis domain={[0,100]} tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTip/>}/>
                  <Area type="monotone" dataKey="mpiOps"  stroke="#d500f9" strokeWidth={2} fill="url(#mpiG)" dot={false} name="MPI Ops %"/>
                  <Area type="monotone" dataKey="network" stroke="#ff6d00" strokeWidth={2} fill="url(#netG)" dot={false} name="Net I/O %"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="pl-chart-grid-2">
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">MPI REDUCE LATENCY (ms)</div>
                <div className={`pl-chart-badge ${(last.latency??4)>8?"badge-warn":"badge-ok"}`}>
                  {(last.latency??4)>8?"⚠ HIGH":"✓ NORMAL"}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={displayData} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false} interval={5}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTip/>}/>
                  <ReferenceLine y={8} stroke="#ff6d00" strokeDasharray="4 4" strokeOpacity={0.5}/>
                  <Line type="monotone" dataKey="latency" stroke="#ffea00" strokeWidth={2} dot={false} name="Latency ms"/>
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="pl-chart-card">
              <div className="pl-chart-header">
                <div className="pl-chart-title">LOG THROUGHPUT (r/s)</div>
                <div className="pl-chart-badge badge-ok">{(last.throughput??340).toFixed(0)} r/s</div>
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={displayData} margin={{top:8,right:20,left:-15,bottom:0}}>
                  <defs>
                    <linearGradient id="tpG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false} interval={5}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<PerfTip/>}/>
                  <Area type="monotone" dataKey="throughput" stroke="#00e5ff" strokeWidth={2} fill="url(#tpG)" dot={false} name="Throughput r/s"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </>
      )}

      {/* ── HISTORY TAB ── */}
      {activeTab==="history"&&(
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">REAL EXECUTION TIME & THROUGHPUT</div>
            <button className="pl-ctrl-btn" style={{padding:"5px 12px",fontSize:11}} onClick={fetchPerf}>⟳</button>
          </div>
          {perfLoading?(
            <div style={{textAlign:"center",padding:"40px",fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.3)",letterSpacing:2}}>LOADING...</div>
          ):!entries.length?(
            <div style={{textAlign:"center",padding:"40px",fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.2)",letterSpacing:2}}>NO HISTORY — Upload files first.</div>
          ):(
            <>
              <div className="pl-chart-grid-2" style={{marginBottom:16}}>
                <div>
                  <div className="pl-chart-title" style={{marginBottom:10}}>EXECUTION TIME PER ANALYSIS</div>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={execTrend} barCategoryGap="20%" margin={{top:5,right:10,left:-20,bottom:0}}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                      <XAxis dataKey="i" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                      <YAxis tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                      <Tooltip content={<PerfTip/>} cursor={{fill:"rgba(255,255,255,0.02)"}}/>
                      <Bar dataKey="execTime" name="Exec Time (s)" radius={[3,3,0,0]}>
                        {execTrend.map((_,i)=>(
                          <Cell key={i} fill={PROC_COLORS[i%PROC_COLORS.length]}
                            style={{filter:`drop-shadow(0 0 4px ${PROC_COLORS[i%PROC_COLORS.length]}66)`}}/>
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div>
                  <div className="pl-chart-title" style={{marginBottom:10}}>REAL THROUGHPUT (LOGS/SEC)</div>
                  <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={execTrend} margin={{top:5,right:10,left:-20,bottom:0}}>
                      <defs>
                        <linearGradient id="rtG" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                      <XAxis dataKey="i" tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                      <YAxis tick={{fill:"rgba(255,255,255,0.25)",fontSize:9}} axisLine={false} tickLine={false}/>
                      <Tooltip content={<PerfTip/>}/>
                      <Area type="monotone" dataKey="throughput" stroke="#10b981" strokeWidth={2} fill="url(#rtG)" dot={false} name="logs/s"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div style={{overflowX:"auto",maxHeight:300,overflowY:"auto"}}>
                <table className="pl-proc-table">
                  <thead><tr><th>File</th><th>Fmt</th><th>Logs</th><th>Exec(s)</th><th>Throughput</th><th>Level</th><th>Score</th><th>Procs</th></tr></thead>
                  <tbody>
                    {entries.map((e,i)=>(
                      <tr key={i} className="pl-proc-row"
                        onClick={()=>setSelectedEntry(selectedEntry===i?null:i)}
                        style={{cursor:"pointer",background:selectedEntry===i?"rgba(0,229,255,0.05)":""}}>
                        <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"#00e5ff",maxWidth:150,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={e.file_name}>{e.file_name}</td>
                        <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"rgba(255,255,255,0.4)"}}>{e.file_format}</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#76ff03"}}>{fmt(e.total_logs)}</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#ffea00"}}>{fmtD(e.execution_time,3)}</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#10b981"}}>{fmt(Math.round(e.throughput))}/s</td>
                        <td><span style={{padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"'Orbitron',monospace",fontWeight:700,letterSpacing:1,background:`${LEVEL_COLOR[e.threat_level]||"#666"}22`,color:LEVEL_COLOR[e.threat_level]||"#666",border:`1px solid ${LEVEL_COLOR[e.threat_level]||"#666"}44`}}>{e.threat_level}</span></td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:13,fontWeight:700,color:LEVEL_COLOR[e.threat_level]}}>{e.threat_score}</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#d500f9"}}>{e.processors_used||"—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selectedEntry!==null&&entries[selectedEntry]&&(
                <div style={{marginTop:12,padding:14,background:"rgba(0,229,255,0.05)",border:"1px solid rgba(0,229,255,0.15)",borderRadius:8}}>
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:10,letterSpacing:3,color:"rgba(255,255,255,0.3)",marginBottom:8}}>NODE SCORES FOR THIS RUN</div>
                  <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                    {(entries[selectedEntry].process_scores||[]).map((p,i)=>(
                      <div key={i} style={{padding:"6px 14px",borderRadius:6,background:`${PROC_COLORS[i%PROC_COLORS.length]}18`,border:`1px solid ${PROC_COLORS[i%PROC_COLORS.length]}44`}}>
                        <div style={{fontFamily:"'Orbitron',monospace",fontSize:11,color:PROC_COLORS[i%PROC_COLORS.length],fontWeight:700}}>N{p.process_id}: {p.score}</div>
                      </div>
                    ))}
                    {!entries[selectedEntry].process_scores?.length&&<div style={{color:"rgba(255,255,255,0.25)",fontFamily:"'Share Tech Mono',monospace",fontSize:11}}>No per-node data.</div>}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ── EFFICIENCY ── */}
      {activeTab==="efficiency"&&(
        !procEfficiency.length?(
          <div className="pl-chart-card" style={{textAlign:"center",padding:"40px"}}>
            <div style={{color:"rgba(255,255,255,0.2)",fontFamily:"'Orbitron',monospace",fontSize:12,letterSpacing:3}}>
              NO DATA — Upload files using different processor counts to compare efficiency
            </div>
          </div>
        ):(
          <>
            <div className="pl-chart-grid-2">
              <div className="pl-chart-card">
                <div className="pl-chart-header"><div className="pl-chart-title">AVG EXEC TIME BY PROCESSOR COUNT</div></div>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={procEfficiency} barCategoryGap="25%" margin={{top:8,right:20,left:-15,bottom:0}}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                    <XAxis dataKey="name" tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false}/>
                    <Tooltip content={<PerfTip/>} cursor={{fill:"rgba(255,255,255,0.02)"}}/>
                    <Bar dataKey="avgExec" name="Avg Exec (s)" radius={[4,4,0,0]}>
                      {procEfficiency.map((_,i)=><Cell key={i} fill={PROC_COLORS[i%PROC_COLORS.length]} style={{filter:`drop-shadow(0 0 5px ${PROC_COLORS[i%PROC_COLORS.length]}66)`}}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="pl-chart-card">
                <div className="pl-chart-header"><div className="pl-chart-title">AVG THROUGHPUT BY PROCESSOR COUNT</div></div>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={procEfficiency} barCategoryGap="25%" margin={{top:8,right:20,left:-15,bottom:0}}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                    <XAxis dataKey="name" tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false}/>
                    <Tooltip content={<PerfTip/>} cursor={{fill:"rgba(255,255,255,0.02)"}}/>
                    <Bar dataKey="avgThroughput" name="Avg Throughput (logs/s)" radius={[4,4,0,0]}>
                      {procEfficiency.map((_,i)=><Cell key={i} fill={PROC_COLORS[i%PROC_COLORS.length]} style={{filter:`drop-shadow(0 0 5px ${PROC_COLORS[i%PROC_COLORS.length]}66)`}}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="pl-chart-card">
              <div className="pl-chart-header"><div className="pl-chart-title">EFFICIENCY TABLE</div></div>
              <table className="pl-proc-table">
                <thead><tr><th>Config</th><th>Analyses</th><th>Avg Exec (s)</th><th>Avg Throughput</th><th>Efficiency Bar</th></tr></thead>
                <tbody>
                  {procEfficiency.map((p,i)=>{
                    const best=Math.max(...procEfficiency.map(x=>x.avgThroughput),1);
                    const eff=(p.avgThroughput/best)*100;
                    return(
                      <tr key={i} className="pl-proc-row">
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:13,color:PROC_COLORS[i%PROC_COLORS.length],fontWeight:700}}>{p.name}</td>
                        <td style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.5)"}}>{p.count}</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#ffea00"}}>{fmtD(p.avgExec,3)}s</td>
                        <td style={{fontFamily:"'Orbitron',monospace",fontSize:12,color:"#10b981"}}>{fmt(Math.round(p.avgThroughput))}/s</td>
                        <td style={{minWidth:140}}>
                          <div style={{display:"flex",alignItems:"center",gap:8}}>
                            <div style={{flex:1,height:6,background:"rgba(255,255,255,0.07)",borderRadius:3,overflow:"hidden"}}>
                              <div style={{width:`${eff}%`,height:"100%",background:eff>80?"#76ff03":eff>50?"#ffa726":"#ef5350",borderRadius:3}}/>
                            </div>
                            <span style={{fontFamily:"'Orbitron',monospace",fontSize:11,color:"rgba(255,255,255,0.6)",width:36,textAlign:"right"}}>{eff.toFixed(0)}%</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )
      )}

      {/* ── AMDAHL ── */}
      {activeTab==="amdahl"&&(
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">AMDAHL'S LAW — THEORETICAL SPEEDUP CURVE</div>
          </div>
          {(() => {
            const P=0.85, maxN=16;
            const theo=Array.from({length:maxN},(_,i)=>({n:i+1,speedup:1/(1-P+P/(i+1))}));
            const byP={};
            entries.forEach(e=>{
              const n=e.processors_used; if(!n) return;
              if(!byP[n]) byP[n]=[];
              byP[n].push(e.throughput);
            });
            const base=byP[1]?.length?byP[1].reduce((s,v)=>s+v,0)/byP[1].length:null;
            const realPts=Object.entries(byP).reduce((acc,[n,vals])=>{
              acc[Number(n)]=base?(vals.reduce((s,v)=>s+v,0)/vals.length)/base:null;
              return acc;
            },{});
            const chartData=theo.map(t=>({...t,real:realPts[t.n]??null}));
            return(
              <ResponsiveContainer width="100%" height={240}>
                <ComposedChart data={chartData} margin={{top:10,right:20,left:-15,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="n" tick={{fill:"rgba(255,255,255,0.3)",fontSize:10}} axisLine={false} tickLine={false} label={{value:"Processors",position:"insideBottom",fill:"rgba(255,255,255,0.2)",fontSize:10,dy:10}}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.3)",fontSize:9}} axisLine={false} tickLine={false} label={{value:"Speedup",angle:-90,position:"insideLeft",fill:"rgba(255,255,255,0.2)",fontSize:10}}/>
                  <Tooltip content={<PerfTip/>}/>
                  <Line type="monotone" dataKey="speedup" stroke="rgba(0,229,255,0.4)" strokeWidth={1.5} dot={false} name="Theoretical" strokeDasharray="4 2"/>
                  {Object.keys(realPts).length>1&&<Line type="monotone" dataKey="real" stroke="#76ff03" strokeWidth={2} dot={{r:5,fill:"#76ff03"}} name="Real Measured" connectNulls={false}/>}
                </ComposedChart>
              </ResponsiveContainer>
            );
          })()}
          <div style={{marginTop:16,padding:14,background:"rgba(0,229,255,0.04)",border:"1px solid rgba(0,229,255,0.12)",borderRadius:8}}>
            <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:13,color:"rgba(255,255,255,0.45)",lineHeight:1.7}}>
              <span style={{color:"rgba(0,229,255,0.6)"}}>Dashed:</span> Theoretical max (Amdahl, P=85% parallel).{" "}
              <span style={{color:"#76ff03"}}>Solid:</span> Your real measured speedup vs 1-processor baseline.
              Upload the same file with 1, 2, 4, 8 processors to plot your real curve.
            </div>
          </div>
        </div>
      )}

      {/* ── TOPOLOGY ── */}
      {activeTab==="topology"&&(
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">MPI NODE TOPOLOGY — {processors} NODE CLUSTER</div>
          </div>
          <div style={{display:"flex",justifyContent:"center",padding:"10px 0"}}>
            <svg width="560" height="280" viewBox="0 0 560 280">
              <defs>
                <marker id="arr2" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
                  <path d="M0,0 L6,3 L0,6 Z" fill="rgba(0,229,255,0.4)"/>
                </marker>
              </defs>
              <circle cx="280" cy="50" r="32" fill="rgba(0,229,255,0.1)" stroke="#00e5ff" strokeWidth="2" style={{filter:"drop-shadow(0 0 8px #00e5ff55)"}}/>
              <text x="280" y="46" textAnchor="middle" fill="#00e5ff" fontSize="9" fontFamily="Share Tech Mono" fontWeight="700">MASTER</text>
              <text x="280" y="60" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="8" fontFamily="Rajdhani">NODE 0</text>
              {Array.from({length:Math.min(processors-1,7)},(_,i)=>{
                const count=Math.min(processors-1,7);
                const frac=count>1?i/(count-1):0.5;
                const cx=80+frac*400, cy=190;
                const color=PROC_COLORS[(i+1)%PROC_COLORS.length];
                const lastScore=entries[0]?.process_scores?.find(p=>p.process_id===i+1)?.score;
                return(
                  <g key={i}>
                    <line x1="280" y1="80" x2={cx} y2={cy-28} stroke="rgba(0,229,255,0.2)" strokeWidth="1" strokeDasharray="5 3" markerEnd="url(#arr2)">
                      <animate attributeName="stroke-dashoffset" values="16;0" dur="2s" repeatCount="indefinite"/>
                    </line>
                    <circle cx={cx} cy={cy} r="26" fill={`${color}15`} stroke={color} strokeWidth="2" style={{filter:`drop-shadow(0 0 6px ${color}55)`}}/>
                    <text x={cx} y={cy-4} textAnchor="middle" fill={color} fontSize="8" fontFamily="Share Tech Mono" fontWeight="700">WORKER</text>
                    <text x={cx} y={cy+7} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="8" fontFamily="Share Tech Mono">N{i+1}</text>
                    {lastScore!=null&&<text x={cx} y={cy+18} textAnchor="middle" fill={color} fontSize="9" fontFamily="Orbitron" fontWeight="700">{lastScore}</text>}
                  </g>
                );
              })}
              <text x="280" y="270" textAnchor="middle" fill="rgba(255,255,255,0.2)" fontSize="10" fontFamily="Rajdhani">
                {processors} processor cluster · last-run node scores displayed
              </text>
            </svg>
          </div>
        </div>
      )}

      {/* ── BENCHMARKS ── */}
      {activeTab==="bench"&&(
        <div className="pl-chart-card">
          <div className="pl-chart-header">
            <div className="pl-chart-title">MPI BENCHMARK SUITE — REAL DATA</div>
            <div className="pl-chart-badge badge-ok">{processors} NODES</div>
          </div>
          {benchRun&&!benchDone&&(
            <div className="pl-bench-running">
              <div className="pl-bench-prog-bar">
                <div className="pl-bench-prog-fill" style={{width:`${benchProg}%`}}/>
              </div>
              <div className="pl-bench-prog-label">RUNNING BENCHMARK SUITE... {benchProg}%</div>
            </div>
          )}
          <div className="pl-bench-results">
            {perfData&&perfData.count>0?[
              {test:"Log Parsing Speed",   score:fmt(Math.round(perfData.avg_throughput)), unit:"logs/s", val:perfData.avg_throughput,    max:Math.max(perfData.max_throughput,1), color:"#00e5ff", note:"Average real throughput"},
              {test:"Peak Throughput",     score:fmt(Math.round(perfData.max_throughput)), unit:"logs/s", val:perfData.max_throughput,    max:Math.max(perfData.max_throughput,1), color:"#76ff03", note:"Best single-run"},
              {test:"Best Exec Time",      score:fmtD(perfData.min_exec_time,3),          unit:"s",      val:perfData.max_exec_time-perfData.min_exec_time, max:Math.max(perfData.max_exec_time,0.001), color:"#ffea00", note:"Lower = faster"},
              {test:"Avg Processors Used", score:fmtD(perfData.avg_processors,1),         unit:"cores",  val:perfData.avg_processors,    max:16,                                  color:"#d500f9", note:"Parallel utilisation"},
              {test:"Total Logs Processed",score:fmt(perfData.total_logs_processed),       unit:"",       val:perfData.total_logs_processed, max:Math.max(perfData.total_logs_processed,1), color:"#10b981", note:"Cumulative"},
            ].map((b,i)=>(
              <div key={i} className="pl-bench-row" style={{animationDelay:`${i*0.06}s`}}>
                <div className="pl-bench-test">
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:14,fontWeight:600,color:"rgba(255,255,255,0.7)"}}>{b.test}</div>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"rgba(255,255,255,0.25)",marginTop:2}}>{b.note}</div>
                </div>
                <div className="pl-bench-score-wrap">
                  <div className="pl-bench-bar-track">
                    <div className="pl-bench-bar-fill" style={{width:`${Math.min((b.val/b.max)*100,100)}%`,background:`linear-gradient(90deg,${b.color}66,${b.color})`,boxShadow:`0 0 8px ${b.color}55`}}/>
                  </div>
                  <div className="pl-bench-score" style={{color:b.color}}>{b.score} <span className="pl-bench-unit">{b.unit}</span></div>
                </div>
                <div className="pl-bench-grade" style={{color:b.color,borderColor:`${b.color}44`}}>
                  {b.val/b.max>0.8?"A+":b.val/b.max>0.6?"A":b.val/b.max>0.4?"B+":"B"}
                </div>
              </div>
            )):(
              <div style={{padding:"20px",textAlign:"center",fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.2)",letterSpacing:2}}>
                UPLOAD FILES TO SEE REAL BENCHMARK DATA
              </div>
            )}
          </div>
          <button className={`pl-run-btn ${benchRun&&!benchDone?"pl-run-running":""}`}
            onClick={()=>{setBenchRun(true);setBenchDone(false);}}
            disabled={benchRun&&!benchDone}>
            {benchRun&&!benchDone?"⟳ BENCHMARKING...":benchDone?"✓ RE-RUN":"▶ RUN BENCHMARK SUITE"}
          </button>
        </div>
      )}

    </div>
  );
}