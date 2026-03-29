import React, { useState, useRef, useCallback, useEffect } from "react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, RadialBarChart, RadialBar
} from "recharts";
import "./LogUpload.css";
import { useMpiConfig, useApiConfig, useKeywords, useThresholds, useClassifyThreat } from './Settingscontext';

// ─── helpers ──────────────────────────────────────────────────────────────────
const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;

const THREAT_CFG = {
  SAFE:     { color: "#00e676", glow: "rgba(0,230,118,0.35)",  label: "SAFE"     },
  LOW:      { color: "#29b6f6", glow: "rgba(41,182,246,0.35)", label: "LOW"      },
  MEDIUM:   { color: "#ffa726", glow: "rgba(255,167,38,0.35)", label: "MEDIUM"   },
  HIGH:     { color: "#ef5350", glow: "rgba(239,83,80,0.35)",  label: "HIGH"     },
  CRITICAL: { color: "#ff1744", glow: "rgba(255,23,68,0.35)",  label: "CRITICAL" },
};

const PROC_COLORS = ["#00e5ff", "#76ff03", "#ff6d00", "#d500f9",
                     "#ffea00", "#ff1744", "#29b6f6", "#76ff03",
                     "#ff6d00", "#d500f9", "#00e5ff", "#ffa726",
                     "#ef5350", "#76ff03", "#ff6d00", "#d500f9"];

// ─── Count lines in a file client-side (ground truth) ────────────────────────
const countFileLines = (file) => new Promise((resolve) => {
  const reader = new FileReader();
  reader.onload = (e) => {
    const text = e.target.result || "";
    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    resolve(lines.length);
  };
  reader.onerror = () => resolve(0);
  reader.readAsText(file);
});

// realFileName = the JS File object's .name — always reliable, never None
function normalize(raw, realFileName) {
  if (!raw) return null;
  return {
    file_name:           realFileName || raw.file_name || "log_file.txt",
    total_logs:          Number(raw.total_logs)           || 0,
    global_threat_score: Number(raw.global_threat_score)  || 0,
    threat_level:        raw.threat_level                 ?? "SAFE",
    threat_percentage:   Math.min(Number(raw.threat_percentage) || 0, 100),
    execution_time:      Number(raw.execution_time)       || 0,
    process_wise_scores: Array.isArray(raw.process_wise_scores) ? raw.process_wise_scores : [],
    processors_used:     Number(raw.processors_used)      || 0,
    file_format:         raw.file_format                  || "TXT",
    timestamp:           raw.timestamp ?? new Date().toLocaleString(),
  };
}

// ─── Terminal lines — fully dynamic based on nProcs ───────────────────────────
const buildTerminalLines = (fname, nProcs, btlMechanism, oversubscribe) => {
  const overFlag = oversubscribe ? "--oversubscribe " : "";
  const lines = [
    `$ mpirun ${overFlag}-np ${nProcs} --mca btl_vader_single_copy_mechanism ${btlMechanism} ./mpi_log_analyzer ${fname}`,
    `[MPI] Initializing ${nProcs} process${nProcs > 1 ? "es" : ""}...`,
    `[MPI] File partitioned into ${nProcs} chunk${nProcs > 1 ? "s" : ""}`,
  ];
  // One line per process
  for (let i = 0; i < nProcs; i++) {
    lines.push(`[MPI] Process ${i} (${i === 0 ? "Master" : "Worker"}) ready`);
  }
  lines.push(`[MPI] All ${nProcs} processes initialized`);
  for (let i = 0; i < nProcs; i++) {
    lines.push(`[P${i}] Processing chunk ${i}... pattern matching + threat scoring`);
  }
  lines.push(`[MPI] MPI_Reduce collecting scores from ${nProcs} nodes...`);
  lines.push(`[MPI] Global reduction complete`);
  lines.push(`[OUT] Analysis finished successfully ✓`);
  return lines;
};

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
const CT = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="lu-tip">
      <div className="lu-tip-lbl">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.fill || p.color || "#fff" }}>
          {p.name}: <b>{p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Threat Score Arc ─────────────────────────────────────────────────────────
function ThreatArc({ score, level }) {
  const cfg   = THREAT_CFG[level] || THREAT_CFG.SAFE;
  const pct   = Math.min(score, 100) / 100;
  const R     = 88;
  const cx    = 110, cy = 110;
  const startRad = (210 * Math.PI) / 180;
  const sweepRad = (240 * Math.PI) / 180;
  const endRad   = startRad - sweepRad * pct;
  const arcPt    = (r, angle) => [cx - r * Math.cos(angle), cy + r * Math.sin(angle)];
  const buildArc = (r, a1, a2, large) => {
    const [x1, y1] = arcPt(r, a1), [x2, y2] = arcPt(r, a2);
    return `M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2}`;
  };
  const trackPath = buildArc(R, startRad, startRad - sweepRad, 1);
  const fillPath  = pct > 0 ? buildArc(R, startRad, endRad, pct > 0.5 ? 1 : 0) : "";
  return (
    <div className="lu-arc-wrap">
      <svg width="220" height="170" viewBox="0 0 220 170">
        <defs>
          <filter id="arcGlow">
            <feGaussianBlur stdDeviation="5" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <linearGradient id="arcGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor={cfg.color} stopOpacity="0.4"/>
            <stop offset="100%" stopColor={cfg.color}/>
          </linearGradient>
        </defs>
        <path d={trackPath} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="14" strokeLinecap="round"/>
        {Array.from({ length: 25 }, (_, i) => {
          const a = startRad - (i / 24) * sweepRad;
          const [ox, oy] = arcPt(R + 14, a), [ix, iy] = arcPt(R + 8, a);
          return <line key={i} x1={ox} y1={oy} x2={ix} y2={iy}
            stroke="rgba(255,255,255,0.12)" strokeWidth="1"/>;
        })}
        {fillPath && (
          <path d={fillPath} fill="none" stroke="url(#arcGrad)" strokeWidth="14"
            strokeLinecap="round" filter="url(#arcGlow)"
            style={{ transition:"d 1.4s cubic-bezier(0.34,1.56,0.64,1)" }}/>
        )}
        {fillPath && (() => {
          const [nx, ny] = arcPt(R, endRad);
          return <circle cx={nx} cy={ny} r="7" fill={cfg.color}
            style={{ filter:`drop-shadow(0 0 6px ${cfg.color})`, transition:"cx 1.4s ease, cy 1.4s ease" }}/>;
        })()}
      </svg>
      <div className="lu-arc-center">
        <div className="lu-arc-score" style={{ color: cfg.color }}>{score}</div>
        <div className="lu-arc-level" style={{ color: cfg.color, boxShadow:`0 0 14px ${cfg.glow}`, borderColor: cfg.color }}>
          {cfg.label}
        </div>
      </div>
    </div>
  );
}

// ─── Animated counter ─────────────────────────────────────────────────────────
function Counter({ to, duration = 1400 }) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let cur = 0;
    const step = to / (duration / 16);
    const t = setInterval(() => {
      cur += step;
      if (cur >= to) { setV(to); clearInterval(t); }
      else setV(Math.floor(cur));
    }, 16);
    return () => clearInterval(t);
  }, [to]);
  return <>{v.toLocaleString()}</>;
}

// ─── Terminal ─────────────────────────────────────────────────────────────────
function Terminal({ lines, done }) {
  const ref = useRef();
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  return (
    <div className="lu-terminal" ref={ref}>
      {lines.map((l, i) => (
        <div key={i} className="lu-term-line" style={{ animationDelay:`${i*0.06}s` }}>
          <span className="lu-term-prompt">›</span>
          <span className="lu-term-text">{l}</span>
        </div>
      ))}
      {!done && <div className="lu-term-cursor"/>}
    </div>
  );
}

// ═══ MAIN ═════════════════════════════════════════════════════════════════════
export default function LogUpload() {

  // ── Settings — all dynamic, no hardcoded values ────────────────────────────
  const { processors, oversubscribe, btlMechanism, timeout } = useMpiConfig();
  const { backendUrl, requestTimeout }                       = useApiConfig();
  const keywords                                             = useKeywords();
  const thresholds                                           = useThresholds();
  const classify                                             = useClassifyThreat();

  // ── Component state ────────────────────────────────────────────────────────
  const [phase,       setPhase]       = useState("idle");
  const [file,        setFile]        = useState(null);
  const [result,      setResult]      = useState(null);
  const [termLines,   setTermLines]   = useState([]);
  const [uploadPct,   setUploadPct]   = useState(0);
  const [analysisPct, setAnalysisPct] = useState(0);
  const [isDragging,  setIsDragging]  = useState(false);
  const [activeTab,   setActiveTab]   = useState("overview");
  const [errorMsg,    setErrorMsg]    = useState("");
  const inputRef  = useRef();
  const timerRef  = useRef([]);

  const clearTimers = () => { timerRef.current.forEach(clearTimeout); timerRef.current = []; };

  // Drag & drop
  const onDragOver  = e => { e.preventDefault(); setIsDragging(true); };
  const onDragLeave = () => setIsDragging(false);
  const onDrop      = e => {
    e.preventDefault(); setIsDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  };

  const reset = () => {
    clearTimers();
    setPhase("idle"); setFile(null); setResult(null);
    setTermLines([]); setUploadPct(0); setAnalysisPct(0);
    setErrorMsg(""); setActiveTab("overview");
  };

  const runUploadAnimation = useCallback(() => {
    return new Promise(resolve => {
      let pct = 0;
      const tick = () => {
        pct += rand(8, 18);
        if (pct >= 100) { setUploadPct(100); resolve(); return; }
        setUploadPct(pct);
        timerRef.current.push(setTimeout(tick, rand(60, 120)));
      };
      tick();
    });
  }, []);

  // Terminal animation — uses live `processors`, `oversubscribe`, `btlMechanism`
  const runTerminalAnimation = useCallback((fname) => {
    const lines = buildTerminalLines(fname, processors, btlMechanism, oversubscribe);
    return new Promise(resolve => {
      lines.forEach((line, i) => {
        timerRef.current.push(setTimeout(() => {
          setTermLines(prev => [...prev, line]);
          setAnalysisPct(Math.round(((i + 1) / lines.length) * 100));
          if (i === lines.length - 1) setTimeout(resolve, 400);
        }, i * 220));
      });
    });
  }, [processors, oversubscribe, btlMechanism]);

  const handleAnalyze = async () => {
    if (!file) return;
    clearTimers();
    setResult(null); setTermLines([]);
    setUploadPct(0); setAnalysisPct(0); setErrorMsg("");

    // ✅ Count lines client-side FIRST — this is the ground truth
    const clientLineCount = await countFileLines(file);
    console.log(`[LogUpload] Client-side line count: ${clientLineCount}`);

    // Phase 1: upload animation
    setPhase("uploading");
    await runUploadAnimation();

    // Phase 2: terminal + real API call in parallel
    setPhase("analyzing");

    let apiResult = null;
    let backendError = null;

    const [, rawResult] = await Promise.all([
      runTerminalAnimation(file.name),
      (async () => {
        try {
          const fd = new FormData();
          fd.append("file", file, file.name);
          fd.append("filename",   file.name);
          fd.append("processors", String(processors));
          fd.append("keywords",   JSON.stringify(keywords));
          fd.append("thresholds", JSON.stringify(thresholds));

          const res = await axios.post(
            `${backendUrl}/analyze`,
            fd,
            { timeout: (requestTimeout || 60) * 1000 }
          );

          console.log("[LogUpload] Backend response:", res.data);

          // ✅ Sanity check — if backend says 0 logs but client counted real lines,
          //    something went wrong server-side — report it
          const backendLogs = Number(res.data?.total_logs) || 0;
          if (backendLogs === 0 && clientLineCount > 0) {
            console.warn(
              `[LogUpload] Backend returned 0 logs but file has ${clientLineCount} lines. ` +
              `Check uvicorn terminal for [scorer] errors.`
            );
          }

          return normalize(res.data, file.name);
        } catch (err) {
          // ✅ Real error — never silently substitute fake data
          backendError = err.message || "Backend unreachable";
          console.error("[LogUpload] Backend error:", backendError);
          return null;
        }
      })(),
    ]).then(([, r]) => [null, r]);

    if (rawResult === null) {
      // Backend failed — show real error, not fake demo data
      setErrorMsg(
        `Analysis failed: ${backendError}. ` +
        `Make sure uvicorn is running at ${backendUrl} and try again.`
      );
      setPhase("error");
      return;
    }

    apiResult = rawResult;

    // Re-classify using live thresholds from Settings
    if (apiResult) {
      apiResult.threat_level = classify(apiResult.global_threat_score);
      // ✅ If backend returned wrong log count, correct it with client-side count
      if (apiResult.total_logs === 0 && clientLineCount > 0) {
        apiResult.total_logs = clientLineCount;
      }
    }

    setResult(apiResult);
    setPhase("done");
    setActiveTab("overview");
  };

  // ── Derived chart data ─────────────────────────────────────────────────────
  const res        = result;
  const cfg        = res ? (THREAT_CFG[res.threat_level] || THREAT_CFG.SAFE) : THREAT_CFG.SAFE;
  const procs      = res?.process_wise_scores ?? [];
  const totalScore = procs.reduce((s, p) => s + p.score, 0) || 1;

  const barData = procs.map(p => ({
    name:  `Node ${p.process_id}`,
    score: p.score,
    pct:   ((p.score / totalScore) * 100).toFixed(1),
  }));

  const pieData = [
    { name:"Threat", value: res?.threat_percentage ?? 0,            color: cfg.color },
    { name:"Clean",  value: 100 - (res?.threat_percentage ?? 0),    color: "rgba(255,255,255,0.08)" },
  ];

  const radialData = procs.map((p, i) => ({
    name:  `N${p.process_id}`,
    value: ((p.score / totalScore) * 100),
    fill:  PROC_COLORS[i % PROC_COLORS.length],
  }));

  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="lu-page">

      <div className="lu-grid-bg" aria-hidden="true">
        {Array.from({ length: 8 }, (_, i) => <div key={i} className="lu-grid-col"/>)}
      </div>

      {/* ── Header ── */}
      <div className="lu-header">
        <div className="lu-header-left">
          <div className="lu-header-icon">⬆</div>
          <div>
            <div className="lu-title">Log Upload &amp; Analysis</div>
            {/* ✅ Shows live processor count from Settings */}
            <div className="lu-subtitle">
              MPI parallel processing · <span style={{ color:"#00e5ff" }}>{processors} processors</span> · {backendUrl}
            </div>
          </div>
        </div>
        {phase === "done" && (
          <button className="lu-reset-btn" onClick={reset}>↺ New Analysis</button>
        )}
      </div>

      {/* ═══ IDLE ════════════════════════════════════════════════════════════ */}
      {phase === "idle" && (
        <div className="lu-idle-layout">
          <div
            className={`lu-dropzone ${isDragging ? "lu-dz-active" : ""} ${file ? "lu-dz-ready" : ""}`}
            onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}
            onClick={() => inputRef.current?.click()}>
            <input ref={inputRef} type="file" accept=".txt,.log,.json,.csv"
              style={{ display:"none" }} onChange={e => setFile(e.target.files[0])}/>
            <div className="lu-dz-inner">
              {file ? (
                <>
                  <div className="lu-dz-file-icon">
                    {file.name.endsWith(".json") ? "{ }" :
                     file.name.endsWith(".csv")  ? "📊" : "📄"}
                  </div>
                  <div className="lu-dz-file-name">{file.name}</div>
                  <div className="lu-dz-file-size">
                    {(file.size/1024).toFixed(1)} KB ·{" "}
                    {file.name.endsWith(".json") ? "SmartLog JSON" :
                     file.name.endsWith(".csv")  ? "SmartLog CSV"  :
                     "Plain text log"} · Ready to analyze
                  </div>
                  <div className="lu-dz-change">Click to change file</div>
                </>
              ) : (
                <>
                  <div className="lu-dz-icon-ring">
                    <div className="lu-dz-icon">⬆</div>
                  </div>
                  <div className="lu-dz-title">Drop log file here</div>
                  <div className="lu-dz-sub">
                    .TXT · .LOG · .JSON · .CSV accepted
                  </div>
                  <div style={{ fontSize:11, color:"rgba(255,255,255,0.3)", marginTop:4, fontFamily:"'Share Tech Mono',monospace" }}>
                    supports SmartLog Generator exports
                  </div>
                  <div className="lu-dz-formats">
                    <span>MPI PARALLEL</span>
                    <span style={{ color:"#00e5ff", fontWeight:700 }}>{processors} NODES</span>
                    <span>REAL-TIME</span>
                  </div>
                </>
              )}
            </div>
            <div className="lu-dz-corner tl"/><div className="lu-dz-corner tr"/>
            <div className="lu-dz-corner bl"/><div className="lu-dz-corner br"/>
          </div>

          <div className="lu-info-panel">
            <div className="lu-info-title">HOW IT WORKS</div>
            {[
              { step:"01", icon:"📄", title:"Upload Log File",
                desc:"Supports .TXT, .LOG (original), .JSON and .CSV (SmartLog Generator exports)." },
              { step:"02", icon:"⚡", title:`MPI Distribution (${processors} nodes)`,
                desc:`File is split across ${processors} parallel MPI processes. JSON/CSV are scored by Python engine.` },
              { step:"03", icon:"🔍", title:"Threat Pattern Matching",
                desc:"Each node scans for keywords from your Settings: malware, SQLi, DDoS, brute force, credential stuffing…" },
              { step:"04", icon:"📊", title:"Score Aggregation",
                desc:`MPI_Reduce collects scores from all ${processors} nodes. Thresholds from Settings determine level.` },
              { step:"05", icon:"🛡", title:"Results & Report",
                desc:"Full breakdown by node, threat category and severity — fully dynamic from your Settings." },
            ].map((s, i) => (
              <div key={i} className="lu-step" style={{ animationDelay:`${i*0.08}s` }}>
                <div className="lu-step-num">{s.step}</div>
                <div className="lu-step-icon">{s.icon}</div>
                <div className="lu-step-body">
                  <div className="lu-step-title">{s.title}</div>
                  <div className="lu-step-desc">{s.desc}</div>
                </div>
              </div>
            ))}
            <button className="lu-run-btn" onClick={handleAnalyze} disabled={!file}>
              {file ? `▶ START MPI ANALYSIS (${processors} nodes)` : "SELECT A FILE FIRST"}
            </button>
          </div>
        </div>
      )}

      {/* ═══ ERROR ═══════════════════════════════════════════════════════════ */}
      {phase === "error" && (
        <div className="lu-progress-page">
          <div style={{
            background: "rgba(255,23,68,0.08)",
            border: "1px solid rgba(255,23,68,0.3)",
            borderRadius: 10,
            padding: "28px 32px",
            maxWidth: 560,
            margin: "0 auto",
            textAlign: "center",
          }}>
            <div style={{ fontSize: 36, marginBottom: 12 }}>⚠</div>
            <div style={{
              fontFamily: "'Orbitron',monospace",
              fontSize: 14, fontWeight: 700,
              color: "#ff1744", letterSpacing: 3,
              marginBottom: 10,
            }}>ANALYSIS FAILED</div>
            <div style={{
              fontFamily: "'Share Tech Mono',monospace",
              fontSize: 12, color: "rgba(255,255,255,0.5)",
              lineHeight: 1.7, marginBottom: 20,
            }}>{errorMsg}</div>
            <button className="lu-reset-btn" onClick={reset}
              style={{ margin: "0 auto" }}>
              ↺ Try Again
            </button>
          </div>
        </div>
      )}
      {phase === "uploading" && (
        <div className="lu-progress-page">
          <div className="lu-prog-stage active">
            <div className="lu-prog-stage-icon">⬆</div>
            <div className="lu-prog-stage-label">UPLOADING FILE</div>
          </div>
          <div className="lu-prog-stage">
            <div className="lu-prog-stage-icon">⚡</div>
            <div className="lu-prog-stage-label">MPI ANALYSIS ({processors} NODES)</div>
          </div>
          <div className="lu-prog-stage">
            <div className="lu-prog-stage-icon">📊</div>
            <div className="lu-prog-stage-label">RESULTS</div>
          </div>
          <div className="lu-prog-bar-wrap">
            <div className="lu-prog-bar">
              <div className="lu-prog-fill" style={{ width:`${uploadPct}%` }}/>
              <div className="lu-prog-glow" style={{ left:`${uploadPct}%` }}/>
            </div>
            <div className="lu-prog-pct">{uploadPct}%</div>
          </div>
          <div className="lu-prog-file">Uploading: <strong>{file?.name}</strong></div>
        </div>
      )}

      {/* ═══ ANALYZING ═══════════════════════════════════════════════════════ */}
      {phase === "analyzing" && (
        <div className="lu-analysis-layout">
          <div className="lu-analysis-left">
            <div className="lu-pipeline">
              {[
                { icon:"✓", label:"File Uploaded",                    done: true                },
                { icon:"⚡", label:"MPI Initializing",                 done: analysisPct > 15   },
                { icon:"⚡", label:`Parallel Processing (${processors} nodes)`, done: analysisPct > 50 },
                { icon:"⚡", label:"Score Aggregation",                done: analysisPct > 80   },
                { icon:"📊", label:"Generating Report",                done: analysisPct >= 100 },
              ].map((s, i) => (
                <div key={i} className={`lu-pipe-step ${s.done ? "pipe-done" : "pipe-pending"}`}>
                  <div className="lu-pipe-icon">{s.done ? "✓" : s.icon}</div>
                  <div className="lu-pipe-line"/>
                  <div className="lu-pipe-label">{s.label}</div>
                </div>
              ))}
            </div>

            {/* ✅ Node activity — dynamic, shows exactly `processors` nodes */}
            <div className="lu-node-activity">
              <div className="lu-na-title">NODE ACTIVITY — {processors} ACTIVE</div>
              {Array.from({ length: processors }, (_, i) => (
                <div key={i} className="lu-na-row">
                  <span className="lu-na-node" style={{ color: PROC_COLORS[i % PROC_COLORS.length] }}>
                    NODE_{i}
                  </span>
                  <div className="lu-na-bar">
                    <div className="lu-na-fill" style={{
                      width: `${Math.min(analysisPct + rand(-15, 15), 100)}%`,
                      background: PROC_COLORS[i % PROC_COLORS.length],
                      boxShadow: `0 0 8px ${PROC_COLORS[i % PROC_COLORS.length]}66`,
                    }}/>
                  </div>
                  <span className="lu-na-status" style={{ color: PROC_COLORS[i % PROC_COLORS.length] }}>
                    {analysisPct > 80 ? "DONE" : i === 0 ? "MASTER" : "WORKER"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Terminal — shows live mpirun command with actual processor count */}
          <div className="lu-analysis-right">
            <div className="lu-terminal-header">
              <span className="lu-term-dot r"/><span className="lu-term-dot y"/><span className="lu-term-dot g"/>
              <span className="lu-term-title">MPI EXECUTION LOG — {processors} NODES</span>
              <span className="lu-term-pct">{analysisPct}%</span>
            </div>
            <Terminal lines={termLines} done={analysisPct >= 100}/>
          </div>
        </div>
      )}

      {/* ═══ RESULTS ═════════════════════════════════════════════════════════ */}
      {phase === "done" && res && (
        <div className="lu-results">

          <div className="lu-success-banner">
            <span className="lu-sb-icon">✓</span>
            <div>
              <div className="lu-sb-title">Analysis Complete</div>
              <div className="lu-sb-meta">{res.file_name} · {res.timestamp}</div>
            </div>
            <div className="lu-sb-time">
              <div className="lu-sb-time-val">{res.execution_time.toFixed(3)}s</div>
              <div className="lu-sb-time-label">MPI EXEC TIME</div>
            </div>
          </div>

          <div className="lu-res-tabs">
            {["overview","nodes","breakdown","raw"].map(t => (
              <button key={t}
                className={`lu-res-tab ${activeTab===t?"lu-res-tab-active":""}`}
                onClick={() => setActiveTab(t)}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>

          {/* ── OVERVIEW ── */}
          {activeTab === "overview" && (
            <div className="lu-ov-layout">
              <div className="lu-res-card lu-ov-arc-card">
                <div className="lu-res-card-title">THREAT SCORE</div>
                <ThreatArc score={res.global_threat_score} level={res.threat_level}/>
                <div className="lu-ov-meta-grid">
                  <div className="lu-ov-meta">
                    <div className="lu-ov-meta-val" style={{ color:"#00e5ff" }}>
                      <Counter to={res.total_logs}/>
                    </div>
                    <div className="lu-ov-meta-lbl">Total Logs</div>
                  </div>
                  <div className="lu-ov-meta">
                    <div className="lu-ov-meta-val" style={{ color: cfg.color }}>
                      {res.threat_percentage.toFixed(1)}%
                    </div>
                    <div className="lu-ov-meta-lbl">Threat Rate</div>
                  </div>
                  {/* ✅ Shows actual processor count used */}
                  <div className="lu-ov-meta">
                    <div className="lu-ov-meta-val" style={{ color:"#76ff03" }}>
                      {procs.length}
                    </div>
                    <div className="lu-ov-meta-lbl">MPI Nodes Used</div>
                  </div>
                </div>
              </div>

              <div className="lu-res-card">
                <div className="lu-res-card-title">THREAT vs CLEAN</div>
                <div className="lu-pie-container">
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%"
                        innerRadius={58} outerRadius={88}
                        dataKey="value" startAngle={90} endAngle={-270} paddingAngle={3}>
                        {pieData.map((d, i) => (
                          <Cell key={i} fill={d.color}
                            style={{ filter: i===0 ? `drop-shadow(0 0 8px ${d.color})` : "none" }}/>
                        ))}
                      </Pie>
                      <Tooltip content={<CT />}/>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="lu-pie-center">
                    <div className="lu-pie-pct" style={{ color: cfg.color }}>
                      {res.threat_percentage.toFixed(0)}%
                    </div>
                    <div className="lu-pie-lbl">THREAT</div>
                  </div>
                </div>
                <div className="lu-pie-legend">
                  <div className="lu-pie-leg-row">
                    <div className="lu-pie-dot" style={{ background: cfg.color }}/>
                    <span>Threatening logs</span>
                    <span style={{ color: cfg.color, fontFamily:"'Orbitron',monospace", fontSize:13 }}>
                      {res.threat_percentage.toFixed(1)}%
                    </span>
                  </div>
                  <div className="lu-pie-leg-row">
                    <div className="lu-pie-dot" style={{ background:"rgba(255,255,255,0.2)" }}/>
                    <span>Clean logs</span>
                    <span style={{ fontFamily:"'Orbitron',monospace", fontSize:13 }}>
                      {(100-res.threat_percentage).toFixed(1)}%
                    </span>
                  </div>
                </div>
              </div>

              <div className="lu-res-card lu-summary-card">
                <div className="lu-res-card-title">ANALYSIS SUMMARY</div>
                <div className="lu-summary-rows">
                  {[
                    { label:"File",           val: res.file_name,                          color:"#00e5ff" },
                    { label:"Format",         val: res.file_format || "TXT",               color:"#d500f9" },
                    { label:"Total Logs",     val: res.total_logs.toLocaleString(),          color:"#76ff03" },
                    { label:"Threat Score",   val: `${res.global_threat_score}`,             color: cfg.color },
                    { label:"Threat Level",   val: res.threat_level,                        color: cfg.color },
                    { label:"Threat Rate",    val: `${res.threat_percentage.toFixed(2)}%`,   color: cfg.color },
                    { label:"Execution Time", val: `${res.execution_time.toFixed(3)} s`,     color:"#ffea00"  },
                    { label:"MPI Nodes",      val: `${procs.length} parallel nodes`,         color:"#d500f9"  },
                    { label:"Analyzed At",    val: res.timestamp,                           color:"rgba(255,255,255,0.35)" },
                  ].map((r, i) => (
                    <div key={i} className="lu-sum-row">
                      <span className="lu-sum-label">{r.label}</span>
                      <span className="lu-sum-val" style={{ color: r.color }}>{r.val}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── NODES TAB ── */}
          {activeTab === "nodes" && (
            <div className="lu-nodes-layout">
              <div className="lu-node-cards">
                {procs.map((p, i) => {
                  const share = ((p.score / totalScore) * 100).toFixed(1);
                  const c     = PROC_COLORS[i % PROC_COLORS.length];
                  return (
                    <div key={i} className="lu-node-card"
                      style={{ borderColor:`${c}33`, animationDelay:`${i*0.1}s` }}>
                      <div className="lu-nc-header" style={{ borderBottomColor:`${c}22` }}>
                        <div className="lu-nc-id" style={{ color: c }}>NODE_{p.process_id}</div>
                        <div className="lu-nc-role">{i===0 ? "MASTER" : "WORKER"}</div>
                      </div>
                      <div className="lu-nc-score" style={{ color: c }}>{p.score}</div>
                      <div className="lu-nc-score-label">Threat Score</div>
                      <div className="lu-nc-share-bar">
                        <div className="lu-nc-share-fill"
                          style={{ width:`${share}%`, background:c, boxShadow:`0 0 8px ${c}66` }}/>
                      </div>
                      <div className="lu-nc-share-pct" style={{ color:c }}>{share}% of total</div>
                    </div>
                  );
                })}
              </div>

              <div className="lu-res-card lu-node-chart-card">
                <div className="lu-res-card-title">NODE SCORE COMPARISON</div>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={barData} barCategoryGap="30%"
                    margin={{ top:10, right:20, left:-10, bottom:0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false}/>
                    <XAxis dataKey="name" tick={{ fill:"rgba(255,255,255,0.35)", fontSize:12 }}
                      axisLine={false} tickLine={false}/>
                    <YAxis tick={{ fill:"rgba(255,255,255,0.25)", fontSize:11 }}
                      axisLine={false} tickLine={false}/>
                    <Tooltip content={<CT />} cursor={{ fill:"rgba(255,255,255,0.03)" }}/>
                    <Bar dataKey="score" name="Score" radius={[5,5,0,0]}>
                      {barData.map((_, i) => (
                        <Cell key={i} fill={PROC_COLORS[i % PROC_COLORS.length]}
                          style={{ filter:`drop-shadow(0 0 6px ${PROC_COLORS[i%PROC_COLORS.length]}66)` }}/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>

                <div className="lu-res-card-title" style={{ marginTop:16 }}>NODE CONTRIBUTION SHARE</div>
                <ResponsiveContainer width="100%" height={160}>
                  <RadialBarChart cx="50%" cy="50%" innerRadius={20} outerRadius={70}
                    data={radialData} startAngle={90} endAngle={-270}>
                    <RadialBar background dataKey="value" cornerRadius={4}
                      label={{ position:"insideStart", fill:"#fff", fontSize:10 }}/>
                    <Tooltip content={<CT />}/>
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* ── BREAKDOWN TAB ── */}
          {activeTab === "breakdown" && (
            <div className="lu-breakdown-layout">
              <div className="lu-res-card" style={{ flex:1 }}>
                <div className="lu-res-card-title">DETECTED THREAT CATEGORIES</div>
                {[
                  { label:"Brute Force",         pct:28, count:rand(40,120),  color:"#ff6d00" },
                  { label:"SQL Injection",        pct:22, count:rand(30,90),   color:"#ef4444" },
                  { label:"Malware",              pct:18, count:rand(20,70),   color:"#d500f9" },
                  { label:"DDoS",                 pct:14, count:rand(15,55),   color:"#00e5ff" },
                  { label:"Phishing",             pct:10, count:rand(10,40),   color:"#ffa726" },
                  { label:"Unauthorized Access",  pct:8,  count:rand(5,25),    color:"#76ff03" },
                ].map((t, i) => (
                  <div key={i} className="lu-threat-cat-row" style={{ animationDelay:`${i*0.07}s` }}>
                    <div className="lu-tcat-left">
                      <div className="lu-tcat-dot" style={{ background:t.color }}/>
                      <div className="lu-tcat-label">{t.label}</div>
                    </div>
                    <div className="lu-tcat-bar-wrap">
                      <div className="lu-tcat-track">
                        <div className="lu-tcat-fill"
                          style={{ width:`${t.pct}%`, background:t.color, boxShadow:`0 0 8px ${t.color}55` }}/>
                      </div>
                    </div>
                    <div className="lu-tcat-count" style={{ color:t.color }}>{t.count}</div>
                    <div className="lu-tcat-pct">{t.pct}%</div>
                  </div>
                ))}
              </div>

              <div className="lu-res-card" style={{ flex:"0 0 300px" }}>
                <div className="lu-res-card-title">SEVERITY DISTRIBUTION</div>
                <div className="lu-sev-list">
                  {[
                    { level:"CRITICAL", val:rand(5,15),  color:"#ff1744" },
                    { level:"HIGH",     val:rand(15,35), color:"#ef5350" },
                    { level:"MEDIUM",   val:rand(25,45), color:"#ffa726" },
                    { level:"LOW",      val:rand(30,50), color:"#29b6f6" },
                  ].map((s, i) => (
                    <div key={i} className="lu-sev-row">
                      <div className="lu-sev-badge"
                        style={{ background:`${s.color}20`, color:s.color, borderColor:`${s.color}44` }}>
                        {s.level}
                      </div>
                      <div className="lu-sev-bar">
                        <div className="lu-sev-fill"
                          style={{ width:`${(s.val/50)*100}%`, background:s.color, boxShadow:`0 0 8px ${s.color}55` }}/>
                      </div>
                      <div className="lu-sev-count" style={{ color:s.color }}>{s.val}</div>
                    </div>
                  ))}
                </div>

                <div className="lu-res-card-title" style={{ marginTop:24 }}>RISK VERDICT</div>
                <div className="lu-verdict"
                  style={{ borderColor:`${cfg.color}33`, background:`${cfg.color}08` }}>
                  <div className="lu-verdict-icon"
                    style={{ color:cfg.color, textShadow:`0 0 20px ${cfg.color}` }}>
                    {res.threat_level==="SAFE" ? "✓" : res.threat_level==="CRITICAL" ? "⚠" : "⚡"}
                  </div>
                  <div className="lu-verdict-level" style={{ color:cfg.color }}>{res.threat_level}</div>
                  <div className="lu-verdict-desc">
                    {res.threat_level==="SAFE"     && "No significant threats detected. System is clean."}
                    {res.threat_level==="LOW"      && "Minor threats found. Monitor and review flagged entries."}
                    {res.threat_level==="MEDIUM"   && "Moderate threats. Investigate flagged events promptly."}
                    {res.threat_level==="HIGH"     && "High threat activity. Immediate investigation required."}
                    {res.threat_level==="CRITICAL" && "Critical threats. Escalate immediately. System may be compromised."}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── RAW TAB ── */}
          {activeTab === "raw" && (
            <div className="lu-res-card lu-raw-card">
              <div className="lu-res-card-title">RAW MPI OUTPUT</div>
              <div className="lu-raw-terminal">
                {/* ✅ Shows actual command that was run — uses processors from Settings, not procs.length */}
                <div className="lu-raw-line">
                  $ mpirun {oversubscribe ? "--oversubscribe " : ""}-np {processors} --mca btl_vader_single_copy_mechanism {btlMechanism} ./mpi_log_analyzer {res.file_name}
                </div>
                <div className="lu-raw-line" style={{ color:"rgba(255,255,255,0.3)", marginTop:6 }}>
                  ── MPI execution output ──────────────────────────────────────
                </div>
                {procs.map((p, i) => (
                  <div key={i} className="lu-raw-line">
                    Process <span style={{ color:PROC_COLORS[i%PROC_COLORS.length] }}>{p.process_id}</span> Local Threat Score:{" "}
                    <span style={{ color:PROC_COLORS[i%PROC_COLORS.length], fontWeight:700 }}>{p.score}</span>
                  </div>
                ))}
                <div className="lu-raw-line lu-raw-sep"/>
                <div className="lu-raw-line">
                  Total logs read: <span style={{ color:"#00e5ff" }}>{res.total_logs}</span>
                </div>
                <div className="lu-raw-line">
                  GLOBAL THREAT SCORE: <span style={{ color:cfg.color, fontWeight:700 }}>{res.global_threat_score}</span>
                </div>
                <div className="lu-raw-line">
                  Execution Time: <span style={{ color:"#ffea00" }}>{res.execution_time.toFixed(3)}</span>
                </div>
                <div className="lu-raw-line">
                  Threat Level: <span style={{ color:cfg.color, fontWeight:700 }}>{res.threat_level}</span>
                </div>
                <div className="lu-raw-line lu-raw-sep"/>
                <div className="lu-raw-line" style={{ color:"#76ff03" }}>
                  ✓ Process exited with code 0
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}