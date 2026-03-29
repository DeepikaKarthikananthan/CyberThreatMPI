import React, { useState, useCallback } from "react";
import { useSettings } from "./Settingscontext";
import "./Settings.css";

// ─── Amdahl helpers ────────────────────────────────────────────────────────────
const amdahlSpeedup      = (n, p = 0.85) => 1 / ((1 - p) + p / n);
const estimateThroughput = (n)           => Math.round(2300 * amdahlSpeedup(n));

// ─── Tooltip ───────────────────────────────────────────────────────────────────
function Tip({ text }) {
  const [show, setShow] = useState(false);
  return (
    <span className="st-tip-wrap"
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      <span className="st-tip-icon">?</span>
      {show && <span className="st-tip-popup">{text}</span>}
    </span>
  );
}

// ─── Toggle ────────────────────────────────────────────────────────────────────
function Toggle({ value, onChange, color = "#00e5ff" }) {
  return (
    <button className={`st-toggle ${value ? "st-toggle-on" : ""}`}
      style={{ "--tc": color }} onClick={() => onChange(!value)}>
      <span className="st-toggle-knob" />
    </button>
  );
}

// ─── Core Grid ─────────────────────────────────────────────────────────────────
function CoreGrid({ count, max = 16 }) {
  return (
    <div className="st-core-grid">
      {Array.from({ length: max }, (_, i) => (
        <div key={i}
          className={`st-core ${i < count ? "st-core-active" : "st-core-idle"}`}
          style={{ animationDelay: `${i * 0.04}s` }}
          title={i < count ? `Core ${i} — ACTIVE` : `Core ${i} — IDLE`}>
          <span className="st-core-id">{i}</span>
          {i < count && <span className="st-core-pulse" />}
        </div>
      ))}
    </div>
  );
}

// ─── Amdahl Chart ──────────────────────────────────────────────────────────────
function AmdahlChart({ currentN }) {
  const points = [1, 2, 4, 6, 8, 10, 12, 16];
  const maxS = amdahlSpeedup(16);
  const W = 320, H = 120;
  const pad = { l: 36, r: 12, t: 12, b: 28 };
  const cW = W - pad.l - pad.r, cH = H - pad.t - pad.b;
  const x = (n) => pad.l + ((n - 1) / 15) * cW;
  const y = (s) => pad.t + cH - (s / maxS) * cH;
  const linePath = points.map((n, i) => `${i === 0 ? "M" : "L"}${x(n)},${y(amdahlSpeedup(n))}`).join(" ");
  const areaPath = linePath + ` L${x(16)},${y(0)+cH} L${x(1)},${y(0)+cH} Z`;
  const cx = x(currentN), cy = y(amdahlSpeedup(currentN));
  return (
    <div className="st-amdahl-wrap">
      <div className="st-amdahl-label">THEORETICAL SPEEDUP — AMDAHL'S LAW · 85% PARALLEL FRACTION</div>
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
        <defs>
          <linearGradient id="aGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#00e5ff" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#00e5ff" stopOpacity="0"   />
          </linearGradient>
        </defs>
        {[1,2,3,4].map(v => (
          <line key={v} x1={pad.l} y1={y((v/4)*maxS)} x2={W-pad.r} y2={y((v/4)*maxS)}
            stroke="rgba(255,255,255,0.04)" strokeWidth="1" />
        ))}
        <path d={areaPath} fill="url(#aGrad)" />
        <path d={linePath} fill="none" stroke="#00e5ff" strokeWidth="2"
          style={{ filter:"drop-shadow(0 0 4px #00e5ff88)" }} />
        {[1,2,3,4].map(v => (
          <text key={v} x={pad.l-4} y={y((v/4)*maxS)+4}
            textAnchor="end" fill="rgba(255,255,255,0.25)" fontSize="9" fontFamily="Share Tech Mono">
            {((v/4)*maxS).toFixed(1)}x
          </text>
        ))}
        {points.map(n => (
          <text key={n} x={x(n)} y={H-6}
            textAnchor="middle" fill="rgba(255,255,255,0.25)" fontSize="9" fontFamily="Share Tech Mono">{n}</text>
        ))}
        <line x1={cx} y1={pad.t} x2={cx} y2={H-pad.b}
          stroke="#00e5ff" strokeWidth="1" strokeDasharray="3 3" strokeOpacity="0.5" />
        <circle cx={cx} cy={cy} r="5" fill="#00e5ff" style={{ filter:"drop-shadow(0 0 6px #00e5ff)" }} />
        <rect x={cx-28} y={cy-22} width={56} height={16} rx="3"
          fill="#050a10" stroke="#00e5ff" strokeOpacity="0.5" strokeWidth="1" />
        <text x={cx} y={cy-11} textAnchor="middle" fill="#00e5ff" fontSize="9" fontFamily="Share Tech Mono">
          {amdahlSpeedup(currentN).toFixed(2)}x
        </text>
      </svg>
    </div>
  );
}

// ─── Log Simulator ─────────────────────────────────────────────────────────────
function LogSimulator({ keywords }) {
  const [line, setLine] = useState("");
  const [result, setResult] = useState(null);
  const simulate = useCallback(() => {
    if (!line.trim()) return;
    const lower = line.toLowerCase();
    let total = 0; const hits = [];
    keywords.filter(k => k.enabled).forEach(k => {
      if (lower.includes(k.word)) { total += k.score; hits.push({ word: k.word, score: k.score }); }
    });
    setResult({ total, hits });
  }, [line, keywords]);
  const threatColor = (s) => s === 0 ? "#76ff03" : s <= 10 ? "#29b6f6" : s <= 25 ? "#ffa726" : s <= 50 ? "#ef5350" : "#ff1744";
  return (
    <div className="st-simulator">
      <div className="st-sim-title">
        LIVE LOG THREAT SIMULATOR
        <Tip text="Type any log line and see the exact threat score with your current keyword config." />
      </div>
      <div className="st-sim-input-row">
        <input className="st-sim-input"
          placeholder="e.g.  EVENT:BRUTE_FORCE_ATTEMPT | IP:192.168.1.5 | malware detected"
          value={line}
          onChange={e => { setLine(e.target.value); setResult(null); }}
          onKeyDown={e => e.key === "Enter" && simulate()} />
        <button className="st-sim-btn" onClick={simulate}>SCAN</button>
      </div>
      {result && (
        <div className="st-sim-result">
          <div className="st-sim-score" style={{ color: threatColor(result.total) }}>
            {result.total}
            <span className="st-sim-score-lbl">THREAT SCORE</span>
          </div>
          <div className="st-sim-hits">
            {result.hits.length === 0
              ? <span className="st-sim-clean">✓ No threat keywords detected</span>
              : result.hits.map((h, i) => (
                <span key={i} className="st-sim-hit">
                  <span className="st-sim-hit-word">{h.word}</span>
                  <span className="st-sim-hit-score">+{h.score}</span>
                </span>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Config Fingerprint ────────────────────────────────────────────────────────
function ConfigFingerprint({ config }) {
  const str = JSON.stringify(config);
  let hash = 0;
  for (let i = 0; i < str.length; i++) hash = (Math.imul(31, hash) + str.charCodeAt(i)) | 0;
  const hex = (Math.abs(hash) >>> 0).toString(16).padStart(8, "0").toUpperCase();
  return (
    <div className="st-fingerprint">
      <span className="st-fp-label">CONFIG HASH</span>
      <span className="st-fp-val">
        {hex.slice(0,4)}<span className="st-fp-sep">-</span>{hex.slice(4,8)}
      </span>
    </div>
  );
}

// ─── Health Check ──────────────────────────────────────────────────────────────
function HealthCheck({ url }) {
  const [status,  setStatus]  = useState("idle");
  const [latency, setLatency] = useState(null);
  const [details, setDetails] = useState(null);
  const runCheck = async () => {
    setStatus("checking"); setLatency(null); setDetails(null);
    const t0 = performance.now();
    try {
      const res = await fetch(`${url}/health`, { signal: AbortSignal.timeout(5000) });
      const ms  = Math.round(performance.now() - t0);
      if (res.ok) { setStatus("ok"); setLatency(ms); setDetails(await res.json()); }
      else { setStatus("error"); setLatency(ms); }
    } catch { setStatus("error"); }
  };
  const statusColor = { idle:"#555", checking:"#ffea00", ok:"#76ff03", error:"#ff1744" };
  const statusLabel = { idle:"NOT CHECKED", checking:"CHECKING...", ok:"ONLINE", error:"OFFLINE" };
  return (
    <div className="st-health">
      <div className="st-health-row">
        <div className="st-health-dot"
          style={{ background:statusColor[status], boxShadow:status!=="idle"?`0 0 8px ${statusColor[status]}`:"none" }} />
        <span className="st-health-status" style={{ color:statusColor[status] }}>{statusLabel[status]}</span>
        {latency && <span className="st-health-latency">{latency}ms</span>}
        <button className="st-health-btn" onClick={runCheck} disabled={status==="checking"}>
          {status==="checking" ? "PINGING..." : "PING BACKEND"}
        </button>
      </div>
      {details && (
        <div className="st-health-details">
          {Object.entries(details).map(([k,v]) => (
            <div key={k} className="st-health-row-detail">
              <span className="st-hd-key">{k.replace(/_/g," ").toUpperCase()}</span>
              <span className="st-hd-val" style={{ color:v===true?"#76ff03":v===false?"#ff1744":"#00e5ff" }}>
                {String(v).toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══ MAIN SETTINGS ════════════════════════════════════════════════════════════
const SECTIONS = [
  { id:"mpi",        label:"MPI CLUSTER",    icon:"⚡" },
  { id:"keywords",   label:"THREAT INTEL",   icon:"🔍" },
  { id:"thresholds", label:"CLASSIFICATION", icon:"🛡" },
  { id:"api",        label:"API & BACKEND",  icon:"🔗" },
  { id:"ui",         label:"INTERFACE",      icon:"◈" },
  { id:"data",       label:"DATA MGMT",      icon:"💾" },
];

export default function Settings() {
  const { config, updateSetting, replaceConfig, resetConfig } = useSettings();
  const set = updateSetting; // alias

  const [saved,         setSaved]         = useState(false);
  const [activeSection, setActiveSection] = useState("mpi");
  const [newKeyword,    setNewKeyword]    = useState({ word:"", score:5 });
  const [importText,    setImportText]    = useState("");
  const [importError,   setImportError]   = useState("");
  const [editingKw,     setEditingKw]     = useState(null);

  const saveNow = () => {
    localStorage.setItem("cyberthreat_settings", JSON.stringify(config));
    setSaved(true); setTimeout(() => setSaved(false), 2000);
  };

  const exportConfig = () => {
    const blob = new Blob([JSON.stringify(config, null, 2)], { type:"application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `cyberthreat_config_${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const importConfig = () => {
    try {
      replaceConfig(JSON.parse(importText));
      setImportText(""); setImportError("");
    } catch { setImportError("Invalid JSON. Please check the format."); }
  };

  const clearHistory = async () => {
    if (!window.confirm("Clear all analysis history?")) return;
    try {
      await fetch(`${config.api.backendUrl}/history`, { method:"DELETE" });
      alert("History cleared.");
    } catch { alert("Failed to reach backend."); }
  };

  const addKeyword = () => {
    if (!newKeyword.word.trim()) return;
    if (config.keywords.some(k => k.word === newKeyword.word.trim().toLowerCase())) return;
    set("keywords", [...config.keywords, { id:Date.now(), word:newKeyword.word.trim().toLowerCase(), score:newKeyword.score, enabled:true }]);
    setNewKeyword({ word:"", score:5 });
  };

  const removeKeyword = (id)             => set("keywords", config.keywords.filter(k => k.id !== id));
  const updateKeyword = (id, field, val) => set("keywords", config.keywords.map(k => k.id === id ? {...k, [field]:val} : k));
  const totalKeywordWeight = config.keywords.filter(k => k.enabled).reduce((s,k) => s + k.score, 0);

  return (
    <div className="st-page">
      <div className="st-scanline" aria-hidden="true" />

      {/* ── Header ── */}
      <div className="st-header">
        <div className="st-header-left">
          <div className="st-header-icon">⚙</div>
          <div>
            <div className="st-title">SYSTEM CONFIGURATION</div>
            <div className="st-subtitle">Advanced runtime settings · changes propagate app-wide instantly</div>
          </div>
        </div>
        <div className="st-header-right">
          <ConfigFingerprint config={config} />
          <button className={`st-save-btn ${saved ? "st-save-ok" : ""}`} onClick={saveNow}>
            {saved ? "✓ SAVED" : "⬇ SAVE NOW"}
          </button>
          <button className="st-reset-btn"
            onClick={() => { if(window.confirm("Reset to factory defaults?")) resetConfig(); }}>
            ↺ RESET
          </button>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="st-body">

        {/* Sidebar */}
        <div className="st-nav">
          {SECTIONS.map(s => (
            <button key={s.id}
              className={`st-nav-item ${activeSection === s.id ? "st-nav-active" : ""}`}
              onClick={() => setActiveSection(s.id)}>
              <span className="st-nav-icon">{s.icon}</span>
              <span className="st-nav-label">{s.label}</span>
              {activeSection === s.id && <span className="st-nav-bar" />}
            </button>
          ))}
          {/* Live stats sidebar widget */}
          <div className="st-nav-summary">
            <div className="st-ns-row">
              <span className="st-ns-lbl">PROCESSORS</span>
              <span className="st-ns-val" style={{ color:"#00e5ff" }}>{config.mpi.processors}</span>
            </div>
            <div className="st-ns-row">
              <span className="st-ns-lbl">SPEEDUP</span>
              <span className="st-ns-val" style={{ color:"#76ff03" }}>
                {amdahlSpeedup(config.mpi.processors).toFixed(2)}x
              </span>
            </div>
            <div className="st-ns-row">
              <span className="st-ns-lbl">KEYWORDS</span>
              <span className="st-ns-val" style={{ color:"#ffa726" }}>
                {config.keywords.filter(k => k.enabled).length}
              </span>
            </div>
            <div className="st-ns-row">
              <span className="st-ns-lbl">ACCENT</span>
              <span className="st-ns-dot"
                style={{ background:config.ui.accentColor, boxShadow:`0 0 6px ${config.ui.accentColor}` }} />
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="st-content">

          {/* ══ MPI CLUSTER ═════════════════════════════════════════════════ */}
          {activeSection === "mpi" && (
            <div className="st-section">
              <div className="st-section-title">MPI CLUSTER CONFIGURATION</div>
              <div className="st-card st-card-highlight">
                <div className="st-card-title">
                  PARALLEL PROCESSORS
                  <Tip text="Number of MPI processes per analysis run. Used in the -np flag when calling mpirun." />
                </div>
                <div className="st-proc-control">
                  <div className="st-proc-number">
                    <button className="st-proc-btn"
                      onClick={() => set("mpi.processors", Math.max(1, config.mpi.processors - 1))}>−</button>
                    <span className="st-proc-val">{config.mpi.processors}</span>
                    <button className="st-proc-btn"
                      onClick={() => set("mpi.processors", Math.min(16, config.mpi.processors + 1))}>+</button>
                  </div>
                  <input type="range" min="1" max="16" value={config.mpi.processors}
                    className="st-slider" onChange={e => set("mpi.processors", +e.target.value)} />
                  <div className="st-proc-meta">
                    <span className="st-proc-meta-item">
                      <span className="st-pmi-label">SPEEDUP</span>
                      <span className="st-pmi-val" style={{ color:"#00e5ff" }}>
                        {amdahlSpeedup(config.mpi.processors).toFixed(2)}x
                      </span>
                    </span>
                    <span className="st-proc-meta-item">
                      <span className="st-pmi-label">EST. THROUGHPUT</span>
                      <span className="st-pmi-val" style={{ color:"#76ff03" }}>
                        ~{estimateThroughput(config.mpi.processors).toLocaleString()} logs/s
                      </span>
                    </span>
                    <span className="st-proc-meta-item">
                      <span className="st-pmi-label">EFFICIENCY</span>
                      <span className="st-pmi-val" style={{ color:"#ffa726" }}>
                        {Math.round((amdahlSpeedup(config.mpi.processors) / config.mpi.processors) * 100)}%
                      </span>
                    </span>
                  </div>
                </div>
                <CoreGrid count={config.mpi.processors} max={16} />
                <AmdahlChart currentN={config.mpi.processors} />
              </div>

              <div className="st-card">
                <div className="st-card-title">EXECUTION FLAGS</div>
                <div className="st-rows">
                  {[
                    { key:"mpi.oversubscribe", label:"--oversubscribe",   desc:"Allow more processes than physical cores",    color:"#00e5ff" },
                    { key:"mpi.bindToCore",    label:"--bind-to-core",    desc:"Pin each MPI process to a specific CPU core", color:"#76ff03" },
                    { key:"mpi.verboseOutput", label:"Verbose MPI output", desc:"Include MPI debug logs in terminal output",  color:"#d500f9" },
                  ].map(f => (
                    <div key={f.key} className="st-row">
                      <div className="st-row-left">
                        <div className="st-row-label">{f.label}</div>
                        <div className="st-row-desc">{f.desc}</div>
                      </div>
                      <Toggle value={f.key.split(".").reduce((o,k) => o[k], config)}
                        onChange={v => set(f.key, v)} color={f.color} />
                    </div>
                  ))}
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">BTL Mechanism</div>
                      <div className="st-row-desc">--mca btl_vader_single_copy_mechanism</div>
                    </div>
                    <select className="st-select" value={config.mpi.btlMechanism}
                      onChange={e => set("mpi.btlMechanism", e.target.value)}>
                      <option value="none">none (recommended)</option>
                      <option value="cma">cma</option>
                      <option value="xpmem">xpmem</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="st-card">
                <div className="st-card-title">RESOURCE LIMITS</div>
                <div className="st-rows">
                  {[
                    { key:"mpi.timeout",      label:"Execution Timeout", desc:"Max seconds before MPI process is killed", unit:"sec", min:5,   max:300  },
                    { key:"mpi.memoryPerNode", label:"Memory per Node",   desc:"Max RAM allocated per MPI process",        unit:"MB",  min:128, max:4096, step:128 },
                  ].map(f => (
                    <div key={f.key} className="st-row">
                      <div className="st-row-left">
                        <div className="st-row-label">{f.label}</div>
                        <div className="st-row-desc">{f.desc}</div>
                      </div>
                      <div className="st-num-input-wrap">
                        <input type="number" className="st-num-input"
                          min={f.min} max={f.max} step={f.step||1}
                          value={f.key.split(".").reduce((o,k) => o[k], config)}
                          onChange={e => set(f.key, +e.target.value)} />
                        <span className="st-num-unit">{f.unit}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ══ THREAT INTEL ════════════════════════════════════════════════ */}
          {activeSection === "keywords" && (
            <div className="st-section">
              <div className="st-section-title">THREAT INTELLIGENCE — KEYWORD ENGINE</div>
              <LogSimulator keywords={config.keywords} />
              <div className="st-card">
                <div className="st-card-title">
                  KEYWORD WEIGHT TABLE
                  <span className="st-kw-stats">
                    {config.keywords.filter(k=>k.enabled).length} active · max score/line: {totalKeywordWeight}
                  </span>
                </div>
                <div className="st-kw-table">
                  <div className="st-kw-thead">
                    <span>KEYWORD</span><span>WEIGHT</span><span>THREAT BAR</span><span>ENABLED</span><span></span>
                  </div>
                  {config.keywords.map(kw => (
                    <div key={kw.id} className={`st-kw-row ${!kw.enabled ? "st-kw-disabled" : ""}`}>
                      {editingKw === kw.id ? (
                        <input className="st-kw-edit-input" defaultValue={kw.word} autoFocus
                          onBlur={e => { updateKeyword(kw.id,"word",e.target.value); setEditingKw(null); }} />
                      ) : (
                        <span className="st-kw-word" onClick={() => setEditingKw(kw.id)}>{kw.word}</span>
                      )}
                      <div className="st-kw-score-cell">
                        <input type="number" min="0" max="20" className="st-kw-score-input"
                          value={kw.score} onChange={e => updateKeyword(kw.id,"score",+e.target.value)} />
                      </div>
                      <div className="st-kw-bar-cell">
                        <div className="st-kw-bar-track">
                          <div className="st-kw-bar-fill" style={{
                            width:`${(kw.score/20)*100}%`,
                            background: kw.score>=8 ? "#ff1744" : kw.score>=5 ? "#ff6d00" : "#00e5ff",
                          }} />
                        </div>
                      </div>
                      <Toggle value={kw.enabled} onChange={v => updateKeyword(kw.id,"enabled",v)} color="#76ff03" />
                      <button className="st-kw-del" onClick={() => removeKeyword(kw.id)}>✕</button>
                    </div>
                  ))}
                </div>
                <div className="st-kw-add">
                  <div className="st-kw-add-title">ADD KEYWORD</div>
                  <div className="st-kw-add-row">
                    <input className="st-kw-add-input" placeholder="keyword..."
                      value={newKeyword.word}
                      onChange={e => setNewKeyword(p=>({...p,word:e.target.value}))}
                      onKeyDown={e => e.key==="Enter" && addKeyword()} />
                    <div className="st-kw-add-score-wrap">
                      <span className="st-kw-add-score-lbl">SCORE</span>
                      <input type="number" min="1" max="20" className="st-kw-score-input"
                        value={newKeyword.score}
                        onChange={e => setNewKeyword(p=>({...p,score:+e.target.value}))} />
                    </div>
                    <button className="st-kw-add-btn" onClick={addKeyword}>+ ADD</button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ══ THRESHOLDS ═════════════════════════════════════════════════ */}
          {activeSection === "thresholds" && (
            <div className="st-section">
              <div className="st-section-title">THREAT CLASSIFICATION THRESHOLDS</div>
              <div className="st-card">
                <div className="st-card-title">
                  LEVEL BOUNDARIES
                  <Tip text="Used live on every page. Change a threshold and the dashboard reflects it instantly — no refresh needed." />
                </div>
                {[
                  { key:"low",      label:"SAFE → LOW",      color:"#29b6f6", max:50  },
                  { key:"medium",   label:"LOW → MEDIUM",    color:"#ffa726", max:100 },
                  { key:"high",     label:"MEDIUM → HIGH",   color:"#ef5350", max:200 },
                  { key:"critical", label:"HIGH → CRITICAL", color:"#ff1744", max:500 },
                ].map(t => (
                  <div key={t.key} className="st-threshold-row">
                    <div className="st-thr-labels">
                      <span className="st-thr-name">{t.label}</span>
                      <span className="st-thr-val" style={{ color:t.color }}>score ≥ {config.thresholds[t.key]}</span>
                    </div>
                    <input type="range" min="0" max={t.max} className="st-slider"
                      style={{ "--sc":t.color }}
                      value={config.thresholds[t.key]}
                      onChange={e => set(`thresholds.${t.key}`, +e.target.value)} />
                    <div className="st-thr-num-wrap">
                      <input type="number" min="0" max={t.max} className="st-thr-num"
                        value={config.thresholds[t.key]}
                        onChange={e => set(`thresholds.${t.key}`, +e.target.value)} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="st-card">
                <div className="st-card-title">THRESHOLD PREVIEW — LIVE</div>
                <div className="st-thr-preview">
                  {[
                    { label:"SAFE",     color:"#76ff03", range:`0 – ${config.thresholds.low-1}` },
                    { label:"LOW",      color:"#29b6f6", range:`${config.thresholds.low} – ${config.thresholds.medium-1}` },
                    { label:"MEDIUM",   color:"#ffa726", range:`${config.thresholds.medium} – ${config.thresholds.high-1}` },
                    { label:"HIGH",     color:"#ef5350", range:`${config.thresholds.high} – ${config.thresholds.critical-1}` },
                    { label:"CRITICAL", color:"#ff1744", range:`${config.thresholds.critical}+` },
                  ].map(t => (
                    <div key={t.label} className="st-thr-prev-item">
                      <div className="st-thr-prev-badge"
                        style={{ background:`${t.color}18`, color:t.color, border:`1px solid ${t.color}55` }}>
                        {t.label}
                      </div>
                      <div className="st-thr-prev-range" style={{ color:t.color }}>{t.range}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ══ API & BACKEND ═══════════════════════════════════════════════ */}
          {activeSection === "api" && (
            <div className="st-section">
              <div className="st-section-title">API & BACKEND CONNECTION</div>
              <div className="st-card">
                <div className="st-card-title">CONNECTION</div>
                <div className="st-rows">
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Backend URL</div>
                      <div className="st-row-desc">FastAPI server endpoint — used by all pages globally</div>
                    </div>
                    <input className="st-url-input" value={config.api.backendUrl}
                      onChange={e => set("api.backendUrl", e.target.value)} />
                  </div>
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Request Timeout</div>
                      <div className="st-row-desc">Max wait for MPI analysis response</div>
                    </div>
                    <div className="st-num-input-wrap">
                      <input type="number" min="10" max="300" className="st-num-input"
                        value={config.api.requestTimeout}
                        onChange={e => set("api.requestTimeout", +e.target.value)} />
                      <span className="st-num-unit">sec</span>
                    </div>
                  </div>
                </div>
                <HealthCheck url={config.api.backendUrl} />
              </div>
              <div className="st-card">
                <div className="st-card-title">HISTORY</div>
                <div className="st-rows">
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Auto-save History</div>
                      <div className="st-row-desc">Persist analysis results after each run</div>
                    </div>
                    <Toggle value={config.api.autoSaveHistory}
                      onChange={v => set("api.autoSaveHistory", v)} />
                  </div>
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Max History Entries</div>
                      <div className="st-row-desc">Older entries are pruned automatically</div>
                    </div>
                    <div className="st-num-input-wrap">
                      <input type="number" min="10" max="1000" className="st-num-input"
                        value={config.api.maxHistoryEntries}
                        onChange={e => set("api.maxHistoryEntries", +e.target.value)} />
                      <span className="st-num-unit">entries</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ══ INTERFACE ════════════════════════════════════════════════════ */}
          {activeSection === "ui" && (
            <div className="st-section">
              <div className="st-section-title">INTERFACE PREFERENCES</div>
              <div className="st-card">
                <div className="st-card-title">APPEARANCE</div>
                <div className="st-rows">
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Accent Color</div>
                      <div className="st-row-desc">Changes globally across all pages instantly via CSS variable</div>
                    </div>
                    <div className="st-color-row">
                      {["#00e5ff","#76ff03","#d500f9","#ff6d00","#ffea00","#ff1744"].map(c => (
                        <button key={c}
                          className={`st-color-swatch ${config.ui.accentColor === c ? "st-color-active" : ""}`}
                          style={{ background:c, boxShadow:config.ui.accentColor===c?`0 0 12px ${c}`:"none" }}
                          onClick={() => set("ui.accentColor", c)} />
                      ))}
                      <input type="color" className="st-color-custom"
                        value={config.ui.accentColor}
                        onChange={e => set("ui.accentColor", e.target.value)} />
                    </div>
                  </div>
                  {[
                    { key:"ui.compactMode",       label:"Compact Mode",        desc:"Reduce padding on all pages",                   color:"#00e5ff" },
                    { key:"ui.showNodeActivity",  label:"Show Node Activity",  desc:"Display live node bars during analysis",        color:"#76ff03" },
                  ].map(f => (
                    <div key={f.key} className="st-row">
                      <div className="st-row-left">
                        <div className="st-row-label">{f.label}</div>
                        <div className="st-row-desc">{f.desc}</div>
                      </div>
                      <Toggle value={f.key.split(".").reduce((o,k)=>o[k], config)}
                        onChange={v => set(f.key, v)} color={f.color} />
                    </div>
                  ))}
                </div>
              </div>
              <div className="st-card">
                <div className="st-card-title">PERFORMANCE</div>
                <div className="st-rows">
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Animation Speed</div>
                      <div className="st-row-desc">Applies globally via --app-t CSS variable</div>
                    </div>
                    <select className="st-select" value={config.ui.animationSpeed}
                      onChange={e => set("ui.animationSpeed", e.target.value)}>
                      <option value="fast">Fast (100ms)</option>
                      <option value="normal">Normal (220ms)</option>
                      <option value="slow">Slow (400ms)</option>
                      <option value="none">None (disabled)</option>
                    </select>
                  </div>
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Terminal Line Speed</div>
                      <div className="st-row-desc">Delay between lines during analysis output</div>
                    </div>
                    <div className="st-num-input-wrap">
                      <input type="number" min="50" max="1000" step="50" className="st-num-input"
                        value={config.ui.terminalSpeed}
                        onChange={e => set("ui.terminalSpeed", +e.target.value)} />
                      <span className="st-num-unit">ms</span>
                    </div>
                  </div>
                  <div className="st-row">
                    <div className="st-row-left">
                      <div className="st-row-label">Chart Refresh Rate</div>
                      <div className="st-row-desc">Performance Lab live data interval</div>
                    </div>
                    <select className="st-select" value={config.ui.chartRefreshRate}
                      onChange={e => set("ui.chartRefreshRate", +e.target.value)}>
                      <option value={500}>500ms (high)</option>
                      <option value={1000}>1000ms (normal)</option>
                      <option value={2000}>2000ms (low)</option>
                      <option value={5000}>5000ms (minimal)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ══ DATA MGMT ════════════════════════════════════════════════════ */}
          {activeSection === "data" && (
            <div className="st-section">
              <div className="st-section-title">DATA MANAGEMENT</div>
              <div className="st-card">
                <div className="st-card-title">EXPORT CONFIG</div>
                <p className="st-card-desc">Download your current config as JSON. Use it as a backup or share across machines.</p>
                <button className="st-action-btn st-action-export" onClick={exportConfig}>
                  ⬇ EXPORT CONFIGURATION
                </button>
              </div>
              <div className="st-card">
                <div className="st-card-title">IMPORT CONFIG</div>
                <p className="st-card-desc">Paste a previously exported JSON config. All pages update instantly.</p>
                <textarea className="st-import-textarea"
                  placeholder='{ "mpi": { "processors": 8, ... } }'
                  value={importText}
                  onChange={e => { setImportText(e.target.value); setImportError(""); }} />
                {importError && <div className="st-import-error">{importError}</div>}
                <button className="st-action-btn st-action-import"
                  onClick={importConfig} disabled={!importText.trim()}>
                  ⬆ IMPORT & APPLY
                </button>
              </div>
              <div className="st-card st-card-danger">
                <div className="st-card-title">DANGER ZONE</div>
                <div className="st-danger-grid">
                  <div className="st-danger-item">
                    <div className="st-danger-label">Clear Analysis History</div>
                    <div className="st-danger-desc">Permanently deletes all entries from analysis_history.json</div>
                    <button className="st-danger-btn" onClick={clearHistory}>CLEAR HISTORY</button>
                  </div>
                  <div className="st-danger-item">
                    <div className="st-danger-label">Reset to Defaults</div>
                    <div className="st-danger-desc">Restores all settings to factory configuration</div>
                    <button className="st-danger-btn"
                      onClick={() => { if(window.confirm("Reset all settings?")) resetConfig(); }}>
                      RESET ALL SETTINGS
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}