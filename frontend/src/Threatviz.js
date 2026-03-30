import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, RadarChart, Radar,
  PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import "./Threatviz.css";
import { useKeywords, useThresholds } from "./Settingscontext";

// ─── Default sample logs for demo ─────────────────────────────────────────────
const SAMPLE_LOGS = `2026-03-20T04:49:52+00:00 | 12.191.134.71 | Attack:Port Scan | port=445 | status=SUCCESSFUL | severity=high | src=12.191.134.71 attack=Port Scan port=445 action=SUCCESSFUL sev=high
2026-03-20T05:46:48+00:00 | 61.90.152.79 | Attack:DDoS | port=21 | status=BLOCKED | severity=medium | src=61.90.152.79 attack=DDoS port=21 action=BLOCKED sev=medium peak_rps=75805
2026-03-21T18:26:26+00:00 | 32.204.3.115 | Attack:Brute Force | port=3389 | status=DETECTED | severity=low | src=32.204.3.115 attack=Brute Force port=3389 action=DETECTED sev=low
2026-03-20T22:47:37+00:00 | 129.250.138.141 | Attack:Port Scan | port=23 | status=BLOCKED | severity=high | src=129.250.138.141 attack=Port Scan port=23 action=BLOCKED sev=high
2026-03-20T18:15:43+00:00 | 162.158.4.141 | Attack:SQL Injection | port=3306 | status=MITIGATED | severity=low | src=162.158.4.141 attack=SQL Injection port=3306 action=MITIGATED sev=low
2026-03-20T21:28:00+00:00 | 172.203.181.82 | Attack:XSS | port=3306 | status=SUCCESSFUL | severity=high | src=172.203.181.82 attack=XSS port=3306 action=SUCCESSFUL sev=high
2026-03-21T06:54:09+00:00 | 72.159.14.167 | Attack:Port Scan | port=3389 | status=DETECTED | severity=high | src=72.159.14.167 attack=Port Scan port=3389 action=DETECTED sev=high
2026-03-21T17:38:09+00:00 | 185.158.91.99 | Attack:Malware | port=443 | status=DETECTED | severity=medium | src=185.158.91.99 attack=Malware port=443 action=DETECTED sev=medium
2026-03-20T11:17:16+00:00 | 72.148.63.123 | Attack:Credential Stuffing | port=22 | status=SUCCESSFUL | severity=high | src=72.148.63.123 attack=Credential Stuffing port=22 action=SUCCESSFUL sev=high pattern=login-failures
2026-03-20T16:28:05+00:00 | 87.90.87.12 | Attack:Brute Force | port=445 | status=SUCCESSFUL | severity=high | src=87.90.87.12 attack=Brute Force port=445 action=SUCCESSFUL sev=high pattern=login-failures`;

const LEVEL_COLOR = {
  SAFE:"#00e676", LOW:"#29b6f6", MEDIUM:"#ffa726", HIGH:"#ef5350", CRITICAL:"#ff1744",
};

// ─── Score a single line with keyword list ────────────────────────────────────
function scoreLine(line, keywords) {
  const lower  = line.toLowerCase();
  const hits   = [];
  let   total  = 0;
  keywords.forEach(kw => {
    if (!kw.enabled || !kw.word?.trim()) return;
    const word  = kw.word.toLowerCase().trim();
    let   count = 0, pos = 0;
    while ((pos = lower.indexOf(word, pos)) !== -1) { count++; pos += word.length; }
    if (count > 0) {
      hits.push({ word: kw.word, score: kw.score, count, total: kw.score * count });
      total += kw.score * count;
    }
  });
  return { total, hits };
}

function classifyScore(score, thresholds) {
  if (score <= 0)                              return "SAFE";
  if (score < (thresholds.low      ?? 10))    return "SAFE";
  if (score < (thresholds.medium   ?? 25))    return "LOW";
  if (score < (thresholds.high     ?? 50))    return "MEDIUM";
  if (score < (thresholds.critical ?? 100))   return "HIGH";
  return "CRITICAL";
}

// ─── Extract IPs from text ────────────────────────────────────────────────────
function extractIPs(text) {
  const re = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const all = [...new Set(text.match(re)||[])];
  return all;
}

// ─── Tooltip ──────────────────────────────────────────────────────────────────
const TVTip = ({ active, payload, label }) => {
  if (!active||!payload?.length) return null;
  return (
    <div className="tv-tooltip">
      <div className="tv-tt-label">{label}</div>
      {payload.map((p,i) => (
        <div key={i} style={{color:p.fill||p.color||"#fff"}}>
          {p.name}: <b>{p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Highlight text with keyword matches ──────────────────────────────────────
function HighlightedLine({ text, keywords }) {
  const lower = text.toLowerCase();
  const regions = [];
  keywords.forEach((kw, ki) => {
    if (!kw.enabled||!kw.word?.trim()) return;
    const word = kw.word.toLowerCase().trim();
    let pos = 0;
    while ((pos = lower.indexOf(word, pos)) !== -1) {
      regions.push({ start:pos, end:pos+word.length, kw, ki });
      pos += word.length;
    }
  });
  regions.sort((a,b) => a.start-b.start);

  const colors = ["#f97316","#06b6d4","#a855f7","#10b981","#f59e0b","#ef4444",
                  "#00e5ff","#76ff03","#d500f9","#ffea00"];
  const parts = [];
  let cur = 0;
  regions.forEach((r, i) => {
    if (r.start < cur) return;
    if (r.start > cur) parts.push({ text:text.slice(cur,r.start), hi:false });
    parts.push({ text:text.slice(r.start,r.end), hi:true, color:colors[r.ki%colors.length], score:r.kw.score });
    cur = r.end;
  });
  if (cur < text.length) parts.push({ text:text.slice(cur), hi:false });

  return (
    <span>
      {parts.map((p,i) => p.hi ? (
        <mark key={i} className="tv-highlight" style={{background:`${p.color}30`,color:p.color,
          border:`1px solid ${p.color}55`,borderRadius:3}}>
          {p.text}
          <span className="tv-score-badge">+{p.score}</span>
        </mark>
      ) : (
        <span key={i}>{p.text}</span>
      ))}
    </span>
  );
}

// ═══ MAIN ══════════════════════════════════════════════════════════════════════
export default function ThreatViz() {
  const keywords   = useKeywords();
  const thresholds = useThresholds();

  // ── Editor state ──────────────────────────────────────────────────────────
  const [logText,       setLogText]       = useState(SAMPLE_LOGS);
  const [activePanel,   setActivePanel]   = useState("score");  // score|highlight|ips|keywords|radar
  const [filterLevel,   setFilterLevel]   = useState("ALL");
  const [sortBy,        setSortBy]        = useState("score");   // score|line|hits
  const [sortDir,       setSortDir]       = useState("desc");
  const [selectedLine,  setSelectedLine]  = useState(null);
  const [searchKw,      setSearchKw]      = useState("");
  const [showOnlyHits,  setShowOnlyHits]  = useState(false);
  const [highlightMode, setHighlightMode] = useState(true);
  const [customKws,     setCustomKws]     = useState([]);  // extra test keywords
  const [newKw,         setNewKw]         = useState("");
  const [newKwScore,    setNewKwScore]    = useState(5);
  const [copyMsg,       setCopyMsg]       = useState("");

  // ── Merge live keywords with custom test keywords ─────────────────────────
  const allKeywords = useMemo(() => [
    ...keywords,
    ...customKws.map((k,i) => ({ ...k, id:`custom_${i}`, enabled:true })),
  ], [keywords, customKws]);

  // ── Parse and score every line ────────────────────────────────────────────
  const lines = useMemo(() => {
    return logText.split(/\r?\n/)
      .map((text, i) => {
        const trimmed = text.trim();
        if (!trimmed) return null;
        const { total, hits } = scoreLine(trimmed, allKeywords);
        const level = classifyScore(total, thresholds);
        return { i, text: trimmed, score: total, hits, level };
      })
      .filter(Boolean);
  }, [logText, allKeywords, thresholds]);

  // ── Global stats ──────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    if (!lines.length) return null;
    const scores    = lines.map(l => l.score);
    const total     = scores.reduce((s,v)=>s+v, 0);
    const levelCounts = {};
    lines.forEach(l => levelCounts[l.level] = (levelCounts[l.level]||0)+1);
    const topHit = {};
    lines.forEach(l => l.hits.forEach(h => {
      topHit[h.word] = (topHit[h.word]||0) + h.total;
    }));
    return {
      totalLines:   lines.length,
      totalScore:   total,
      avgScore:     total / lines.length,
      maxScore:     Math.max(...scores),
      hitLines:     lines.filter(l=>l.score>0).length,
      cleanLines:   lines.filter(l=>l.score===0).length,
      levelCounts,
      overallLevel: classifyScore(Math.round(total/lines.length), thresholds),
      topKeywords:  Object.entries(topHit)
        .sort((a,b)=>b[1]-a[1]).slice(0,8)
        .map(([word,score]) => ({ word, score })),
    };
  }, [lines, thresholds]);

  // ── IP extraction ─────────────────────────────────────────────────────────
  const ips = useMemo(() => {
    const ipLines = {};
    lines.forEach(l => {
      extractIPs(l.text).forEach(ip => {
        if (!ipLines[ip]) ipLines[ip] = { ip, lines:0, score:0 };
        ipLines[ip].lines++;
        ipLines[ip].score += l.score;
      });
    });
    return Object.values(ipLines).sort((a,b)=>b.score-a.score);
  }, [lines]);

  // ── Keyword frequency ─────────────────────────────────────────────────────
  const kwFrequency = useMemo(() => {
    const freq = {};
    lines.forEach(l => l.hits.forEach(h => {
      if (!freq[h.word]) freq[h.word] = { word:h.word, hits:0, score:0, lines:0 };
      freq[h.word].hits  += h.count;
      freq[h.word].score += h.total;
      freq[h.word].lines++;
    }));
    return Object.values(freq).sort((a,b)=>b.score-a.score);
  }, [lines]);

  // ── Radar data (threat categories from keywords) ──────────────────────────
  const radarData = useMemo(() => {
    const cats = {
      "Network":     ["port","scan","ddos","network"],
      "Malware":     ["malware","trojan","virus"],
      "Auth":        ["brute","failed","login-failures","credential stuffing","unauthorized"],
      "Injection":   ["sql","xss","injection"],
      "Phishing":    ["phishing"],
      "Anomaly":     ["anomalous","suspicious","detected"],
    };
    return Object.entries(cats).map(([cat, words]) => {
      let score = 0;
      lines.forEach(l => l.hits.forEach(h => {
        if (words.some(w => h.word.toLowerCase().includes(w))) score += h.total;
      }));
      return { cat, score };
    });
  }, [lines]);

  // ── Filtered + sorted line table ──────────────────────────────────────────
  const displayLines = useMemo(() => {
    let out = [...lines];
    if (filterLevel !== "ALL")  out = out.filter(l => l.level === filterLevel);
    if (showOnlyHits)            out = out.filter(l => l.score > 0);
    if (searchKw.trim()) {
      const q = searchKw.toLowerCase();
      out = out.filter(l => l.text.toLowerCase().includes(q) ||
                            l.hits.some(h => h.word.toLowerCase().includes(q)));
    }
    out.sort((a,b) => {
      if (sortBy==="score") return sortDir==="desc" ? b.score-a.score : a.score-b.score;
      if (sortBy==="hits")  return sortDir==="desc" ? b.hits.length-a.hits.length : a.hits.length-b.hits.length;
      return sortDir==="desc" ? b.i-a.i : a.i-b.i;
    });
    return out;
  }, [lines, filterLevel, showOnlyHits, searchKw, sortBy, sortDir]);

  // ── Export scored report ──────────────────────────────────────────────────
  const exportReport = () => {
    const rows = ["Line,Score,Level,Keywords,Text"];
    lines.forEach(l => {
      rows.push([
        l.i+1, l.score, l.level,
        `"${l.hits.map(h=>h.word).join(";")}"`  ,
        `"${l.text.replace(/"/g,"'")}"`,
      ].join(","));
    });
    const blob = new Blob([rows.join("\n")], {type:"text/csv"});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a"); a.href=url;
    a.download = `threat_analysis_${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const copyStats = () => {
    if (!stats) return;
    const text = `Threat Analysis Report\nLines: ${stats.totalLines}\nTotal Score: ${stats.totalScore}\nAvg Score: ${stats.avgScore.toFixed(1)}\nOverall Level: ${stats.overallLevel}`;
    navigator.clipboard.writeText(text).then(()=>{
      setCopyMsg("Copied!"); setTimeout(()=>setCopyMsg(""),1500);
    });
  };

  const addCustomKw = () => {
    if (!newKw.trim()) return;
    setCustomKws(prev => [...prev, { word:newKw.trim(), score:Number(newKwScore) }]);
    setNewKw(""); setNewKwScore(5);
  };

  // ──────────────────────────────────────────────────────────────────────────
  return (
    <div className="tv-page">
      <div className="tv-scanline"/>

      {/* ── Header ── */}
      <div className="tv-header">
        <div>
          <div className="tv-title">THREAT INTELLIGENCE WORKBENCH</div>
          <div className="tv-subtitle">
            Live log parser · real-time keyword scoring · instant forensics · no upload needed
          </div>
        </div>
        <div className="tv-header-actions">
          <button className="tv-btn tv-btn-ghost" onClick={()=>setLogText("")}>✕ Clear</button>
          <button className="tv-btn tv-btn-ghost" onClick={()=>setLogText(SAMPLE_LOGS)}>⊞ Sample</button>
          <button className="tv-btn tv-btn-export" onClick={exportReport} disabled={!lines.length}>
            ⬇ Export CSV
          </button>
          <button className="tv-btn tv-btn-ghost" onClick={copyStats}>
            {copyMsg || "⧉ Copy Stats"}
          </button>
        </div>
      </div>

      {/* ── Main Layout: Editor | Analysis ── */}
      <div className="tv-workspace">

        {/* LEFT: Log editor */}
        <div className="tv-editor-panel">
          <div className="tv-panel-header">
            <span className="tv-panel-title">LOG INPUT</span>
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <label className="tv-toggle-label">
                <input type="checkbox" checked={highlightMode}
                  onChange={e=>setHighlightMode(e.target.checked)}/>
                <span>Highlight</span>
              </label>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                color:"rgba(255,255,255,0.25)"}}>
                {lines.length} lines
              </span>
            </div>
          </div>

          {highlightMode ? (
            /* Highlighted read view with overlaid editor */
            <div className="tv-editor-wrap">
              <div className="tv-highlighted-view">
                {lines.length === 0 ? (
                  <div className="tv-empty-hint">Paste log lines here to start analysis…</div>
                ) : (
                  <div className="tv-line-list">
                    {lines.map((l,i) => {
                      const c = LEVEL_COLOR[l.level]||"#666";
                      return (
                        <div key={i}
                          className={`tv-log-line ${selectedLine===l.i?"tv-line-selected":""}`}
                          onClick={()=>setSelectedLine(selectedLine===l.i?null:l.i)}
                          style={{borderLeft:`3px solid ${l.score>0?c:"rgba(255,255,255,0.05)"}`}}>
                          <span className="tv-line-num">{l.i+1}</span>
                          <span className="tv-line-score" style={{color:c,opacity:l.score>0?1:0.3}}>
                            {l.score}
                          </span>
                          <span className="tv-line-body">
                            <HighlightedLine text={l.text} keywords={allKeywords}/>
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
              <textarea
                className="tv-editor-ghost"
                value={logText}
                onChange={e=>setLogText(e.target.value)}
                placeholder="Paste log lines here…"
                spellCheck={false}
              />
            </div>
          ) : (
            <textarea
              className="tv-editor-plain"
              value={logText}
              onChange={e=>setLogText(e.target.value)}
              placeholder="Paste log lines here…"
              spellCheck={false}
            />
          )}
        </div>

        {/* RIGHT: Analysis panels */}
        <div className="tv-analysis-panel">

          {/* Panel tabs */}
          <div className="tv-panel-tabs">
            {[
              {id:"score",    label:"Score"},
              {id:"highlight",label:"Lines"},
              {id:"ips",      label:"IPs"},
              {id:"keywords", label:"Keywords"},
              {id:"radar",    label:"Radar"},
            ].map(t => (
              <button key={t.id}
                className={`tv-ptab ${activePanel===t.id?"tv-ptab-active":""}`}
                onClick={()=>setActivePanel(t.id)}>
                {t.label}
              </button>
            ))}
          </div>

          {/* ── SCORE panel ── */}
          {activePanel === "score" && (
            <div className="tv-pane">
              {!stats ? (
                <div className="tv-pane-empty">Paste logs on the left to analyse</div>
              ) : (
                <>
                  {/* Overall score ring */}
                  <div className="tv-score-hero">
                    <div className="tv-score-ring-wrap">
                      {(() => {
                        const max  = Math.max(stats.maxScore * 1.2, 100);
                        const pct  = Math.min(stats.avgScore / max, 1);
                        const c    = LEVEL_COLOR[stats.overallLevel];
                        const R    = 56, circ = 2*Math.PI*R;
                        return (
                          <svg width="140" height="140" viewBox="0 0 140 140">
                            <circle cx="70" cy="70" r={R} fill="none"
                              stroke="rgba(255,255,255,0.06)" strokeWidth="10"/>
                            <circle cx="70" cy="70" r={R} fill="none"
                              stroke={c} strokeWidth="10" strokeLinecap="round"
                              strokeDasharray={`${pct*circ} ${circ}`}
                              strokeDashoffset={circ/4}
                              style={{transition:"stroke-dasharray 0.8s ease",
                                filter:`drop-shadow(0 0 8px ${c})`}}/>
                            <text x="70" y="63" textAnchor="middle"
                              fontFamily="Orbitron" fontSize="22" fontWeight="900" fill={c}>
                              {Math.round(stats.avgScore)}
                            </text>
                            <text x="70" y="78" textAnchor="middle"
                              fontFamily="Rajdhani" fontSize="10" fill="rgba(255,255,255,0.35)">
                              AVG SCORE
                            </text>
                            <text x="70" y="93" textAnchor="middle"
                              fontFamily="Orbitron" fontSize="9" fontWeight="700" fill={c}>
                              {stats.overallLevel}
                            </text>
                          </svg>
                        );
                      })()}
                    </div>

                    <div className="tv-score-stats">
                      {[
                        {label:"Lines",       val:stats.totalLines,            color:"#06b6d4"},
                        {label:"Total Score", val:stats.totalScore,            color:LEVEL_COLOR[stats.overallLevel]},
                        {label:"Max Line",    val:stats.maxScore,              color:"#ff1744"},
                        {label:"Hits",        val:stats.hitLines,              color:"#ffa726"},
                        {label:"Clean",       val:stats.cleanLines,            color:"#10b981"},
                      ].map((s,i) => (
                        <div key={i} className="tv-stat-row">
                          <span className="tv-stat-lbl">{s.label}</span>
                          <span className="tv-stat-val" style={{color:s.color}}>{s.val.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Level breakdown bars */}
                  <div className="tv-level-bars">
                    {Object.entries(LEVEL_COLOR).map(([level, color]) => {
                      const count = stats.levelCounts[level]||0;
                      const pct = stats.totalLines > 0 ? (count/stats.totalLines)*100 : 0;
                      return (
                        <div key={level} className="tv-level-row"
                          onClick={()=>setFilterLevel(filterLevel===level?"ALL":level)}
                          style={{cursor:"pointer",opacity:filterLevel!=="ALL"&&filterLevel!==level?0.35:1}}>
                          <span className="tv-level-lbl" style={{color}}>{level}</span>
                          <div className="tv-level-track">
                            <div className="tv-level-fill"
                              style={{width:`${pct}%`,background:color,boxShadow:`0 0 6px ${color}55`}}/>
                          </div>
                          <span className="tv-level-count" style={{color}}>{count}</span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Top keywords bar chart */}
                  {stats.topKeywords.length > 0 && (
                    <>
                      <div className="tv-section-title">TOP KEYWORD CONTRIBUTIONS</div>
                      <ResponsiveContainer width="100%" height={150}>
                        <BarChart data={stats.topKeywords} barCategoryGap="20%"
                          margin={{top:4,right:8,left:-30,bottom:0}}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                          <XAxis dataKey="word" tick={{fill:"rgba(255,255,255,0.35)",fontSize:9}}
                            axisLine={false} tickLine={false}/>
                          <YAxis tick={{fill:"rgba(255,255,255,0.25)",fontSize:8}} axisLine={false} tickLine={false}/>
                          <Tooltip content={<TVTip/>} cursor={{fill:"rgba(255,255,255,0.02)"}}/>
                          <Bar dataKey="score" name="Score" radius={[3,3,0,0]}>
                            {stats.topKeywords.map((_,i) => {
                              const colors=["#f97316","#06b6d4","#a855f7","#10b981","#f59e0b","#ef4444","#00e5ff","#76ff03"];
                              return <Cell key={i} fill={colors[i%colors.length]}
                                style={{filter:`drop-shadow(0 0 4px ${colors[i%colors.length]}66)`}}/>;
                            })}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </>
                  )}
                </>
              )}
            </div>
          )}

          {/* ── LINES panel ── */}
          {activePanel === "highlight" && (
            <div className="tv-pane tv-pane-lines">
              <div className="tv-lines-controls">
                <input className="tv-search-input" placeholder="⌕ search lines..."
                  value={searchKw} onChange={e=>setSearchKw(e.target.value)}/>
                <div className="tv-sort-group">
                  {["score","hits","line"].map(s => (
                    <button key={s}
                      className={`tv-sort-btn ${sortBy===s?"tv-sort-active":""}`}
                      onClick={()=>{ setSortBy(s); setSortDir(d=>sortBy===s?(d==="asc"?"desc":"asc"):"desc"); }}>
                      {s}{sortBy===s?(sortDir==="asc"?"↑":"↓"):""}
                    </button>
                  ))}
                </div>
                <label className="tv-toggle-label" style={{fontSize:11}}>
                  <input type="checkbox" checked={showOnlyHits}
                    onChange={e=>setShowOnlyHits(e.target.checked)}/>
                  <span>Hits only</span>
                </label>
                <div className="tv-filter-pills">
                  {["ALL",...Object.keys(LEVEL_COLOR)].map(l => (
                    <button key={l}
                      className={`tv-pill ${filterLevel===l?"tv-pill-active":""}`}
                      style={filterLevel===l&&l!=="ALL"?{color:LEVEL_COLOR[l],borderColor:`${LEVEL_COLOR[l]}66`}:{}}
                      onClick={()=>setFilterLevel(l)}>{l}</button>
                  ))}
                </div>
              </div>

              <div className="tv-lines-table">
                {displayLines.length === 0 ? (
                  <div className="tv-pane-empty">No lines match current filters</div>
                ) : (
                  displayLines.map((l, i) => {
                    const c = LEVEL_COLOR[l.level]||"#666";
                    const isSel = selectedLine === l.i;
                    return (
                      <div key={i} className={`tv-tbl-row ${isSel?"tv-tbl-selected":""}`}
                        style={{borderLeft:`3px solid ${l.score>0?c:"rgba(255,255,255,0.04)"}`}}
                        onClick={()=>setSelectedLine(isSel?null:l.i)}>
                        <div className="tv-tbl-meta">
                          <span className="tv-tbl-num">#{l.i+1}</span>
                          <span className="tv-tbl-score"
                            style={{color:c,background:`${c}18`,border:`1px solid ${c}44`}}>
                            {l.score}
                          </span>
                          {l.hits.length > 0 && (
                            <div className="tv-tbl-hits">
                              {l.hits.slice(0,4).map((h,j)=>(
                                <span key={j} className="tv-hit-chip">{h.word}×{h.count}</span>
                              ))}
                              {l.hits.length>4&&<span className="tv-hit-chip">+{l.hits.length-4}</span>}
                            </div>
                          )}
                        </div>
                        <div className="tv-tbl-text">
                          <HighlightedLine text={l.text} keywords={allKeywords}/>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
              {displayLines.length > 0 && (
                <div className="tv-lines-footer">
                  {displayLines.length} of {lines.length} lines
                </div>
              )}
            </div>
          )}

          {/* ── IPs panel ── */}
          {activePanel === "ips" && (
            <div className="tv-pane">
              <div className="tv-section-title">EXTRACTED IP ADDRESSES</div>
              {ips.length === 0 ? (
                <div className="tv-pane-empty">No IP addresses found in logs</div>
              ) : (
                <>
                  <div className="tv-ip-list">
                    {ips.map((ip, i) => {
                      const isPrivate = ip.ip.startsWith("192.168")||ip.ip.startsWith("10.")||ip.ip.startsWith("172.");
                      const maxScore  = Math.max(...ips.map(x=>x.score),1);
                      return (
                        <div key={i} className="tv-ip-row">
                          <div className="tv-ip-indicator"
                            style={{background:isPrivate?"rgba(41,182,246,0.15)":"rgba(239,83,80,0.15)",
                              border:`1px solid ${isPrivate?"rgba(41,182,246,0.3)":"rgba(239,83,80,0.3)"}`,
                              color:isPrivate?"#29b6f6":"#ef5350"}}>
                            {isPrivate?"INT":"EXT"}
                          </div>
                          <span className="tv-ip-addr">{ip.ip}</span>
                          <div className="tv-ip-bar-wrap">
                            <div className="tv-ip-bar"
                              style={{width:`${(ip.score/maxScore)*100}%`,
                                background:isPrivate?"#29b6f6":"#ef5350",
                                boxShadow:`0 0 6px ${isPrivate?"#29b6f6":"#ef5350"}55`}}/>
                          </div>
                          <span className="tv-ip-score"
                            style={{color:isPrivate?"#29b6f6":"#ef5350"}}>
                            {ip.score}
                          </span>
                          <span className="tv-ip-lines">{ip.lines}L</span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="tv-ip-summary">
                    <span style={{color:"#ef5350",fontSize:11}}>
                      {ips.filter(ip=>!ip.ip.startsWith("192.168")&&!ip.ip.startsWith("10.")&&!ip.ip.startsWith("172.")).length} external
                    </span>
                    <span style={{color:"rgba(255,255,255,0.25)",margin:"0 6px"}}>/</span>
                    <span style={{color:"#29b6f6",fontSize:11}}>
                      {ips.filter(ip=>ip.ip.startsWith("192.168")||ip.ip.startsWith("10.")||ip.ip.startsWith("172.")).length} internal
                    </span>
                    <span style={{color:"rgba(255,255,255,0.25)",margin:"0 6px"}}>/</span>
                    <span style={{color:"rgba(255,255,255,0.45)",fontSize:11}}>{ips.length} unique IPs</span>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ── KEYWORDS panel ── */}
          {activePanel === "keywords" && (
            <div className="tv-pane">
              <div className="tv-section-title">KEYWORD HIT FREQUENCY</div>
              {kwFrequency.length === 0 ? (
                <div className="tv-pane-empty">No keyword matches in current logs</div>
              ) : (
                <div className="tv-kw-freq-list">
                  {kwFrequency.map((k,i) => {
                    const maxS = Math.max(...kwFrequency.map(x=>x.score),1);
                    const colors=["#f97316","#06b6d4","#a855f7","#10b981","#f59e0b","#ef4444","#00e5ff","#76ff03"];
                    const c = colors[i%colors.length];
                    return (
                      <div key={i} className="tv-kw-freq-row">
                        <span className="tv-kw-freq-word" style={{color:c}}>{k.word}</span>
                        <div className="tv-kw-freq-track">
                          <div className="tv-kw-freq-fill"
                            style={{width:`${(k.score/maxS)*100}%`,background:c,boxShadow:`0 0 6px ${c}55`}}/>
                        </div>
                        <div className="tv-kw-freq-nums">
                          <span style={{color:c,fontFamily:"'Orbitron',monospace",fontSize:12,fontWeight:700}}>{k.score}</span>
                          <span style={{color:"rgba(255,255,255,0.3)",fontSize:10}}>{k.hits}×</span>
                          <span style={{color:"rgba(255,255,255,0.2)",fontSize:10}}>{k.lines}L</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Custom keyword tester */}
              <div className="tv-section-title" style={{marginTop:20}}>TEST CUSTOM KEYWORDS</div>
              <div className="tv-custom-kw-form">
                <input className="tv-kw-input" placeholder="keyword to test..."
                  value={newKw} onChange={e=>setNewKw(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&addCustomKw()}/>
                <input className="tv-kw-score-input" type="number" min="1" max="20"
                  value={newKwScore} onChange={e=>setNewKwScore(Number(e.target.value))}/>
                <button className="tv-btn tv-btn-add" onClick={addCustomKw}>+ADD</button>
              </div>
              {customKws.length > 0 && (
                <div className="tv-custom-kw-list">
                  {customKws.map((k,i) => (
                    <div key={i} className="tv-custom-kw-row">
                      <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"#f97316"}}>{k.word}</span>
                      <span style={{fontFamily:"'Orbitron',monospace",fontSize:11,color:"rgba(255,255,255,0.4)"}}>×{k.score}</span>
                      <button className="tv-kw-remove"
                        onClick={()=>setCustomKws(prev=>prev.filter((_,j)=>j!==i))}>✕</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── RADAR panel ── */}
          {activePanel === "radar" && (
            <div className="tv-pane">
              <div className="tv-section-title">THREAT CATEGORY RADAR</div>
              {radarData.every(d=>d.score===0) ? (
                <div className="tv-pane-empty">No threat data to plot</div>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={260}>
                    <RadarChart data={radarData} margin={{top:10,right:30,left:30,bottom:10}}>
                      <PolarGrid stroke="rgba(255,255,255,0.07)"/>
                      <PolarAngleAxis dataKey="cat"
                        tick={{fill:"rgba(255,255,255,0.5)",fontSize:11,fontFamily:"Rajdhani",fontWeight:600}}/>
                      <PolarRadiusAxis angle={30} tick={{fill:"rgba(255,255,255,0.15)",fontSize:8}} axisLine={false}/>
                      <Radar name="Score" dataKey="score" stroke="#f97316"
                        fill="#f97316" fillOpacity={0.2} strokeWidth={2}
                        dot={{fill:"#f97316",r:3}}/>
                      <Tooltip content={<TVTip/>}/>
                    </RadarChart>
                  </ResponsiveContainer>
                  <div className="tv-radar-legend">
                    {radarData.filter(d=>d.score>0).sort((a,b)=>b.score-a.score).map((d,i)=>(
                      <div key={i} className="tv-radar-row">
                        <span style={{color:"#f97316",fontFamily:"'Rajdhani',sans-serif",fontSize:12,fontWeight:600,flex:1}}>{d.cat}</span>
                        <div style={{flex:2,height:5,background:"rgba(255,255,255,0.06)",borderRadius:3,overflow:"hidden",margin:"0 10px"}}>
                          <div style={{width:`${(d.score/Math.max(...radarData.map(x=>x.score),1))*100}%`,
                            height:"100%",background:"#f97316",borderRadius:3}}/>
                        </div>
                        <span style={{fontFamily:"'Orbitron',monospace",fontSize:11,color:"#f97316",fontWeight:700,width:40,textAlign:"right"}}>{d.score}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

        </div>
      </div>

      {/* ── Selected line detail ── */}
      {selectedLine !== null && lines.find(l=>l.i===selectedLine) && (() => {
        const l = lines.find(x=>x.i===selectedLine);
        const c = LEVEL_COLOR[l.level];
        return (
          <div className="tv-detail-bar">
            <div className="tv-detail-header">
              <span style={{fontFamily:"'Orbitron',monospace",fontSize:11,color:c,letterSpacing:2}}>
                LINE {l.i+1} — {l.level}
              </span>
              <span style={{fontFamily:"'Orbitron',monospace",fontSize:13,color:c,fontWeight:900}}>
                SCORE: {l.score}
              </span>
              <button className="tv-close-btn" onClick={()=>setSelectedLine(null)}>✕</button>
            </div>
            <div className="tv-detail-body">
              <HighlightedLine text={l.text} keywords={allKeywords}/>
            </div>
            {l.hits.length > 0 && (
              <div className="tv-detail-hits">
                {l.hits.map((h,i)=>{
                  const colors=["#f97316","#06b6d4","#a855f7","#10b981","#f59e0b","#ef4444","#00e5ff","#76ff03"];
                  return(
                    <div key={i} className="tv-detail-hit"
                      style={{background:`${colors[i%colors.length]}15`,
                        border:`1px solid ${colors[i%colors.length]}44`,
                        color:colors[i%colors.length]}}>
                      <span style={{fontWeight:700}}>{h.word}</span>
                      <span style={{opacity:0.6,fontSize:10}}>×{h.count} = +{h.total}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}