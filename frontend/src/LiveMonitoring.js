import React, {
  useState, useEffect, useRef, useMemo, useCallback,
} from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import "./LiveMonitoring.css";
import { useApiConfig } from "./Settingscontext";

// ─── Constants ─────────────────────────────────────────────────────────────────
const LEVEL_COLOR = {
  SAFE:"#00e676", LOW:"#29b6f6", MEDIUM:"#ffa726", HIGH:"#ef5350", CRITICAL:"#ff1744",
};
const EVENT_META = {
  analysis_start: { icon:"⚡", label:"Analysis Started",  color:"#06b6d4" },
  analysis_done:  { icon:"✓", label:"Analysis Complete",  color:"#10b981" },
  connected:      { icon:"⬡", label:"Device Connected",   color:"#a855f7" },
  disconnected:   { icon:"◌", label:"Device Left",        color:"rgba(255,255,255,0.3)" },
  folder_scan:    { icon:"📂", label:"Folder Scan",        color:"#f97316" },
};
const fmt = (n) => Number(n||0).toLocaleString();

// ─── Tooltips ──────────────────────────────────────────────────────────────────
const LmTip = ({ active, payload, label }) => {
  if (!active||!payload?.length) return null;
  return (
    <div className="lm-tooltip">
      <div className="lm-tt-lbl">{label}</div>
      {payload.map((p,i)=>(
        <div key={i} style={{color:p.fill||p.color||"#fff"}}>
          {p.name}: <b>{p.value}</b>
        </div>
      ))}
    </div>
  );
};

// ─── Pulsing dot ───────────────────────────────────────────────────────────────
function PulseDot({ color="#10b981", size=10 }) {
  return (
    <span className="lm-pulse-wrap" style={{"--pc":color,"--ps":`${size}px`}}>
      <span className="lm-pulse-ring"/>
      <span className="lm-pulse-core" style={{background:color}}/>
    </span>
  );
}

// ─── Device card ───────────────────────────────────────────────────────────────
function DeviceCard({ client, activityMap }) {
  const events = activityMap[client.client_ip] || [];
  const lastEvent = events[events.length-1];
  const isActive  = lastEvent && lastEvent.type==="analysis_start" &&
    Date.now() - new Date(lastEvent.ts_iso).getTime() < 10000;
  const analyses  = events.filter(e=>e.type==="analysis_done").length;

  return (
    <div className={`lm-device-card ${isActive?"lm-device-active":""}`}>
      <div className="lm-device-header">
        <PulseDot color={isActive?"#f97316":"#10b981"}/>
        <div className="lm-device-name">{client.name}</div>
        {isActive&&(
          <span className="lm-device-badge lm-badge-analyzing">ANALYSING</span>
        )}
      </div>
      <div className="lm-device-ip">{client.client_ip}</div>
      <div className="lm-device-stats">
        <div className="lm-dstat">
          <div className="lm-dstat-val">{analyses}</div>
          <div className="lm-dstat-lbl">Analyses</div>
        </div>
        <div className="lm-dstat">
          <div className="lm-dstat-val" style={{fontSize:10}}>
            {client.connected_at
              ? new Date(client.connected_at).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})
              : "—"}
          </div>
          <div className="lm-dstat-lbl">Joined</div>
        </div>
        <div className="lm-dstat">
          <div className="lm-dstat-val">
            {lastEvent
              ? new Date(lastEvent.ts_iso).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})
              : "—"}
          </div>
          <div className="lm-dstat-lbl">Last Activity</div>
        </div>
      </div>
      {lastEvent?.type==="analysis_done" && lastEvent.data && (
        <div className="lm-device-last">
          <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,
            color:"rgba(255,255,255,0.35)"}}>last: </span>
          <span style={{color:LEVEL_COLOR[lastEvent.data.threat_level]||"#fff",
            fontFamily:"'Orbitron',monospace",fontSize:11,fontWeight:700}}>
            {lastEvent.data.threat_level} ({lastEvent.data.global_threat_score})
          </span>
          <span style={{color:"rgba(255,255,255,0.3)",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
            marginLeft:6,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:120}}>
            {lastEvent.data.file_name}
          </span>
        </div>
      )}
    </div>
  );
}

// ─── Activity row ──────────────────────────────────────────────────────────────
function ActivityRow({ event, isNew }) {
  const meta = EVENT_META[event.type] || {icon:"◈",label:event.type,color:"#fff"};
  const d    = event.data || {};
  const time = event.ts_iso
    ? new Date(event.ts_iso).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})
    : event.timestamp;

  return (
    <div className={`lm-activity-row ${isNew?"lm-activity-new":""}`}
      style={{borderLeft:`3px solid ${meta.color}`}}>
      <div className="lm-act-icon" style={{color:meta.color}}>{meta.icon}</div>
      <div className="lm-act-body">
        <div className="lm-act-title" style={{color:meta.color}}>{meta.label}</div>
        <div className="lm-act-detail">
          {event.type==="analysis_done" && d.file_name && (
            <>
              <span style={{color:"rgba(255,255,255,0.5)"}}>{d.file_name}</span>
              {" · "}
              <span style={{color:LEVEL_COLOR[d.threat_level]||"#fff",fontWeight:700,
                fontFamily:"'Orbitron',monospace",fontSize:10}}>
                {d.threat_level}
              </span>
              {" · score "}
              <span style={{color:LEVEL_COLOR[d.threat_level]||"#fff",fontFamily:"'Orbitron',monospace",
                fontSize:10,fontWeight:700}}>
                {d.global_threat_score}
              </span>
              {d.total_logs && ` · ${fmt(d.total_logs)} logs`}
            </>
          )}
          {event.type==="analysis_start" && d.file_name && (
            <span style={{color:"rgba(255,255,255,0.5)"}}>
              {d.file_name} ({d.file_format}) · {d.processors} processors
            </span>
          )}
          {(event.type==="connected"||event.type==="disconnected") && (
            <span style={{color:"rgba(255,255,255,0.5)"}}>
              {d.name} @ {d.client_ip}
              {d.total_connected!==undefined && ` · ${d.total_connected} online`}
            </span>
          )}
        </div>
      </div>
      <div className="lm-act-meta">
        <div className="lm-act-ip">{event.client_ip}</div>
        <div className="lm-act-time">{time}</div>
      </div>
    </div>
  );
}

// ═══ MAIN ══════════════════════════════════════════════════════════════════════
export default function LiveMonitoring() {
  const { backendUrl } = useApiConfig();

  // ── State ──────────────────────────────────────────────────────────────────
  const [wsStatus,    setWsStatus]    = useState("disconnected"); // connecting|connected|disconnected|error
  const [events,      setEvents]      = useState([]);
  const [clients,     setClients]     = useState([]);
  const [stats,       setStats]       = useState(null);
  const [newEventIds, setNewEventIds] = useState(new Set());
  const [autoScroll,  setAutoScroll]  = useState(true);
  const [filterType,  setFilterType]  = useState("all");
  const [myName,      setMyName]      = useState(() =>
    localStorage.getItem("lm_display_name") || "Analyst"
  );
  const [editingName, setEditingName] = useState(false);
  const [nameInput,   setNameInput]   = useState(myName);
  const [soundOn,     setSoundOn]     = useState(false);
  const [showCopyBox, setShowCopyBox] = useState(false);

  const wsRef       = useRef(null);
  const feedRef     = useRef(null);
  const pingRef     = useRef(null);
  const statsRef    = useRef(null);
  const reconnectRef= useRef(null);
  const audioCtx    = useRef(null);

  // ── Build WS URL from backendUrl ──────────────────────────────────────────
  const wsUrl = useMemo(() => {
    const base = backendUrl.replace(/^http/, "ws");
    const name = encodeURIComponent(myName);
    return `${base}/ws/monitor?name=${name}`;
  }, [backendUrl, myName]);

  // ── Beep on critical ─────────────────────────────────────────────────────
  const beep = useCallback(() => {
    if (!soundOn) return;
    try {
      if (!audioCtx.current) audioCtx.current = new AudioContext();
      const osc  = audioCtx.current.createOscillator();
      const gain = audioCtx.current.createGain();
      osc.connect(gain); gain.connect(audioCtx.current.destination);
      osc.frequency.value = 880; osc.type = "sine";
      gain.gain.setValueAtTime(0.3, audioCtx.current.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.current.currentTime+0.3);
      osc.start(); osc.stop(audioCtx.current.currentTime+0.3);
    } catch {}
  }, [soundOn]);

  // ── Add events helper ────────────────────────────────────────────────────
  const addEvent = useCallback((event) => {
    setEvents(prev => {
      const next = [...prev, event];
      return next.length > 200 ? next.slice(-200) : next;
    });
    setNewEventIds(prev => {
      const s = new Set(prev);
      s.add(event.id);
      setTimeout(() => setNewEventIds(p => { const n=new Set(p); n.delete(event.id); return n; }), 2000);
      return s;
    });
    if (event.type==="analysis_done" &&
        ["CRITICAL","HIGH"].includes(event.data?.threat_level)) beep();
  }, [beep]);

  // ── Fetch stats periodically ──────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/monitor/stats`);
      if (res.ok) setStats(await res.json());
    } catch {}
  }, [backendUrl]);

  const fetchClients = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/monitor/clients`);
      if (res.ok) {
        const d = await res.json();
        setClients(d.clients || []);
      }
    } catch {}
  }, [backendUrl]);

  // ── WebSocket connect ─────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState < 2) return;
    setWsStatus("connecting");

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus("connected");
      // Start keepalive ping every 20s
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:"ping"}));
      }, 20000);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.event === "catchup") {
          setEvents(msg.payload || []);
        } else if (msg.event === "activity") {
          addEvent(msg.payload);
          fetchClients();
          fetchStats();
        }
        // pong ignored
      } catch {}
    };

    ws.onerror = () => setWsStatus("error");

    ws.onclose = () => {
      setWsStatus("disconnected");
      clearInterval(pingRef.current);
      // Auto-reconnect after 3s
      reconnectRef.current = setTimeout(connect, 3000);
    };
  }, [wsUrl, addEvent, fetchClients, fetchStats]);

  useEffect(() => {
    connect();
    fetchStats();
    fetchClients();
    statsRef.current = setInterval(() => { fetchStats(); fetchClients(); }, 10000);
    return () => {
      wsRef.current?.close();
      clearInterval(pingRef.current);
      clearInterval(statsRef.current);
      clearTimeout(reconnectRef.current);
    };
  }, [connect, fetchStats, fetchClients]);

  // Auto-scroll feed
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  // ── Derived data ──────────────────────────────────────────────────────────
  const activityMap = useMemo(() => {
    const map = {};
    events.forEach(e => {
      if (!map[e.client_ip]) map[e.client_ip] = [];
      map[e.client_ip].push(e);
    });
    return map;
  }, [events]);

  const filteredEvents = useMemo(() => {
    const rev = [...events].reverse();
    if (filterType==="all") return rev;
    return rev.filter(e=>e.type===filterType);
  }, [events, filterType]);

  // Score timeline (last 20 analysis_done events)
  const scoreLine = useMemo(() =>
    events.filter(e=>e.type==="analysis_done")
      .slice(-20)
      .map((e,i) => ({
        i: i+1,
        score: e.data?.global_threat_score||0,
        level: e.data?.threat_level||"SAFE",
        name:  (e.data?.file_name||"").slice(0,10),
      })),
  [events]);

  // Activity rate — group by minute for last 10 min
  const activityRate = useMemo(() => {
    const now = Date.now();
    const buckets = Array.from({length:10},(_,i)=>({
      label:`-${9-i}m`, count:0, analyses:0,
    }));
    events.forEach(e => {
      const age = now - new Date(e.ts_iso||0).getTime();
      const min = Math.floor(age/60000);
      if (min<10) {
        buckets[9-min].count++;
        if (e.type==="analysis_done") buckets[9-min].analyses++;
      }
    });
    return buckets;
  }, [events]);

  const analysesTotal   = events.filter(e=>e.type==="analysis_done").length;
  const criticalTotal   = events.filter(e=>e.type==="analysis_done"&&e.data?.threat_level==="CRITICAL").length;
  const devicesTotal    = new Set(events.map(e=>e.client_ip)).size;

  // ── Name save ─────────────────────────────────────────────────────────────
  const saveName = () => {
    const n = nameInput.trim() || "Analyst";
    setMyName(n); localStorage.setItem("lm_display_name", n);
    setEditingName(false);
    // Reconnect with new name
    wsRef.current?.close();
  };

  // WS URL shown in "share" box
  const shareUrl = `${backendUrl.replace("127.0.0.1","YOUR_IP").replace("localhost","YOUR_IP")}`;

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="lm-page">
      <div className="lm-scanline"/>

      {/* ── Header ── */}
      <div className="lm-header">
        <div className="lm-header-left">
          <div className="lm-title-row">
            <PulseDot color={wsStatus==="connected"?"#10b981":wsStatus==="connecting"?"#ffa726":"#ef5350"} size={12}/>
            <div className="lm-title">LIVE MONITORING</div>
            <span className={`lm-ws-badge lm-ws-${wsStatus}`}>
              {wsStatus==="connected"?"LIVE"
               :wsStatus==="connecting"?"CONNECTING..."
               :wsStatus==="error"?"ERROR"
               :"OFFLINE"}
            </span>
          </div>
          <div className="lm-subtitle">
            Real-time multi-device threat analysis feed · WebSocket
          </div>
        </div>
        <div className="lm-header-right">
          {/* Identity */}
          {editingName ? (
            <div className="lm-name-form">
              <input className="lm-name-input" value={nameInput}
                onChange={e=>setNameInput(e.target.value)}
                onKeyDown={e=>e.key==="Enter"&&saveName()}
                placeholder="Your display name" autoFocus/>
              <button className="lm-btn lm-btn-cyan" onClick={saveName}>✓</button>
              <button className="lm-btn lm-btn-ghost" onClick={()=>setEditingName(false)}>✕</button>
            </div>
          ) : (
            <button className="lm-btn lm-btn-ghost" onClick={()=>{setNameInput(myName);setEditingName(true);}}>
              ✎ {myName}
            </button>
          )}
          <button className={`lm-btn ${soundOn?"lm-btn-cyan":"lm-btn-ghost"}`}
            onClick={()=>setSoundOn(v=>!v)} title="Alert sound on/off">
            {soundOn?"🔔":"🔕"}
          </button>
          <button className="lm-btn lm-btn-ghost" onClick={()=>setShowCopyBox(v=>!v)}>
            🔗 Share
          </button>
          <button className="lm-btn lm-btn-ghost" onClick={()=>{
            wsRef.current?.close(); clearTimeout(reconnectRef.current); connect();
          }}>⟳ Reconnect</button>
        </div>
      </div>

      {/* ── Share box ── */}
      {showCopyBox && (
        <div className="lm-share-box">
          <div className="lm-share-title">🔗 HOW YOUR FRIEND CONNECTS</div>
          <div className="lm-share-steps">
            <div className="lm-share-step">
              <span className="lm-step-num">1</span>
              <span>Make sure both laptops are on the <strong>same WiFi</strong></span>
            </div>
            <div className="lm-share-step">
              <span className="lm-step-num">2</span>
              <span>
                Find your IP: open terminal → type{" "}
                <code className="lm-code">ipconfig</code> (Windows) or{" "}
                <code className="lm-code">ip a</code> (Linux/WSL) → look for IPv4 address
              </span>
            </div>
            <div className="lm-share-step">
              <span className="lm-step-num">3</span>
              <span>
                Your friend opens their browser to{" "}
                <code className="lm-code">http://YOUR_IP:3000</code>{" "}
                (React UI) — replace <code className="lm-code">YOUR_IP</code> with your actual IP
              </span>
            </div>
            <div className="lm-share-step">
              <span className="lm-step-num">4</span>
              <span>
                Make sure uvicorn listens on all interfaces:{" "}
                <code className="lm-code">uvicorn backend:app --reload --host 0.0.0.0 --port 8000</code>
              </span>
            </div>
            <div className="lm-share-step">
              <span className="lm-step-num">5</span>
              <span>
                Your friend goes to Settings page → sets Backend URL to{" "}
                <code className="lm-code">http://YOUR_IP:8000</code>
              </span>
            </div>
          </div>
          <button className="lm-btn lm-btn-ghost" style={{marginTop:8}}
            onClick={()=>setShowCopyBox(false)}>✕ Close</button>
        </div>
      )}

      {/* ── KPI strip ── */}
      <div className="lm-kpi-strip">
        {[
          {label:"ONLINE DEVICES",    val:clients.length,     color:"#10b981"},
          {label:"SESSION ANALYSES",  val:analysesTotal,      color:"#06b6d4"},
          {label:"CRITICAL ALERTS",   val:criticalTotal,      color:"#ff1744"},
          {label:"UNIQUE IPs",         val:devicesTotal,       color:"#a855f7"},
          {label:"TOTAL ANALYSES",     val:stats?.total_analyses??0, color:"#f97316"},
          {label:"ANALYSES (24h)",     val:stats?.analyses_24h??0,   color:"#ffea00"},
        ].map((k,i) => (
          <div key={i} className="lm-kpi">
            <div className="lm-kpi-val" style={{color:k.color}}>{k.val}</div>
            <div className="lm-kpi-lbl">{k.label}</div>
          </div>
        ))}
      </div>

      {/* ── Main layout: devices + charts | feed ── */}
      <div className="lm-main">

        {/* LEFT column */}
        <div className="lm-left">

          {/* Connected devices */}
          <div className="lm-card">
            <div className="lm-card-title">
              CONNECTED DEVICES
              <span className="lm-live-badge">
                <span className="lm-live-dot"/>LIVE
              </span>
            </div>
            {clients.length === 0 ? (
              <div className="lm-empty">
                Waiting for devices to connect…
                <div style={{fontSize:11,marginTop:6,color:"rgba(255,255,255,0.2)"}}>
                  Click "Share" above for connection instructions
                </div>
              </div>
            ) : (
              <div className="lm-devices-grid">
                {clients.map((c,i) => (
                  <DeviceCard key={i} client={c} activityMap={activityMap}/>
                ))}
              </div>
            )}
          </div>

          {/* Threat score timeline */}
          <div className="lm-card">
            <div className="lm-card-title">LIVE THREAT SCORE STREAM</div>
            {scoreLine.length < 2 ? (
              <div className="lm-empty">Waiting for analyses…</div>
            ) : (
              <ResponsiveContainer width="100%" height={150}>
                <AreaChart data={scoreLine} margin={{top:8,right:8,left:-28,bottom:0}}>
                  <defs>
                    <linearGradient id="lmScoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#f97316" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                  <XAxis dataKey="i" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <YAxis tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<LmTip/>}/>
                  <Area type="monotone" dataKey="score" stroke="#f97316" strokeWidth={2}
                    fill="url(#lmScoreGrad)" dot={(props)=>{
                      const c=LEVEL_COLOR[props.payload?.level]||"#f97316";
                      return <circle cx={props.cx} cy={props.cy} r={4} fill={c}
                        style={{filter:`drop-shadow(0 0 4px ${c})`}}/>;
                    }} name="Score"/>
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Activity rate chart */}
          <div className="lm-card">
            <div className="lm-card-title">ACTIVITY RATE (LAST 10 MIN)</div>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={activityRate} barCategoryGap="20%"
                margin={{top:4,right:8,left:-28,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
                <XAxis dataKey="label" tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis tick={{fill:"rgba(255,255,255,0.2)",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<LmTip/>} cursor={{fill:"rgba(255,255,255,0.02)"}}/>
                <Bar dataKey="count"    name="Events"   fill="rgba(6,182,212,0.4)"  radius={[2,2,0,0]}/>
                <Bar dataKey="analyses" name="Analyses" fill="rgba(249,115,22,0.7)" radius={[2,2,0,0]}/>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Last analysis summary card */}
          {stats?.last_analysis && (
            <div className="lm-card lm-last-card"
              style={{borderColor:`${LEVEL_COLOR[stats.last_analysis.threat_level]||"#fff"}44`}}>
              <div className="lm-card-title">LAST ANALYSIS</div>
              <div className="lm-last-row">
                <div className="lm-last-score"
                  style={{color:LEVEL_COLOR[stats.last_analysis.threat_level]}}>
                  {stats.last_analysis.global_threat_score}
                </div>
                <div className="lm-last-details">
                  <div className="lm-last-level"
                    style={{color:LEVEL_COLOR[stats.last_analysis.threat_level]}}>
                    {stats.last_analysis.threat_level}
                  </div>
                  <div className="lm-last-file">{stats.last_analysis.file_name}</div>
                  <div className="lm-last-meta">
                    {fmt(stats.last_analysis.total_logs)} logs ·{" "}
                    {Number(stats.last_analysis.execution_time||0).toFixed(3)}s ·{" "}
                    {stats.last_analysis.processors_used} procs
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT column — activity feed */}
        <div className="lm-right">
          <div className="lm-card lm-feed-card">
            <div className="lm-feed-header">
              <div className="lm-card-title">
                LIVE ACTIVITY FEED
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                  color:"rgba(255,255,255,0.25)",marginLeft:8}}>
                  {filteredEvents.length} events
                </span>
              </div>
              <div className="lm-feed-controls">
                {/* Filter tabs */}
                <div className="lm-filter-row">
                  {[
                    {id:"all",            label:"All"},
                    {id:"analysis_done",  label:"✓ Done"},
                    {id:"analysis_start", label:"⚡ Start"},
                    {id:"connected",      label:"⬡ Connect"},
                  ].map(f => (
                    <button key={f.id}
                      className={`lm-filter-btn ${filterType===f.id?"lm-filter-active":""}`}
                      onClick={()=>setFilterType(f.id)}>
                      {f.label}
                    </button>
                  ))}
                </div>
                <label className="lm-autoscroll-toggle">
                  <input type="checkbox" checked={autoScroll}
                    onChange={e=>setAutoScroll(e.target.checked)}/>
                  <span>Auto-scroll</span>
                </label>
                <button className="lm-btn lm-btn-ghost"
                  style={{padding:"4px 10px",fontSize:10}}
                  onClick={()=>setEvents([])}>✕ Clear</button>
              </div>
            </div>

            {/* Feed */}
            <div className="lm-feed" ref={feedRef}
              onScroll={e => {
                const el = e.target;
                const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
                if (!atBottom && autoScroll) setAutoScroll(false);
              }}>
              {filteredEvents.length === 0 ? (
                <div className="lm-feed-empty">
                  <div style={{fontSize:32,marginBottom:12}}>📡</div>
                  <div style={{fontFamily:"'Orbitron',monospace",fontSize:12,letterSpacing:4,
                    color:"rgba(255,255,255,0.15)"}}>WAITING FOR EVENTS</div>
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:13,
                    color:"rgba(255,255,255,0.2)",marginTop:6}}>
                    {wsStatus==="connected"
                      ? "Connected — events will appear here as they happen"
                      : wsStatus==="connecting"
                      ? "Connecting to server…"
                      : "Not connected. Check that uvicorn is running."}
                  </div>
                </div>
              ) : (
                filteredEvents.map((e,i) => (
                  <ActivityRow key={e.id||i} event={e} isNew={newEventIds.has(e.id)}/>
                ))
              )}
            </div>

            {/* Scroll-to-bottom button */}
            {!autoScroll && (
              <button className="lm-scroll-btn"
                onClick={()=>{
                  setAutoScroll(true);
                  if (feedRef.current)
                    feedRef.current.scrollTop = feedRef.current.scrollHeight;
                }}>
                ↓ Jump to latest
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}