/**
 * Settingscontext.js
 *
 * TWO-LAYER ARCHITECTURE — solves the "hook called outside component" crash:
 *
 *   Layer 1 — Module-level store (SAFE to call anywhere, any time, no React needed)
 *             getConfig(), getMpi(), getApi(), getUi(), getThresholds(), getKeywords()
 *
 *   Layer 2 — React hooks (ONLY inside component functions)
 *             useSettings(), useMpiConfig(), useApiConfig(), useUiConfig(),
 *             useThresholds(), useKeywords(), useClassifyThreat()
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";

// ─── Default config ────────────────────────────────────────────────────────────
export const DEFAULT_CONFIG = {
  mpi: {
    processors:    4,
    timeout:       30,
    oversubscribe: true,
    btlMechanism:  "none",
    memoryPerNode: 512,
    bindToCore:    false,
    verboseOutput: false,
  },
  keywords: [
    // ── Original log keywords ──────────────────────────────────────────────
    { id: 1,  word: "failed",              score: 2,  enabled: true },
    { id: 2,  word: "brute",               score: 5,  enabled: true },
    { id: 3,  word: "sql",                 score: 8,  enabled: true },
    { id: 4,  word: "xss",                 score: 7,  enabled: true },
    { id: 5,  word: "malware",             score: 10, enabled: true },
    { id: 6,  word: "unauthorized",        score: 6,  enabled: true },
    { id: 7,  word: "ddos",                score: 9,  enabled: true },
    { id: 8,  word: "phishing",            score: 5,  enabled: true },
    { id: 9,  word: "error",               score: 1,  enabled: true },
    { id: 10, word: "attack",              score: 4,  enabled: true },
    { id: 11, word: "port",                score: 3,  enabled: true },
    { id: 12, word: "scan",                score: 3,  enabled: true },
    // ── SmartLog Generator attack/event keywords ───────────────────────────
    { id: 13, word: "credential stuffing", score: 8,  enabled: true },
    { id: 14, word: "injection",           score: 8,  enabled: true },
    { id: 15, word: "successful",          score: 6,  enabled: true },
    { id: 16, word: "detected",            score: 3,  enabled: true },
    { id: 17, word: "denied",              score: 4,  enabled: true },
    { id: 18, word: "login-failures",      score: 7,  enabled: true },
    { id: 19, word: "suspicious",          score: 5,  enabled: true },
    { id: 20, word: "anomalous",           score: 6,  enabled: true },
    { id: 21, word: "dropped",             score: 2,  enabled: true },
    { id: 22, word: "peak_rps",            score: 4,  enabled: true },
  ],
  thresholds: {
    low:      10,
    medium:   25,
    high:     50,
    critical: 100,
  },
  api: {
    backendUrl:        "http://127.0.0.1:8000",
    maxHistoryEntries: 100,
    autoSaveHistory:   true,
    requestTimeout:    60,
  },
  ui: {
    accentColor:     "#00e5ff",
    animationSpeed:  "normal",
    terminalSpeed:   220,
    showNodeActivity: true,
    chartRefreshRate: 1000,
    compactMode:     false,
    theme:           "dark",   // "dark" | "light"
  },
};

const STORAGE_KEY = "cyberthreat_settings";

// ─── Load from localStorage (safe, no React) ──────────────────────────────────
const loadConfig = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const p = JSON.parse(raw);
      return {
        ...DEFAULT_CONFIG, ...p,
        mpi:        { ...DEFAULT_CONFIG.mpi,        ...(p.mpi        || {}) },
        thresholds: { ...DEFAULT_CONFIG.thresholds, ...(p.thresholds || {}) },
        api:        { ...DEFAULT_CONFIG.api,         ...(p.api        || {}) },
        ui:         { ...DEFAULT_CONFIG.ui,          ...(p.ui         || {}) },
        keywords:   p.keywords || DEFAULT_CONFIG.keywords,
      };
    }
  } catch {}
  return DEFAULT_CONFIG;
};

// ─── Apply CSS vars (safe, no React) ──────────────────────────────────────────
const applyCssVars = (config) => {
  const r = document.documentElement;
  r.style.setProperty("--accent", config.ui.accentColor);
  r.style.setProperty("--app-cyan", config.ui.accentColor);
  const speeds = { fast:"0.1s", normal:"0.22s", slow:"0.4s", none:"0s" };
  r.style.setProperty("--app-t", `${speeds[config.ui.animationSpeed] || "0.22s"} cubic-bezier(0.4,0,0.2,1)`);
  r.style.setProperty("--app-compact", config.ui.compactMode ? "1" : "0");

  // ✅ Apply theme to <html> data-theme attribute — Theme.css reads this
  const theme = config.ui?.theme || "dark";
  document.documentElement.setAttribute("data-theme", theme);
};

// Exported so App.js toggle can call it directly without hooks
export const applyTheme = (theme) => {
  document.documentElement.setAttribute("data-theme", theme);
};

// ══════════════════════════════════════════════════════════════════════════════
// LAYER 1 — MODULE-LEVEL STORE
// Safe to call at any point in any file — no React, no hooks, no crashes.
// ══════════════════════════════════════════════════════════════════════════════

let _store = loadConfig();
const _subscribers = new Set();

const _notify = () => {
  _subscribers.forEach((fn) => fn(_store));
};

/** Read the full config object (non-reactive, always safe) */
export const getConfig      = ()  => _store;
export const getMpi         = ()  => _store.mpi;
export const getApi         = ()  => _store.api;
export const getUi          = ()  => _store.ui;
export const getThresholds  = ()  => _store.thresholds;
export const getKeywords    = ()  => _store.keywords;

/** Update a setting by dot-path e.g. "mpi.processors" (non-React, safe anywhere) */
export const updateSettingGlobal = (path, value) => {
  const parts = path.split(".");
  const clone = JSON.parse(JSON.stringify(_store));
  let obj = clone;
  for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
  obj[parts[parts.length - 1]] = value;
  _store = clone;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(_store));
  applyCssVars(_store);
  _notify();
};

/** Classify a threat score using current thresholds (safe anywhere) */
export const classifyThreat = (score) => {
  const t = _store.thresholds;
  if (score === 0 || score < t.low)      return "SAFE";
  if (score < t.medium)                  return "LOW";
  if (score < t.high)                    return "MEDIUM";
  if (score < t.critical)                return "HIGH";
  return "CRITICAL";
};

// ══════════════════════════════════════════════════════════════════════════════
// LAYER 2 — REACT CONTEXT + HOOKS
// Only use these INSIDE React component functions.
// ══════════════════════════════════════════════════════════════════════════════

const SettingsContext = createContext(null);

export function SettingsProvider({ children }) {
  const [config, setConfig] = useState(() => {
    _store = loadConfig();
    applyCssVars(_store);
    return _store;
  });

  // Subscribe to module-store changes (so Layer 1 writes also update React)
  useEffect(() => {
    const handler = (newStore) => {
      setConfig({ ...newStore });
      applyCssVars(newStore);
    };
    _subscribers.add(handler);
    return () => _subscribers.delete(handler);
  }, []);

  // Apply CSS vars on every config change
  useEffect(() => {
    applyCssVars(config);
  }, [config]);

  // Persist to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    _store = config;
  }, [config]);

  const updateSetting = useCallback((path, value) => {
    setConfig((prev) => {
      const parts = path.split(".");
      const clone = JSON.parse(JSON.stringify(prev));
      let obj = clone;
      for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
      obj[parts[parts.length - 1]] = value;
      _store = clone;
      _notify();
      return clone;
    });
  }, []);

  const replaceConfig = useCallback((newConfig) => {
    const merged = { ...DEFAULT_CONFIG, ...newConfig };
    setConfig(merged);
    _store = merged;
    _notify();
  }, []);

  const resetConfig = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setConfig(DEFAULT_CONFIG);
    _store = DEFAULT_CONFIG;
    _notify();
  }, []);

  return (
    <SettingsContext.Provider value={{ config, updateSetting, replaceConfig, resetConfig }}>
      {children}
    </SettingsContext.Provider>
  );
}

// ─── Safe hook — returns defaults if called outside provider ──────────────────
export function useSettings() {
  const ctx = useContext(SettingsContext);
  // Fallback so app doesn't crash even if provider is missing
  if (!ctx) {
    return {
      config:        _store,
      updateSetting: updateSettingGlobal,
      replaceConfig: (c) => { _store = { ...DEFAULT_CONFIG, ...c }; _notify(); },
      resetConfig:   () => { _store = DEFAULT_CONFIG; _notify(); },
    };
  }
  return ctx;
}

// ─── Reactive slice hooks (use INSIDE components only) ────────────────────────
export function useMpiConfig() {
  const { config } = useSettings();
  return config.mpi;
}

export function useApiConfig() {
  const { config } = useSettings();
  return config.api;
}

export function useUiConfig() {
  const { config } = useSettings();
  return config.ui;
}

export function useThresholds() {
  const { config } = useSettings();
  return config.thresholds;
}

export function useKeywords() {
  const { config } = useSettings();
  return config.keywords;
}

/** Theme hook — returns current theme and a toggle function */
export function useTheme() {
  const { config, updateSetting } = useSettings();
  const theme = config.ui?.theme || "dark";
  const toggleTheme = useCallback(() => {
    const next = theme === "dark" ? "light" : "dark";
    updateSetting("ui.theme", next);
  }, [theme, updateSetting]);
  const setTheme = useCallback((t) => {
    updateSetting("ui.theme", t);
  }, [updateSetting]);
  return { theme, toggleTheme, setTheme, isDark: theme === "dark" };
}

/** Returns a classify function that always uses live thresholds */
export function useClassifyThreat() {
  const thresholds = useThresholds();
  return useCallback((score) => {
    if (score === 0 || score < thresholds.low)    return "SAFE";
    if (score < thresholds.medium)                return "LOW";
    if (score < thresholds.high)                  return "MEDIUM";
    if (score < thresholds.critical)              return "HIGH";
    return "CRITICAL";
  }, [thresholds]);
}