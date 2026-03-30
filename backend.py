from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import subprocess
import os
import re
import uuid
import json
import csv
import time
import asyncio
import socket
from datetime import datetime
from io import StringIO

app = FastAPI(title="CyberThreat MPI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Paths always relative to THIS file — not the cwd ──────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
HISTORY_FILE  = os.path.join(BASE_DIR, "analysis_history.json")
MPI_BINARY    = os.path.join(BASE_DIR, "mpi_log_analyzer")

print(f"[init] BASE_DIR     : {BASE_DIR}")
print(f"[init] UPLOAD_FOLDER: {UPLOAD_FOLDER}")
print(f"[init] MPI_BINARY   : {MPI_BINARY}")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)

# ── WebSocket connection manager ───────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[dict] = []   # {ws, client_ip, name, connected_at}

    async def connect(self, ws: WebSocket, client_ip: str, name: str):
        await ws.accept()
        self.active.append({
            "ws":           ws,
            "client_ip":    client_ip,
            "name":         name,
            "connected_at": datetime.now().isoformat(),
        })
        print(f"[ws] Connected: {name} @ {client_ip}  total={len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c["ws"] is not ws]
        print(f"[ws] Disconnected  total={len(self.active)}")

    async def broadcast(self, message: dict):
        dead = []
        for conn in self.active:
            try:
                await conn["ws"].send_json(message)
            except Exception:
                dead.append(conn)
        for d in dead:
            self.active.remove(d)

    def clients_info(self):
        return [
            {
                "client_ip":    c["client_ip"],
                "name":         c["name"],
                "connected_at": c["connected_at"],
            }
            for c in self.active
        ]


manager = ConnectionManager()

# ── In-memory activity log (last 200 events) ──────────────────────────────────
ACTIVITY_LOG: list = []
MAX_ACTIVITY  = 200

def push_activity(event_type: str, data: dict, client_ip: str = "server"):
    """Record an activity event and broadcast to all WebSocket clients."""
    entry = {
        "id":         str(uuid.uuid4())[:8],
        "type":       event_type,        # "analysis_start"|"analysis_done"|"folder_scan"|"connected"|"disconnected"
        "data":       data,
        "client_ip":  client_ip,
        "timestamp":  datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p"),
        "ts_iso":     datetime.now().isoformat(),
    }
    ACTIVITY_LOG.append(entry)
    if len(ACTIVITY_LOG) > MAX_ACTIVITY:
        ACTIVITY_LOG.pop(0)
    # Fire-and-forget broadcast
    asyncio.create_task(manager.broadcast({"event": "activity", "payload": entry}))
    return entry

# ── Default keywords — covers both original logs AND SmartLog generator output ─
DEFAULT_KEYWORDS = [
    # Original keywords
    {"word": "failed",              "score": 2,  "enabled": True},
    {"word": "brute",               "score": 5,  "enabled": True},
    {"word": "sql",                 "score": 8,  "enabled": True},
    {"word": "xss",                 "score": 7,  "enabled": True},
    {"word": "malware",             "score": 10, "enabled": True},
    {"word": "unauthorized",        "score": 6,  "enabled": True},
    {"word": "ddos",                "score": 9,  "enabled": True},
    {"word": "phishing",            "score": 5,  "enabled": True},
    {"word": "error",               "score": 1,  "enabled": True},
    {"word": "attack",              "score": 4,  "enabled": True},
    {"word": "port",                "score": 3,  "enabled": True},
    {"word": "scan",                "score": 3,  "enabled": True},
    # SmartLog Generator attack types
    {"word": "credential stuffing", "score": 8,  "enabled": True},
    {"word": "injection",           "score": 8,  "enabled": True},
    {"word": "successful",          "score": 6,  "enabled": True},  # attack=... action=SUCCESSFUL
    {"word": "detected",            "score": 3,  "enabled": True},  # action=DETECTED
    {"word": "denied",              "score": 4,  "enabled": True},  # status=DENIED
    {"word": "login-failures",      "score": 7,  "enabled": True},  # pattern=login-failures
    {"word": "suspicious",          "score": 5,  "enabled": True},  # suspicious-response
    {"word": "anomalous",           "score": 6,  "enabled": True},  # anomalous=protocol-port-mismatch
    {"word": "dropped",             "score": 2,  "enabled": True},  # status=DROPPED
    {"word": "rst",                 "score": 2,  "enabled": True},  # status=RST
    {"word": "high",                "score": 1,  "enabled": True},  # sev=high
    {"word": "peak_rps",            "score": 4,  "enabled": True},  # DDoS peak_rps field
]

DEFAULT_THRESHOLDS = {"low": 10, "medium": 25, "high": 50, "critical": 100}


# ── Classifier ─────────────────────────────────────────────────────────────────
def classify_threat(score: int, thresholds: dict) -> str:
    if score <= 0:                                return "SAFE"
    if score < thresholds.get("low",      10):   return "SAFE"
    if score < thresholds.get("medium",   25):   return "LOW"
    if score < thresholds.get("high",     50):   return "MEDIUM"
    if score < thresholds.get("critical", 100):  return "HIGH"
    return "CRITICAL"


# ── File reader — handles all encodings ────────────────────────────────────────
def read_raw_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()

def bytes_to_text(raw: bytes) -> str:
    for enc in ["utf-8", "latin-1", "cp1252", "ascii"]:
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


# ── Format detector + line extractor ──────────────────────────────────────────
def extract_lines(file_path: str, file_ext: str) -> list:
    """
    Auto-detect file format and extract scorable text lines.

    Supports:
    - TXT  : one log line per line (original format + SmartLog TXT export)
    - JSON : SmartLog JSON export — array of LogEntry objects
             extracts 'message' field from each entry
    - CSV  : SmartLog CSV export — extracts 'message' column
    """
    raw   = read_raw_bytes(file_path)
    text  = bytes_to_text(raw)
    ext   = file_ext.lower().lstrip(".")

    print(f"[extractor] format={ext}, raw_size={len(raw)} bytes")

    # ── JSON format (SmartLog JSON export) ────────────────────────────────────
    if ext == "json":
        try:
            data = json.loads(text)
            lines = []

            # SmartLog response wraps logs in { "logs": [...] }
            if isinstance(data, dict) and "logs" in data:
                data = data["logs"]

            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        # Build a rich scorable line from all fields
                        parts = []
                        for field in ["message", "event_type", "status", "severity",
                                      "ip", "log_type", "attack", "action"]:
                            val = entry.get(field, "")
                            if val:
                                parts.append(str(val))
                        line = " | ".join(parts)
                        if line:
                            lines.append(line)
                    elif isinstance(entry, str):
                        lines.append(entry)

            print(f"[extractor] JSON parsed: {len(lines)} entries")
            return lines if lines else text.splitlines()
        except Exception as e:
            print(f"[extractor] JSON parse failed: {e} — falling back to plain text")
            return text.splitlines()

    # ── CSV format (SmartLog CSV export) ─────────────────────────────────────
    if ext == "csv":
        try:
            reader  = csv.DictReader(StringIO(text))
            lines   = []
            headers = reader.fieldnames or []
            print(f"[extractor] CSV headers: {headers}")

            # Score columns — message is primary, others are supplementary
            score_cols = [c for c in headers if c.lower() in
                          {"message","event_type","status","severity","attack","action","log_type"}]
            if not score_cols:
                score_cols = list(headers)  # fallback: use all columns

            for row in reader:
                parts = [str(row[c]) for c in score_cols if row.get(c)]
                if parts:
                    lines.append(" | ".join(parts))

            print(f"[extractor] CSV parsed: {len(lines)} rows")
            return lines if lines else text.splitlines()
        except Exception as e:
            print(f"[extractor] CSV parse failed: {e} — falling back to plain text")
            return text.splitlines()

    # ── TXT / LOG (default) ───────────────────────────────────────────────────
    lines = text.splitlines()
    # Filter empty lines
    lines = [l for l in lines if l.strip()]
    print(f"[extractor] TXT: {len(lines)} lines")
    return lines


# ── Scorer ────────────────────────────────────────────────────────────────────
def score_lines(lines: list, keywords: list, n_procs: int) -> dict:
    """Score extracted lines using live keywords, split into n_procs chunks."""
    active_kw = [
        (k["word"].strip().lower(), int(k.get("score", 1)))
        for k in keywords
        if k.get("enabled", True) and str(k.get("word", "")).strip()
    ]
    print(f"[scorer] {len(active_kw)} active keywords")

    total_lines = len(lines)
    if total_lines == 0:
        return {"total_logs": 0, "total_score": 0,
                "threat_lines": 0, "process_scores": []}

    line_scores = []
    for line in lines:
        lower = line.lower()
        s = sum(score for word, score in active_kw if word in lower)
        line_scores.append(s)

    total_score  = sum(line_scores)
    threat_lines = sum(1 for s in line_scores if s > 0)

    print(f"[scorer] total_score={total_score}, "
          f"threat_lines={threat_lines}/{total_lines}")

    # Distribute into n_procs chunks (mirrors MPI)
    process_scores = []
    for pid in range(n_procs):
        start = (pid * total_lines) // n_procs
        end   = ((pid + 1) * total_lines) // n_procs
        process_scores.append({
            "process_id": pid,
            "score":      sum(line_scores[start:end]),
        })

    return {
        "total_logs":     total_lines,
        "total_score":    total_score,
        "threat_lines":   threat_lines,
        "process_scores": process_scores,
    }


def save_history(entry):
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        data = []
    data.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=4)


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
def home():
    return {"message": "Cyber Threat MPI API Running"}


# ── Analyze ───────────────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze_file(
    request:    Request,
    file:       UploadFile     = File(...),
    processors: Optional[int] = Form(4),
    keywords:   Optional[str] = Form(None),
    thresholds: Optional[str] = Form(None),
    filename:   Optional[str] = Form(None),
):
    # ── Resolve filename ──────────────────────────────────────────────────────
    original_name = (filename or file.filename or "uploaded_file.txt").strip()
    original_name = os.path.basename(original_name) or "uploaded_file.txt"

    # Determine extension
    _, ext = os.path.splitext(original_name)
    ext = ext.lower()  # .txt / .log / .json / .csv

    ALLOWED = {".txt", ".log", ".json", ".csv"}
    if ext not in ALLOWED:
        return {"error": f"Only {', '.join(ALLOWED)} files are allowed"}

    print(f"\n{'='*60}")
    print(f"[analyze] file={original_name}  ext={ext}")

    # ── Broadcast: analysis started ───────────────────────────────────────────
    try:
        client_ip = request.client.host if hasattr(request, 'client') and request.client else "unknown"
    except Exception:
        client_ip = "unknown"

    push_activity("analysis_start", {
        "file_name":  original_name,
        "file_format": ext.lstrip(".").upper(),
        "processors": n_procs,
    }, client_ip)

    # ── Parse settings ────────────────────────────────────────────────────────
    try:
        kw_list = json.loads(keywords) if keywords else DEFAULT_KEYWORDS
    except Exception:
        kw_list = DEFAULT_KEYWORDS

    try:
        thr_dict = json.loads(thresholds) if thresholds else DEFAULT_THRESHOLDS
    except Exception:
        thr_dict = DEFAULT_THRESHOLDS

    n_procs = max(1, min(int(processors or 4), 16))
    print(f"[analyze] n_procs={n_procs}, keywords={len(kw_list)}")

    # ── Save file ─────────────────────────────────────────────────────────────
    unique_id = str(uuid.uuid4())[:8]
    safe_name = unique_id + "_" + original_name
    abs_path  = os.path.join(UPLOAD_FOLDER, safe_name)

    try:
        contents = await file.read()
        print(f"[analyze] received {len(contents)} bytes")
        if len(contents) == 0:
            return {"error": "Uploaded file is empty",
                    "file_name": original_name, "total_logs": 0,
                    "global_threat_score": 0, "threat_level": "SAFE",
                    "threat_percentage": 0.0, "execution_time": 0.0,
                    "process_wise_scores": [], "processors_used": n_procs,
                    "timestamp": datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p")}
        with open(abs_path, "wb") as f_out:
            f_out.write(contents)
        print(f"[analyze] saved: {abs_path}")
    except Exception as e:
        return {"error": f"Failed to save file: {str(e)}"}

    # ── Extract lines (handles TXT / JSON / CSV) ──────────────────────────────
    lines = extract_lines(abs_path, ext)

    # ── Score using live keywords from Settings ───────────────────────────────
    scored         = score_lines(lines, kw_list, n_procs)
    total_logs     = scored["total_logs"]
    threat_score   = scored["total_score"]
    threat_lines   = scored["threat_lines"]
    process_scores = scored["process_scores"]

    # ── Try MPI (TXT/LOG only — C program expects plain text) ─────────────────
    execution_time_val = 0.0
    if ext in {".txt", ".log"}:
        command = [
            "mpirun", "--oversubscribe",
            "-np", str(n_procs),
            "--mca", "btl_vader_single_copy_mechanism", "none",
            MPI_BINARY, abs_path,
        ]
        print(f"[analyze] MPI: {' '.join(command)}")
        try:
            t0     = time.time()
            result = subprocess.run(command, capture_output=True,
                                    text=True, timeout=60)
            execution_time_val = round(time.time() - t0, 4)
            print(f"[analyze] MPI rc={result.returncode} time={execution_time_val}s")
            if result.stdout:
                print(f"[analyze] MPI stdout:\n{result.stdout[:400]}")
            et = re.search(r"Execution Time: ([0-9.]+)", result.stdout or "")
            if et:
                execution_time_val = float(et.group(1))
        except subprocess.TimeoutExpired:
            execution_time_val = 60.0
            print("[analyze] MPI timed out")
        except FileNotFoundError:
            print("[analyze] mpirun not found — Python scoring only")
        except Exception as e:
            print(f"[analyze] MPI error: {e}")
    else:
        print(f"[analyze] Skipping MPI for {ext} — Python scorer handles this format")

    # ── Classify ──────────────────────────────────────────────────────────────
    threat_level      = classify_threat(threat_score, thr_dict)
    threat_percentage = (
        round(min((threat_lines / total_logs) * 100, 100), 2)
        if total_logs > 0 else 0.0
    )

    print(f"[analyze] RESULT: logs={total_logs}, score={threat_score}, "
          f"level={threat_level}, pct={threat_percentage}%")
    print(f"{'='*60}\n")

    response_data = {
        "file_name":           original_name,
        "total_logs":          total_logs,
        "global_threat_score": threat_score,
        "threat_level":        threat_level,
        "threat_percentage":   threat_percentage,
        "execution_time":      execution_time_val,
        "process_wise_scores": process_scores,
        "processors_used":     n_procs,
        "file_format":         ext.lstrip(".").upper(),
        "timestamp":           datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p"),
    }

    save_history(response_data)

    # ── Broadcast analysis complete to all live monitor clients ───────────────
    push_activity("analysis_done", {
        "file_name":           response_data["file_name"],
        "global_threat_score": response_data["global_threat_score"],
        "threat_level":        response_data["threat_level"],
        "total_logs":          response_data["total_logs"],
        "threat_percentage":   response_data["threat_percentage"],
        "execution_time":      response_data["execution_time"],
        "processors_used":     response_data["processors_used"],
        "file_format":         response_data["file_format"],
    }, client_ip)

    # ✅ Clean up — delete the uploaded file after scoring
    # Prevents uploads/ from accumulating thousands of files
    # which could cause path confusion and slow down the server
    try:
        os.remove(abs_path)
        print(f"[cleanup] Deleted: {abs_path}")
    except Exception as e:
        print(f"[cleanup] Could not delete {abs_path}: {e}")

    return response_data


# ── History ───────────────────────────────────────────────────────────────────
@app.get("/history")
def get_history():
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


@app.delete("/history")
def clear_history():
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)
    return {"message": "History cleared successfully"}


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {
        "status":         "Running",
        "mpi_enabled":    True,
        "uploads_folder": os.path.exists(UPLOAD_FOLDER),
        "history_file":   os.path.exists(HISTORY_FILE),
    }


# ── Watched Folder ─────────────────────────────────────────────────────────────
# The user drops SmartLog-generated files here; we detect which haven't been
# analysed yet and let Analytics page pick them up for one-click analysis.

WATCHED_FOLDER = os.path.join(BASE_DIR, "Uploads_From_Log_Generator")
os.makedirs(WATCHED_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {".txt", ".log", ".json", ".csv"}


def _already_analysed(filename: str) -> bool:
    """Return True if this exact filename already appears in history."""
    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
        return any(h.get("file_name") == filename for h in history)
    except Exception:
        return False


@app.get("/watched-folder")
def get_watched_folder():
    """Return folder path + list of files with their analysis status."""
    try:
        files = []
        if os.path.isdir(WATCHED_FOLDER):
            for fname in sorted(os.listdir(WATCHED_FOLDER)):
                fpath = os.path.join(WATCHED_FOLDER, fname)
                if not os.path.isfile(fpath):
                    continue
                _, ext = os.path.splitext(fname)
                if ext.lower() not in ALLOWED_EXTENSIONS:
                    continue
                stat = os.stat(fpath)
                files.append({
                    "name":      fname,
                    "size_kb":   round(stat.st_size / 1024, 2),
                    "modified":  datetime.fromtimestamp(stat.st_mtime)
                                   .strftime("%d/%m/%Y, %I:%M:%S %p"),
                    "ext":       ext.lower().lstrip(".").upper(),
                    "analysed":  _already_analysed(fname),
                })
        return {
            "folder_path": WATCHED_FOLDER,
            "files":       files,
            "total":       len(files),
            "pending":     sum(1 for f in files if not f["analysed"]),
        }
    except Exception as e:
        return {"folder_path": WATCHED_FOLDER, "files": [], "total": 0,
                "pending": 0, "error": str(e)}


@app.post("/analyze-from-folder")
async def analyze_from_folder(
    filename:   str          = Form(...),
    processors: Optional[int]= Form(4),
    keywords:   Optional[str]= Form(None),
    thresholds: Optional[str]= Form(None),
):
    """
    Analyse a file that already sits in WATCHED_FOLDER.
    Behaves exactly like /analyze but reads the file from disk instead of upload.
    """
    # Safety: strip any path traversal
    safe_name = os.path.basename(filename)
    src_path  = os.path.join(WATCHED_FOLDER, safe_name)

    if not os.path.isfile(src_path):
        return {"error": f"File not found in watched folder: {safe_name}"}

    _, ext = os.path.splitext(safe_name)
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return {"error": f"File type {ext} not supported"}

    # Parse settings
    try:
        kw_list  = json.loads(keywords)  if keywords   else DEFAULT_KEYWORDS
    except Exception:
        kw_list  = DEFAULT_KEYWORDS
    try:
        thr_dict = json.loads(thresholds) if thresholds else DEFAULT_THRESHOLDS
    except Exception:
        thr_dict = DEFAULT_THRESHOLDS

    n_procs = max(1, min(int(processors or 4), 16))

    print(f"\n{'='*60}")
    print(f"[folder-analyze] file={safe_name}  ext={ext}  n_procs={n_procs}")

    # Copy to uploads/ so MPI can read it
    unique_id = str(uuid.uuid4())[:8]
    work_path = os.path.join(UPLOAD_FOLDER, unique_id + "_" + safe_name)
    with open(src_path, "rb") as f_in, open(work_path, "wb") as f_out:
        f_out.write(f_in.read())

    # Extract + score
    lines       = extract_lines(work_path, ext)
    scored      = score_lines(lines, kw_list, n_procs)
    total_logs  = scored["total_logs"]
    threat_score= scored["total_score"]
    threat_lines= scored["threat_lines"]
    process_scores = scored["process_scores"]

    # Try MPI
    execution_time_val = 0.0
    if ext in {".txt", ".log"}:
        command = [
            "mpirun", "--oversubscribe", "-np", str(n_procs),
            "--mca", "btl_vader_single_copy_mechanism", "none",
            MPI_BINARY, work_path,
        ]
        try:
            t0     = time.time()
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            execution_time_val = round(time.time() - t0, 4)
            et = re.search(r"Execution Time: ([0-9.]+)", result.stdout or "")
            if et:
                execution_time_val = float(et.group(1))
        except Exception as e:
            print(f"[folder-analyze] MPI error: {e}")

    # Classify + build response
    threat_level      = classify_threat(threat_score, thr_dict)
    threat_percentage = (
        round(min((threat_lines / total_logs) * 100, 100), 2)
        if total_logs > 0 else 0.0
    )

    response_data = {
        "file_name":           safe_name,
        "total_logs":          total_logs,
        "global_threat_score": threat_score,
        "threat_level":        threat_level,
        "threat_percentage":   threat_percentage,
        "execution_time":      execution_time_val,
        "process_wise_scores": process_scores,
        "processors_used":     n_procs,
        "file_format":         ext.lstrip(".").upper(),
        "timestamp":           datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p"),
        "source":              "watched_folder",
    }

    save_history(response_data)

    # Clean up work copy (NOT the original in watched folder)
    try:
        os.remove(work_path)
    except Exception:
        pass

    print(f"[folder-analyze] DONE: score={threat_score} level={threat_level}")
    print(f"{'='*60}\n")
    return response_data


@app.get("/performance-stats")
def performance_stats():
    """Aggregate performance metrics from analysis history for PerformanceLab."""
    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
    except Exception:
        history = []

    if not history:
        return {"count": 0, "entries": []}

    entries = []
    for h in history:
        exec_time  = float(h.get("execution_time", 0) or 0)
        total_logs = int(h.get("total_logs", 0) or 0)
        procs      = int(h.get("processors_used", 0) or 0)
        score      = int(h.get("global_threat_score", 0) or 0)
        entries.append({
            "file_name":       h.get("file_name", ""),
            "timestamp":       h.get("timestamp", ""),
            "total_logs":      total_logs,
            "execution_time":  exec_time,
            "threat_score":    score,
            "threat_level":    h.get("threat_level", "SAFE"),
            "processors_used": procs,
            "file_format":     h.get("file_format", "TXT"),
            "throughput":      round(total_logs / exec_time, 2) if exec_time > 0 else 0,
            "process_scores":  h.get("process_wise_scores", []),
        })

    exec_times  = [e["execution_time"] for e in entries if e["execution_time"] > 0]
    throughputs = [e["throughput"]      for e in entries if e["throughput"]      > 0]
    proc_counts = [e["processors_used"] for e in entries if e["processors_used"] > 0]

    return {
        "count":              len(entries),
        "entries":            entries,
        "avg_exec_time":      round(sum(exec_times)/len(exec_times),   4) if exec_times  else 0,
        "max_exec_time":      round(max(exec_times),                   4) if exec_times  else 0,
        "min_exec_time":      round(min(exec_times),                   4) if exec_times  else 0,
        "avg_throughput":     round(sum(throughputs)/len(throughputs), 2) if throughputs else 0,
        "max_throughput":     round(max(throughputs),                  2) if throughputs else 0,
        "total_logs_processed": sum(e["total_logs"] for e in entries),
        "avg_processors":     round(sum(proc_counts)/len(proc_counts), 1) if proc_counts else 0,
        "proc_distribution":  {str(k): proc_counts.count(k)
                               for k in sorted(set(proc_counts))},
        "level_distribution": {lvl: sum(1 for e in entries if e["threat_level"]==lvl)
                               for lvl in ["SAFE","LOW","MEDIUM","HIGH","CRITICAL"]
                               if any(e["threat_level"]==lvl for e in entries)},
    }

# ── WebSocket endpoint ─────────────────────────────────────────────────────────
@app.websocket("/ws/monitor")
async def websocket_monitor(ws: WebSocket):
    client_ip = ws.client.host if ws.client else "unknown"
    # Accept a name query param: /ws/monitor?name=Alice
    name = ws.query_params.get("name", f"User@{client_ip}")
    await manager.connect(ws, client_ip, name)

    # Notify everyone a new user joined
    push_activity("connected", {
        "name":      name,
        "client_ip": client_ip,
        "total_connected": len(manager.active),
    }, client_ip)

    # Send the last 50 activity events as a "catch-up" burst
    catch_up = ACTIVITY_LOG[-50:] if ACTIVITY_LOG else []
    await ws.send_json({"event": "catchup", "payload": catch_up})

    try:
        while True:
            # Keep connection alive; client can send ping {"type":"ping"}
            data = await ws.receive_json()
            if data.get("type") == "ping":
                await ws.send_json({"event": "pong", "ts": datetime.now().isoformat()})
    except (WebSocketDisconnect, Exception):
        manager.disconnect(ws)
        push_activity("disconnected", {
            "name":      name,
            "client_ip": client_ip,
            "total_connected": len(manager.active),
        }, client_ip)


# ── REST fallback for activity (for clients that can't use WS) ────────────────
@app.get("/activity")
def get_activity(limit: int = 50):
    """Return recent activity events — polling fallback if WS not available."""
    return {
        "events":   ACTIVITY_LOG[-limit:],
        "total":    len(ACTIVITY_LOG),
        "clients":  manager.clients_info(),
    }


@app.get("/monitor/clients")
def get_clients():
    """List currently connected WebSocket clients."""
    return {
        "connected": len(manager.active),
        "clients":   manager.clients_info(),
    }


@app.get("/monitor/stats")
def monitor_stats():
    """Live stats snapshot for the monitoring page."""
    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
    except Exception:
        history = []

    # Last 60 minutes
    now = time.time()
    recent_1h = [h for h in history if _ts_to_epoch(h.get("timestamp","")) > now - 3600]
    recent_24h = [h for h in history if _ts_to_epoch(h.get("timestamp","")) > now - 86400]

    return {
        "total_analyses":    len(history),
        "analyses_1h":       len(recent_1h),
        "analyses_24h":      len(recent_24h),
        "connected_clients": len(manager.active),
        "clients":           manager.clients_info(),
        "recent_activity":   ACTIVITY_LOG[-20:],
        "last_analysis":     history[-1] if history else None,
        "critical_count_24h": sum(1 for h in recent_24h if h.get("threat_level")=="CRITICAL"),
        "high_count_24h":     sum(1 for h in recent_24h if h.get("threat_level") in ["HIGH","CRITICAL"]),
    }


def _ts_to_epoch(ts: str) -> float:
    """Convert '21/03/2026, 09:02:58 AM' → unix timestamp."""
    try:
        import re as _re
        m = _re.match(r'(\d{2})/(\d{2})/(\d{4}),?\s+(\d+):(\d+):(\d+)\s*(am|pm)?', ts, _re.I)
        if m:
            d,mo,y,h,mi,s,ap = m.groups()
            h = int(h)
            if ap and ap.lower()=="pm" and h<12: h+=12
            if ap and ap.lower()=="am" and h==12: h=0
            from datetime import datetime as _dt
            return _dt(int(y),int(mo),int(d),h,int(mi),int(s)).timestamp()
    except Exception:
        pass
    return 0.0