from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import subprocess
import os
import re
import uuid
import json
import csv
import time
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