from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shutil
import os
import re
import uuid
import json
from datetime import datetime

app = FastAPI(title="CyberThreat MPI Backend")

# -------------------------------
# CORS Configuration
# -------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_FOLDER = "uploads"
HISTORY_FILE = "analysis_history.json"

# Create folders if not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)

# -------------------------------
# Utility Functions
# -------------------------------

def classify_threat(score):
    if score == 0:
        return "SAFE"
    elif score <= 10:
        return "LOW"
    elif score <= 25:
        return "MEDIUM"
    elif score <= 50:
        return "HIGH"
    else:
        return "CRITICAL"

def save_history(entry):
    with open(HISTORY_FILE, "r") as f:
        data = json.load(f)

    data.append(entry)

    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=4)

# -------------------------------
# Root Endpoint
# -------------------------------

@app.get("/")
def home():
    return {"message": "Cyber Threat MPI API Running"}

# -------------------------------
# Analyze Logs Endpoint
# -------------------------------

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):

    if not file.filename.endswith(".txt"):
        return {"error": "Only .txt files are allowed"}

    # Unique filename
    unique_name = str(uuid.uuid4()) + "_" + file.filename
    file_path = os.path.join(UPLOAD_FOLDER, unique_name)

    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Run MPI Program
    # command = [
    #     "mpirun",
    #     "--oversubscribe",
    #     "-np",
    #     "4",
    #     "./mpi_log_analyzer",
    #     file_path
    # ]
    command = [
    "mpirun",
    "--oversubscribe",
    "-np", "4",
    "--mca", "btl_vader_single_copy_mechanism", "none",
    "./mpi_log_analyzer",
    file_path
]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        return {
            "error": "MPI execution failed",
            "details": result.stderr
        }

    output = result.stdout

    # -------------------------------
    # Extract Data from MPI Output
    # -------------------------------

    total_logs = re.search(r"Total logs read: (\d+)", output)
    threat_score = re.search(r"GLOBAL THREAT SCORE: (\d+)", output)
    execution_time = re.search(r"Execution Time: ([0-9.]+)", output)

    process_scores = re.findall(r"Process (\d+) Local Threat Score: (\d+)", output)

    total_logs_val = int(total_logs.group(1)) if total_logs else 0
    threat_score_val = int(threat_score.group(1)) if threat_score else 0
    execution_time_val = float(execution_time.group(1)) if execution_time else 0.0

    threat_level = classify_threat(threat_score_val)

    threat_percentage = (
        (threat_score_val / total_logs_val) * 100
        if total_logs_val > 0 else 0
    )

    # Prepare response
    response_data = {
        "file_name": file.filename,
        "total_logs": total_logs_val,
        "global_threat_score": threat_score_val,
        "threat_level": threat_level,
        "threat_percentage": round(threat_percentage, 2),
        "execution_time": execution_time_val,
        "process_wise_scores": [
            {"process_id": int(pid), "score": int(score)}
            for pid, score in process_scores
        ],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Save history
    save_history(response_data)

    return response_data


# -------------------------------
# Get Analysis History
# -------------------------------

@app.get("/history")
def get_history():
    with open(HISTORY_FILE, "r") as f:
        data = json.load(f)
    return data


# -------------------------------
# Delete History
# -------------------------------

@app.delete("/history")
def clear_history():
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)
    return {"message": "History cleared successfully"}


# -------------------------------
# System Health Check
# -------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "Running",
        "mpi_enabled": True,
        "uploads_folder": os.path.exists(UPLOAD_FOLDER),
        "history_file": os.path.exists(HISTORY_FILE)
    }
