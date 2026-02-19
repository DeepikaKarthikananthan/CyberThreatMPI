from fastapi import FastAPI, UploadFile, File
import subprocess
import shutil
import os
import re

# Create FastAPI app FIRST
app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.get("/")
def home():
    return {"message": "Cyber Threat MPI API Running"}

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)

    # Save uploaded file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Run MPI program
    command = [
        "mpirun",
        "--oversubscribe",
        "-np",
        "4",
        "./mpi_log_analyzer",
        file_path
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    output = result.stdout

    # Extract structured data
    total_logs = re.search(r"Total logs read: (\d+)", output)
    threat_score = re.search(r"GLOBAL THREAT SCORE: (\d+)", output)
    execution_time = re.search(r"Execution Time: ([0-9.]+)", output)

    return {
        "total_logs": int(total_logs.group(1)) if total_logs else 0,
        "global_threat_score": int(threat_score.group(1)) if threat_score else 0,
        "execution_time": float(execution_time.group(1)) if execution_time else 0.0
    }
