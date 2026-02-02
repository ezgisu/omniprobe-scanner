from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import scanner
from typing import Dict

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory database for demo purposes (can use SQLite later)
scans: Dict[str, dict] = {}

class ScanRequest(BaseModel):
    target: str
    scan_mode: str = "light"  # "light" or "deep"

@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "id": scan_id,
        "target": request.target,
        "mode": request.scan_mode,
        "status": "QUEUED",
        "progress": 0,
        "current_stage": "Initializing",
        "findings": []
    }
    background_tasks.add_task(scanner.run_scan, scan_id, request.target, scans, request.scan_mode)
    return {"scan_id": scan_id}

@app.get("/scan/{scan_id}")
def get_scan_status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/report/{scan_id}")
def get_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]
