"""
server/app.py
MiniSploit Server API

Description: 
Initializes API for MiniSploit client to submit package inventory and receive matching CVE findings.
On startup, attempt to update ubuntu cve tracker and rebuild local db
Client POSTs inventory to /scan with release and list of packages
Server matches packages to CVEs and returns a list of findings

"""
import logging
import subprocess
from dataclasses import asdict
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

from .bootstrap import rebuild_cve_db
from .match_packages import match_inventory
from .settings import BASE_DIR, DB_PATH

# define logger
log = logging.getLogger("minisploit.server")
#define FastAPI object
app = FastAPI(title="MiniSploit Server")

class Package(BaseModel):
    # package format from client
    name: str
    version: str

class RunPOCRequest(BaseModel):
    # POST request body for /poc
    action: str
    ip: str

class ScanRequest(BaseModel):
    # POST request body for /scan
    client_id: str
    ubuntu_release: str  # focal/jammy/noble
    packages: List[Package]
    timestamp: Optional[str] = None #optional timestamp

class FindingOut(BaseModel):
    #vulnerability finding
    cve_id: str
    package: str
    installed_version: str
    status: str
    fixed_version: Optional[str]
    priority: str

@app.on_event("startup")
def startup():
    """
    Runs when server starts
      - tries to update ubuntu-cve-tracker
      - rebuilds DB only when needed
      - server stays up even if update/rebuild fails
    """
    try:
        stats = rebuild_cve_db(BASE_DIR)
    except Exception as e:
        # Keep server running but record error
        stats = {"error": repr(e), "db_path": str(DB_PATH)}

    app.state.db_stats = stats
    log_startup_summary(stats)

def log_startup_summary(stats):
    """
    Format log summary
    """
    if stats.get("error"):
        log.error("MiniSploit startup error")
        log.error("DB path: %s", stats.get("db_path"))
        log.error("Error: %s", stats["error"])
        return

    releases = ",".join(stats.get("releases", [])) or "unknown"
    db_path = stats.get("db_path")
    updated_at = stats.get("updated_at", "unknown")

    # Tracker status
    if stats.get("git_updated") is True:
        if stats.get("tracker_changed"):
            tracker_status = "Updated (new data pulled)"
        else:
            tracker_status = "OK (no changes)"
    else:
        tracker_status = "Unavailable (using cached data)"

    # Database status
    if stats.get("db_rebuilt"):
        db_status = f"Rebuilt ({stats.get('imported_cves')} CVEs, {stats.get('imported_rows')} package rows)"
    else:
        db_status = "Ready (cached)"

    log.info("MiniSploit CVE Server")
    log.info("──────────────────────")
    log.info("CVE Tracker:  %s", tracker_status)
    if stats.get("git_error"):
        log.warning("Tracker error: %s", stats["git_error"])
    log.info("Ubuntu data:  %s", releases)
    log.info("Database:     %s", db_status)
    log.info("DB path:      %s", db_path)
    log.info("Last update:  %s", updated_at)
    log.info("API ready at  http://0.0.0.0:8000")

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db_status")
def db_status():
    return getattr(app.state, "db_stats", {}) or {"status": "unknown"}

@app.post("/run-poc")
def run_poc(req: RunPOCRequest):
    action = req.action
    ip = req.ip
    input_text = "id; whoami; hostname -I\n"

    if action == "CVE-2026-24061":
        cmd = ["python3", str(BASE_DIR / "client" / "poc" / "CVE-2026-24061.py"), ip]
        result = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True
        )
    return {
        "stdin": input_text,
        "stdout": result.stdout,
        "stderr": result.stderr
    }

@app.post("/scan", response_model=List[FindingOut])
def scan(req: ScanRequest):
    pkgs = [(p.name, p.version) for p in req.packages]

    stats = getattr(app.state, "db_stats", {}) or {}
    db_path = Path(stats.get("db_path", str(DB_PATH)))

    findings = match_inventory(req.ubuntu_release, pkgs, db_path=db_path)
    return [asdict(f) for f in findings]
