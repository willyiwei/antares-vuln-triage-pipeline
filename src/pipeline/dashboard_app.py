"""FastAPI dashboard for the AnTAres Vulnerability Triage Pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import PipelineConfig
from .models import ScanResult, VulnerabilityFinding, Severity, FindingStatus, GovernanceDecision
from .pipeline import TriagePipeline
from .sarif import write_sarif, write_json

app = FastAPI(title="AnTAres Vulnerability Triage Dashboard", version="0.1.0")

# In-memory scan store (replace with DB in production)
_scan_store: dict[str, ScanResult] = {}


class ScanRequest(BaseModel):
    repo_url: str
    branch: str | None = None


class GovernanceUpdate(BaseModel):
    scan_id: str
    finding_id: str
    decision: str
    status: str
    notes: str = ""


@app.get("/", response_class=HTMLResponse)
async def dashboard_root() -> str:
    """Serve the dashboard HTML page."""
    html_path = Path(__file__).parent.parent.parent / "dashboard" / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path))
    return HTMLResponse(content=_default_dashboard_html())


@app.post("/api/scan")
async def start_scan(request: ScanRequest) -> dict[str, Any]:
    """Start a new scan."""
    config = PipelineConfig()
    pipeline = TriagePipeline(config)
    result = await pipeline.run_scan(request.repo_url, branch=request.branch)
    _scan_store[result.scan_id] = result
    return {"scanId": result.scan_id, "status": "completed", "totalFindings": result.total_findings}


@app.get("/api/scans")
async def list_scans() -> list[dict[str, Any]]:
    """List all scans."""
    return [
        {
            "scanId": s.scan_id,
            "repoUrl": s.repo_url,
            "branch": s.branch,
            "totalFindings": s.total_findings,
            "completedAt": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in _scan_store.values()
    ]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    """Get scan results by ID."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_store[scan_id].model_dump(mode="json")


@app.patch("/api/scans/{scan_id}/findings/{finding_id}")
async def update_finding(scan_id: str, finding_id: str, update: GovernanceUpdate) -> dict[str, Any]:
    """Update a finding's governance decision and status."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = _scan_store[scan_id]
    for f in scan.findings:
        if f.id == finding_id:
            f.governance_decision = GovernanceDecision(update.decision) if update.decision else None
            f.status = FindingStatus(update.status) if update.status else f.status
            f.triage_reasoning = update.notes
            return {"status": "updated", "findingId": finding_id}
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/api/scans/{scan_id}/reports/sarif")
async def get_sarif_report(scan_id: str) -> dict[str, Any]:
    """Get SARIF report for a scan."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    from .sarif import build_sarif
    return build_sarif(_scan_store[scan_id])


def _default_dashboard_html() -> str:
    """Fallback HTML for the dashboard."""
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>AnTAres Triage Dashboard</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 2rem; background: #f5f5f5; }
h1 { color: #1a1a2e; }
.card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.severity-critical { color: #dc3545; font-weight: bold; }
.severity-high { color: #fd7e14; font-weight: bold; }
.severity-medium { color: #ffc107; }
.severity-low { color: #28a745; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }
button { padding: 0.4rem 1rem; border: none; border-radius: 4px; cursor: pointer; background: #007bff; color: white; }
button:hover { background: #0056b3; }
</style>
</head>
<body>
<h1>🔍 AnTAres Vulnerability Triage Dashboard</h1>
<div class="card">
<h2>Quick Start</h2>
<p>Run a scan from the CLI: <code>antares-triage scan -r https://github.com/example/repo</code></p>
<p>Or use the API: <code>POST /api/scan { "repo_url": "https://..." }</code></p>
</div>
<div class="card" id="scans">
<h2>Scans</h2>
<p>No scans yet. Run a scan to see results here.</p>
</div>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8181)
