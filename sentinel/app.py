from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .agent import summarize_with_gemini
from .demo import sample_submission
from .models import AuditResult, Submission
from .store import persist_audit
from .validator import audit_submission


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "web"

app = FastAPI(title="Deadline Sentinel", version="0.1.0")
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


def run_audit(submission: Submission) -> AuditResult:
    result = audit_submission(submission)
    result.agent_summary = summarize_with_gemini(submission, result)
    persist_audit(submission, result)
    return result


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/demo", response_model=AuditResult)
def demo() -> AuditResult:
    return run_audit(sample_submission())


@app.post("/api/tick", response_model=AuditResult)
def scheduled_tick() -> AuditResult:
    """Cloud Scheduler target: re-audit active work without a chat interaction."""
    return run_audit(sample_submission())


@app.post("/api/audit", response_model=AuditResult)
def audit(submission: Submission) -> AuditResult:
    return run_audit(submission)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
