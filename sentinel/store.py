from __future__ import annotations

import os
from typing import Any

from google.cloud import firestore

from .models import AuditResult, Submission


def persist_audit(submission: Submission, result: AuditResult) -> bool:
    """Write a compact audit record to Firestore when Cloud persistence is enabled."""
    project = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project or os.getenv("SENTINEL_DISABLE_PERSISTENCE") == "1":
        return False

    client = firestore.Client(project=project)
    key = submission.name.lower().replace(" ", "-").replace("—", "-")[:80]
    document: dict[str, Any] = {
        "submission_name": submission.name,
        "deadline": submission.deadline,
        "state": result.state.value,
        "confidence": result.confidence,
        "ready": result.ready,
        "review": result.review,
        "missing": result.missing,
        "hours_remaining": result.hours_remaining,
        "agent_summary": result.agent_summary,
        "generated_at": result.generated_at,
    }
    client.collection("deadline_sentinel_audits").document(key).set(document)
    return True
