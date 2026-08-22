from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import Action, ArtifactState, AuditResult, Submission


def _valid_public_url(value: object) -> bool:
    if value is None:
        return False
    parsed = urlparse(str(value))
    return parsed.scheme == "https" and bool(parsed.netloc)


def audit_submission(submission: Submission, now: datetime | None = None) -> AuditResult:
    """Apply reproducible gates before asking the model to prioritize work."""
    current = now or datetime.now(timezone.utc)
    deadline = submission.deadline
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)

    checked = []
    actions: list[Action] = []
    for artifact in submission.artifacts:
        item = artifact.model_copy(deep=True)
        has_url = _valid_public_url(item.url)
        has_evidence = bool(item.evidence and item.evidence.strip())

        if has_url and has_evidence:
            item.state = ArtifactState.READY
        elif has_url or has_evidence:
            item.state = ArtifactState.REVIEW
            actions.append(
                Action(
                    priority=2,
                    title=f"Verify {item.label}",
                    reason="A link or verification note is present, but not both.",
                    requires_human=True,
                )
            )
        elif item.required:
            item.state = ArtifactState.MISSING
            actions.append(
                Action(
                    priority=1,
                    title=f"Add {item.label}",
                    reason="The requirement is mandatory and no evidence is attached.",
                )
            )
        else:
            item.state = ArtifactState.REVIEW
        checked.append(item)

    counts = {state: sum(a.state == state for a in checked) for state in ArtifactState}
    total = len(checked)
    weighted = counts[ArtifactState.READY] + 0.5 * counts[ArtifactState.REVIEW]
    confidence = round(100 * weighted / total) if total else 0
    hours_remaining = max(0.0, (deadline - current).total_seconds() / 3600)

    if counts[ArtifactState.MISSING]:
        state = ArtifactState.MISSING
    elif counts[ArtifactState.REVIEW]:
        state = ArtifactState.REVIEW
    else:
        state = ArtifactState.READY

    if hours_remaining <= 24 and state != ArtifactState.READY:
        actions.insert(
            0,
            Action(
                priority=1,
                title="Freeze non-essential work",
                reason="The deadline is under 24 hours away and required evidence is unresolved.",
                requires_human=True,
            ),
        )

    return AuditResult(
        state=state,
        confidence=confidence,
        ready=counts[ArtifactState.READY],
        review=counts[ArtifactState.REVIEW],
        missing=counts[ArtifactState.MISSING],
        total=total,
        hours_remaining=round(hours_remaining, 1),
        artifacts=checked,
        actions=sorted(actions, key=lambda action: action.priority),
        agent_summary="",
        generated_at=current,
    )
