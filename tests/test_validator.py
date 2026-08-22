from datetime import datetime, timedelta, timezone

from sentinel.models import Artifact, ArtifactState, Submission
from sentinel.validator import audit_submission


NOW = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)


def submission(*artifacts: Artifact, hours: int = 48) -> Submission:
    return Submission(name="Test", deadline=NOW + timedelta(hours=hours), artifacts=list(artifacts))


def test_ready_requires_url_and_evidence() -> None:
    result = audit_submission(
        submission(Artifact(key="repo", label="Repository", url="https://example.com/repo", evidence="Public and verified")),
        now=NOW,
    )
    assert result.state == ArtifactState.READY
    assert result.confidence == 100


def test_missing_required_artifact_blocks_submission() -> None:
    result = audit_submission(submission(Artifact(key="video", label="Video")), now=NOW)
    assert result.state == ArtifactState.MISSING
    assert result.missing == 1
    assert result.actions[0].title == "Add Video"


def test_partial_evidence_requires_review() -> None:
    result = audit_submission(
        submission(Artifact(key="diagram", label="Diagram", url="https://example.com/diagram")),
        now=NOW,
    )
    assert result.state == ArtifactState.REVIEW
    assert result.review == 1
    assert result.confidence == 50


def test_urgent_unresolved_submission_freezes_nonessential_work() -> None:
    result = audit_submission(submission(Artifact(key="approval", label="Approval"), hours=12), now=NOW)
    assert result.actions[0].title == "Freeze non-essential work"
    assert result.actions[0].requires_human is True


def test_naive_deadline_is_treated_as_utc() -> None:
    item = Submission(name="Test", deadline=datetime(2026, 8, 23), artifacts=[])
    result = audit_submission(item, now=NOW)
    assert result.hours_remaining == 12
