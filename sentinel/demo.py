from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import Artifact, Submission


def sample_submission() -> Submission:
    now = datetime.now(timezone.utc)
    return Submission(
        name="Global Impact Grant — Final Package",
        deadline=now + timedelta(hours=31, minutes=20),
        timezone="Asia/Tokyo",
        artifacts=[
            Artifact(
                key="application",
                label="Application narrative",
                url="https://example.org/application",
                evidence="Version 7 approved by program lead",
            ),
            Artifact(
                key="budget",
                label="Signed budget",
                url="https://example.org/budget",
                evidence="Finance review completed 2026-08-22",
            ),
            Artifact(
                key="video",
                label="Public demo video",
                url="https://example.org/video",
                evidence=None,
            ),
            Artifact(
                key="impact",
                label="Impact data appendix",
                url=None,
                evidence=None,
            ),
            Artifact(
                key="approval",
                label="Final human approval",
                url=None,
                evidence="Awaiting executive sign-off",
            ),
        ],
    )
