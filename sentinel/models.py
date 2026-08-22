from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class ArtifactState(StrEnum):
    READY = "ready"
    REVIEW = "review"
    MISSING = "missing"


class Artifact(BaseModel):
    key: str
    label: str
    required: bool = True
    url: HttpUrl | None = None
    evidence: str | None = None
    state: ArtifactState = ArtifactState.MISSING


class Submission(BaseModel):
    name: str
    deadline: datetime
    timezone: str = "UTC"
    owner: str = "Solo builder"
    artifacts: list[Artifact] = Field(default_factory=list)


class Action(BaseModel):
    priority: int = Field(ge=1, le=3)
    title: str
    reason: str
    requires_human: bool = False


class AuditResult(BaseModel):
    state: ArtifactState
    confidence: int = Field(ge=0, le=100)
    ready: int
    review: int
    missing: int
    total: int
    hours_remaining: float
    artifacts: list[Artifact]
    actions: list[Action]
    agent_summary: str
    generated_at: datetime
