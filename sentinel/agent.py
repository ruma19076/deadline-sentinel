from __future__ import annotations

import json
import os

from google.adk.agents import Agent
from google import genai

from .models import AuditResult, Submission


SYSTEM_INSTRUCTION = """
You are Deadline Sentinel, a submission operations agent. Turn deterministic
audit results into a short action brief. Never claim an artifact exists unless
the audit marks it ready. Never invent, interpolate, or repair missing evidence.
Prioritize the smallest set of actions that protects eligibility. Any final
submission or destructive change requires explicit human approval.
""".strip()


root_agent = Agent(
    name="deadline_sentinel",
    model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
    description="Prioritizes submission work without overriding deterministic gates.",
    instruction=SYSTEM_INSTRUCTION,
)


def _fallback_summary(result: AuditResult) -> str:
    if result.state.value == "ready":
        return "All required evidence passed deterministic checks. Human approval remains before submission."
    if result.missing:
        return f"Submission is blocked by {result.missing} missing requirement(s). Resolve the priority-one actions first."
    return f"No evidence is missing, but {result.review} item(s) still require human verification."


def summarize_with_gemini(submission: Submission, result: AuditResult) -> str:
    """Use Gemini when configured; stay fully functional in deterministic demo mode."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _fallback_summary(result)

    client = genai.Client(api_key=api_key)
    payload = {
        "submission": submission.model_dump(mode="json"),
        "audit": result.model_dump(mode="json"),
    }
    response = client.models.generate_content(
        model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
        contents=f"{SYSTEM_INSTRUCTION}\n\nReturn a two-sentence action brief:\n{json.dumps(payload)}",
    )
    return (response.text or _fallback_summary(result)).strip()
