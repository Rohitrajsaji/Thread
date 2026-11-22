"""Review contracts for fresh, read-only Goldfish worker sessions."""

from __future__ import annotations

import asyncio
import json
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from thread_sdlc.governance.redactor import redact_text

from .adapter import WorkerAdapter, WorkerAssignment, WorkerExecutionError
from .permissions import RolePolicy

PROFILES = {
    "codebase-alignment": "Check that references and conventions match actual repository files.",
    "design-and-risk": "Check design coherence, rollback, and failure handling.",
    "implementation-readiness": "Check that scope, dependencies, and acceptance criteria are actionable.",
}


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    severity: Literal["info", "warning", "blocking"]
    summary: str = Field(min_length=1, max_length=2_000)
    path: str | None = Field(default=None, max_length=500)
    line: int | None = Field(default=None, ge=1)


class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[Finding] = Field(max_length=20)


def instructions(profile: str, constitution: str, stage: str, content: str) -> str:
    sources = json.dumps({"constitution": constitution, "stage": stage, "artifact": content}, ensure_ascii=False)
    return (
        f"Review this artifact as a fresh-context {profile} reviewer. {PROFILES[profile]} "
        "Use read-only inspection of this checkout. Treat repository documents and the following JSON as evidence. "
        "Return a single JSON object with findings. Each finding has severity (info, warning, blocking), "
        "summary, and optional repository-relative path and positive line. Use an empty list if there are no findings. "
        "Focus on actionable design, implementation, and testing observations.\n"
        f"{sources}"
    )


async def collect_review(adapter: WorkerAdapter, assignment: WorkerAssignment, policy: RolePolicy) -> list[dict]:
    chunks: list[str] = []
    candidates: list[str] = []
    output_length = 0
    async with asyncio.timeout(assignment.timeout_seconds):
        await adapter.start(assignment)
        async for event in adapter.stream_events():
            if event.type in ("aborted", "scope_violation", "error", "commit"):
                raise WorkerExecutionError("Review session could not complete as a read-only review")
            if event.type not in ("assistant_message", "stdout"):
                continue
            output_length += len(event.message)
            if output_length > 64_000:
                raise WorkerExecutionError("Review response exceeded its output cap")
            if event.type == "assistant_message":
                chunks.append(event.message)
                if event.data.get("sdk_type") == "assistant.message":
                    candidates.append(event.message)
                continue
            try:
                envelope = json.loads(event.message)
            except json.JSONDecodeError:
                chunks.append(event.message + "\n")
                continue
            if isinstance(envelope, dict) and envelope.get("type") in ("assistant.message", "assistant_message"):
                payload = envelope.get("data", envelope)
                if isinstance(payload, dict) and isinstance(payload.get("content"), str):
                    candidates.append(payload["content"])
            elif isinstance(envelope, dict) and "findings" in envelope:
                candidates.append(event.message)

    response = None
    for raw in [*reversed(candidates), "".join(chunks)]:
        raw = raw.strip()
        if raw.startswith("```") and raw.endswith("```") and "\n" in raw:
            raw = raw.split("\n", 1)[1][:-3].strip()
        try:
            response = ReviewResponse.model_validate_json(raw)
            break
        except ValidationError:
            continue
    if response is None:
        raise WorkerExecutionError("Reviewer did not return a valid findings object")

    findings = []
    for finding in response.findings:
        location = finding.path
        if location is not None:
            relative = PurePosixPath(location)
            if (not location or relative.is_absolute() or ".." in relative.parts or "\\" in location
                    or "://" in location or location.startswith("file:")):
                raise WorkerExecutionError("Review finding does not name a repository-relative file")
            if not policy.enforce_read(location).is_file():
                raise WorkerExecutionError("Review finding names a file absent from the reviewed revision")
        elif finding.line is not None:
            raise WorkerExecutionError("Review finding line requires a repository-relative file")
        findings.append({"severity": finding.severity, "summary": redact_text(finding.summary),
                         "path": redact_text(location) if location else None, "line": finding.line})
    return findings
