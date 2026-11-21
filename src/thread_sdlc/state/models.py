"""Pydantic v2 record models mirroring the 7 SQLite WAL tables."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Return current UTC ISO-8601 timestamp."""
    return datetime.now(UTC).isoformat()


class ThreadRecord(BaseModel):
    id: str
    title: str
    goal: str = ""
    track: int = 1
    status: str = "Intake"
    base_sha: str = ""
    risk_reasons: list[str] = Field(default_factory=list)
    credits_used: float = 0.0
    turns_used: int = 0
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


class TicketRecord(BaseModel):
    id: str
    thread_id: str
    title: str
    role: str
    status: str = "pending"
    depends_on: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    verifies_rules: list[str] = Field(default_factory=list)
    worktree_branch: str | None = None
    worktree_path: str | None = None
    result_sha: str | None = None


class AssignmentRecord(BaseModel):
    id: str
    ticket_id: str
    adapter_type: str
    status: str = "running"
    base_sha: str = ""
    result_sha: str | None = None
    commit_trailer: str
    turns_used: int = 0
    credits_used: float = 0.0
    log_path: str | None = None
    started_at: str = Field(default_factory=utc_now_iso)
    ended_at: str | None = None


class CheckpointRecord(BaseModel):
    id: str
    thread_id: str
    stage: str
    content_md: str
    content_sha256: str
    git_head_sha: str = ""
    gate_type: str
    permitted_next_stage: str | None = None
    status: str = "pending"
    waits_for_person: bool = False
    decision: str | None = None
    decided_at: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)


class AnnotationRecord(BaseModel):
    id: str
    checkpoint_id: str
    target_type: str
    file_path: str | None = None
    line_or_section: str | None = None
    comment: str
    resolved: bool = False
    created_at: str = Field(default_factory=utc_now_iso)


class VerificationRunRecord(BaseModel):
    id: str
    thread_id: str
    commit_sha: str
    mode: str
    passed: bool
    scorecard: dict[str, Any] = Field(default_factory=dict)
    rule_evidence: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


class EventRecord(BaseModel):
    id: int | None = None
    thread_id: str | None = None
    type: str
    payload_json: str = "{}"
    created_at: str = Field(default_factory=utc_now_iso)
