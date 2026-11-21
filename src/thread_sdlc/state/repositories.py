"""Typed repositories for threads, tickets, assignments, checkpoints, annotations, and verifications."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from thread_sdlc.state.db import StateDatabase
from thread_sdlc.state.models import (
    AnnotationRecord,
    AssignmentRecord,
    CheckpointRecord,
    ThreadRecord,
    TicketRecord,
    VerificationRunRecord,
    utc_now_iso,
)


def _row_to_thread(row: sqlite3.Row) -> ThreadRecord:
    return ThreadRecord(
        id=row["id"],
        title=row["title"],
        goal=row["goal"],
        track=row["track"],
        status=row["status"],
        base_sha=row["base_sha"],
        risk_reasons=json.loads(row["risk_reasons_json"]),
        credits_used=float(row["credits_used"]),
        turns_used=int(row["turns_used"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_ticket(row: sqlite3.Row) -> TicketRecord:
    return TicketRecord(
        id=row["id"],
        thread_id=row["thread_id"],
        title=row["title"],
        role=row["role"],
        status=row["status"],
        depends_on=json.loads(row["depends_on_json"]),
        paths=json.loads(row["paths_json"]),
        verifies_rules=json.loads(row["verifies_rules_json"]),
        worktree_branch=row["worktree_branch"],
        worktree_path=row["worktree_path"],
        result_sha=row["result_sha"],
    )


def _row_to_assignment(row: sqlite3.Row) -> AssignmentRecord:
    return AssignmentRecord(
        id=row["id"],
        ticket_id=row["ticket_id"],
        adapter_type=row["adapter_type"],
        status=row["status"],
        base_sha=row["base_sha"],
        result_sha=row["result_sha"],
        commit_trailer=row["commit_trailer"],
        turns_used=int(row["turns_used"]),
        credits_used=float(row["credits_used"]),
        log_path=row["log_path"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
    )


def _row_to_checkpoint(row: sqlite3.Row) -> CheckpointRecord:
    return CheckpointRecord(
        id=row["id"],
        thread_id=row["thread_id"],
        stage=row["stage"],
        content_md=row["content_md"],
        content_sha256=row["content_sha256"],
        git_head_sha=row["git_head_sha"],
        gate_type=row["gate_type"],
        permitted_next_stage=row["permitted_next_stage"],
        status=row["status"],
        waits_for_person=bool(row["waits_for_person"]),
        decision=row["decision"],
        decided_at=row["decided_at"],
        created_at=row["created_at"],
    )


def _row_to_annotation(row: sqlite3.Row) -> AnnotationRecord:
    return AnnotationRecord(
        id=row["id"],
        checkpoint_id=row["checkpoint_id"],
        target_type=row["target_type"],
        file_path=row["file_path"],
        line_or_section=row["line_or_section"],
        comment=row["comment"],
        resolved=bool(row["resolved"]),
        created_at=row["created_at"],
    )


def _row_to_verification(row: sqlite3.Row) -> VerificationRunRecord:
    return VerificationRunRecord(
        id=row["id"],
        thread_id=row["thread_id"],
        commit_sha=row["commit_sha"],
        mode=row["mode"],
        passed=bool(row["passed"]),
        scorecard=json.loads(row["scorecard_json"]),
        rule_evidence=json.loads(row["rule_evidence_json"]),
        created_at=row["created_at"],
    )


class StateRepository:
    """Unified CRUD repository over the 6 entity tables in ``StateDatabase``."""

    def __init__(self, db: StateDatabase) -> None:
        self.db = db

    # --- Threads ---

    def create_thread(self, thread: ThreadRecord) -> ThreadRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO threads (
                    id, title, goal, track, status, base_sha, risk_reasons_json,
                    credits_used, turns_used, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    thread.id,
                    thread.title,
                    thread.goal,
                    thread.track,
                    thread.status,
                    thread.base_sha,
                    json.dumps(thread.risk_reasons),
                    thread.credits_used,
                    thread.turns_used,
                    thread.created_at,
                    thread.updated_at,
                ),
            )
        return thread

    def get_thread(self, thread_id: str) -> ThreadRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute("SELECT * FROM threads WHERE id = ?", (thread_id,)).fetchone()
            return _row_to_thread(row) if row is not None else None

    def get_latest_thread(self) -> ThreadRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM threads ORDER BY updated_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
            return _row_to_thread(row) if row is not None else None

    def list_threads(self) -> list[ThreadRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM threads ORDER BY updated_at DESC, rowid DESC"
            ).fetchall()
            return [_row_to_thread(r) for r in rows]

    def update_thread(
        self,
        thread_id: str,
        *,
        track: int | None = None,
        status: str | None = None,
        base_sha: str | None = None,
        risk_reasons: list[str] | None = None,
        credits_used: float | None = None,
        turns_used: int | None = None,
    ) -> ThreadRecord | None:
        fields: list[str] = ["updated_at = ?"]
        params: list[Any] = [utc_now_iso()]
        if track is not None:
            fields.append("track = ?")
            params.append(track)
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if base_sha is not None:
            fields.append("base_sha = ?")
            params.append(base_sha)
        if risk_reasons is not None:
            fields.append("risk_reasons_json = ?")
            params.append(json.dumps(risk_reasons))
        if credits_used is not None:
            fields.append("credits_used = ?")
            params.append(credits_used)
        if turns_used is not None:
            fields.append("turns_used = ?")
            params.append(turns_used)

        params.append(thread_id)
        with self.db.transaction() as conn:
            conn.execute(f"UPDATE threads SET {', '.join(fields)} WHERE id = ?", params)
        return self.get_thread(thread_id)

    def increment_thread_usage(
        self, thread_id: str, *, credits_delta: float = 0.0, turns_delta: int = 0
    ) -> ThreadRecord | None:
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE threads
                SET credits_used = credits_used + ?,
                    turns_used = turns_used + ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (credits_delta, turns_delta, utc_now_iso(), thread_id),
            )
        return self.get_thread(thread_id)

    # --- Tickets ---

    def create_ticket(self, ticket: TicketRecord) -> TicketRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO tickets (
                    id, thread_id, title, role, status, depends_on_json,
                    paths_json, verifies_rules_json, worktree_branch, worktree_path, result_sha
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket.id,
                    ticket.thread_id,
                    ticket.title,
                    ticket.role,
                    ticket.status,
                    json.dumps(ticket.depends_on),
                    json.dumps(ticket.paths),
                    json.dumps(ticket.verifies_rules),
                    ticket.worktree_branch,
                    ticket.worktree_path,
                    ticket.result_sha,
                ),
            )
        return ticket

    def upsert_tickets(self, thread_id: str, tickets: list[TicketRecord]) -> list[TicketRecord]:
        with self.db.transaction() as conn:
            for ticket in tickets:
                conn.execute(
                    """
                    INSERT INTO tickets (
                        id, thread_id, title, role, status, depends_on_json,
                        paths_json, verifies_rules_json, worktree_branch, worktree_path, result_sha
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        role = excluded.role,
                        status = excluded.status,
                        depends_on_json = excluded.depends_on_json,
                        paths_json = excluded.paths_json,
                        verifies_rules_json = excluded.verifies_rules_json,
                        worktree_branch = COALESCE(excluded.worktree_branch, tickets.worktree_branch),
                        worktree_path = COALESCE(excluded.worktree_path, tickets.worktree_path),
                        result_sha = COALESCE(excluded.result_sha, tickets.result_sha)
                    """,
                    (
                        ticket.id,
                        thread_id,
                        ticket.title,
                        ticket.role,
                        ticket.status,
                        json.dumps(ticket.depends_on),
                        json.dumps(ticket.paths),
                        json.dumps(ticket.verifies_rules),
                        ticket.worktree_branch,
                        ticket.worktree_path,
                        ticket.result_sha,
                    ),
                )
        return self.list_tickets(thread_id)

    def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            return _row_to_ticket(row) if row is not None else None

    def list_tickets(self, thread_id: str) -> list[TicketRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tickets WHERE thread_id = ? ORDER BY rowid ASC", (thread_id,)
            ).fetchall()
            return [_row_to_ticket(r) for r in rows]

    def update_ticket(
        self,
        ticket_id: str,
        *,
        status: str | None = None,
        worktree_branch: str | None = None,
        worktree_path: str | None = None,
        result_sha: str | None = None,
    ) -> TicketRecord | None:
        fields: list[str] = []
        params: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if worktree_branch is not None:
            fields.append("worktree_branch = ?")
            params.append(worktree_branch)
        if worktree_path is not None:
            fields.append("worktree_path = ?")
            params.append(worktree_path)
        if result_sha is not None:
            fields.append("result_sha = ?")
            params.append(result_sha)
        if not fields:
            return self.get_ticket(ticket_id)
        params.append(ticket_id)
        with self.db.transaction() as conn:
            conn.execute(f"UPDATE tickets SET {', '.join(fields)} WHERE id = ?", params)
        return self.get_ticket(ticket_id)

    # --- Assignments ---

    def create_assignment(self, assignment: AssignmentRecord) -> AssignmentRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO assignments (
                    id, ticket_id, adapter_type, status, base_sha, result_sha,
                    commit_trailer, turns_used, credits_used, log_path, started_at, ended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assignment.id,
                    assignment.ticket_id,
                    assignment.adapter_type,
                    assignment.status,
                    assignment.base_sha,
                    assignment.result_sha,
                    assignment.commit_trailer,
                    assignment.turns_used,
                    assignment.credits_used,
                    assignment.log_path,
                    assignment.started_at,
                    assignment.ended_at,
                ),
            )
        return assignment

    def get_assignment(self, assignment_id: str) -> AssignmentRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM assignments WHERE id = ?", (assignment_id,)
            ).fetchone()
            return _row_to_assignment(row) if row is not None else None

    def get_latest_assignment_for_ticket(self, ticket_id: str) -> AssignmentRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM assignments
                WHERE ticket_id = ?
                ORDER BY started_at DESC, rowid DESC
                LIMIT 1
                """,
                (ticket_id,),
            ).fetchone()
            return _row_to_assignment(row) if row is not None else None

    def list_assignments_for_ticket(self, ticket_id: str) -> list[AssignmentRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM assignments WHERE ticket_id = ? ORDER BY rowid ASC",
                (ticket_id,),
            ).fetchall()
            return [_row_to_assignment(r) for r in rows]

    def list_running_assignments(self, thread_id: str) -> list[AssignmentRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                """
                SELECT a.* FROM assignments a
                JOIN tickets t ON t.id = a.ticket_id
                WHERE t.thread_id = ? AND a.status = 'running'
                ORDER BY a.rowid ASC
                """,
                (thread_id,),
            ).fetchall()
            return [_row_to_assignment(r) for r in rows]

    def count_active_assignments(self, thread_id: str) -> int:
        with self.db.read_connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS cnt FROM assignments a
                JOIN tickets t ON t.id = a.ticket_id
                WHERE t.thread_id = ? AND a.status = 'running'
                """,
                (thread_id,),
            ).fetchone()
            return int(row["cnt"]) if row is not None else 0

    def reserve_running_assignment(
        self,
        *,
        thread_id: str,
        assignment: AssignmentRecord,
        max_workers_per_thread: int,
        max_retries_per_ticket: int,
        max_credits_per_thread: float,
    ) -> tuple[ThreadRecord, TicketRecord, str | None, dict[str, Any]]:
        """Atomically check quota/concurrency/retry caps and insert a ``running`` assignment."""
        with self.db.transaction() as conn:
            thread_row = conn.execute(
                "SELECT * FROM threads WHERE id = ?", (thread_id,)
            ).fetchone()
            if thread_row is None:
                raise KeyError(f"Thread {thread_id!r} not found")
            thread = _row_to_thread(thread_row)

            ticket_row = conn.execute(
                "SELECT * FROM tickets WHERE id = ?", (assignment.ticket_id,)
            ).fetchone()
            if ticket_row is None:
                raise KeyError(f"Ticket {assignment.ticket_id!r} not found")
            ticket = _row_to_ticket(ticket_row)
            if ticket.thread_id != thread_id:
                raise ValueError(
                    f"Ticket {assignment.ticket_id!r} belongs to thread {ticket.thread_id!r}, "
                    f"not {thread_id!r}"
                )

            if (
                thread.status == "PausedQuota"
                or thread.credits_used >= max_credits_per_thread
            ):
                return thread, ticket, "paused_quota", {}

            running_ticket_row = conn.execute(
                "SELECT id FROM assignments WHERE ticket_id = ? AND status = 'running' LIMIT 1",
                (assignment.ticket_id,),
            ).fetchone()
            if running_ticket_row is not None:
                return (
                    thread,
                    ticket,
                    "ticket_already_running",
                    {"running_assignment_id": running_ticket_row["id"]},
                )

            active_row = conn.execute(
                """
                SELECT COUNT(*) AS cnt FROM assignments a
                JOIN tickets t ON t.id = a.ticket_id
                WHERE t.thread_id = ? AND a.status = 'running'
                """,
                (thread_id,),
            ).fetchone()
            active_workers = int(active_row["cnt"]) if active_row is not None else 0
            if active_workers >= max_workers_per_thread:
                return (
                    thread,
                    ticket,
                    "concurrency_limit",
                    {"active_workers": active_workers},
                )

            prior_rows = conn.execute(
                "SELECT status FROM assignments WHERE ticket_id = ?",
                (assignment.ticket_id,),
            ).fetchall()
            failed_attempts = sum(1 for r in prior_rows if r["status"] == "failed")
            if failed_attempts > max_retries_per_ticket:
                return (
                    thread,
                    ticket,
                    "retry_limit",
                    {"failed_attempts": failed_attempts},
                )

            existing_row = conn.execute(
                "SELECT status FROM assignments WHERE id = ?",
                (assignment.id,),
            ).fetchone()
            if existing_row is not None:
                return (
                    thread,
                    ticket,
                    "duplicate_assignment",
                    {"existing_status": existing_row["status"]},
                )

            conn.execute(
                """
                INSERT INTO assignments (
                    id, ticket_id, adapter_type, status, base_sha, result_sha,
                    commit_trailer, turns_used, credits_used, log_path, started_at, ended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assignment.id,
                    assignment.ticket_id,
                    assignment.adapter_type,
                    "running",
                    assignment.base_sha,
                    assignment.result_sha,
                    assignment.commit_trailer,
                    assignment.turns_used,
                    assignment.credits_used,
                    assignment.log_path,
                    assignment.started_at,
                    assignment.ended_at,
                ),
            )
            return thread, ticket, None, {"active_workers": active_workers}

    def update_assignment(
        self,
        assignment_id: str,
        *,
        adapter_type: str | None = None,
        base_sha: str | None = None,
        status: str | None = None,
        result_sha: str | None = None,
        turns_used: int | None = None,
        credits_used: float | None = None,
        log_path: str | None = None,
        ended_at: str | None = None,
    ) -> AssignmentRecord | None:
        fields: list[str] = []
        params: list[Any] = []
        if adapter_type is not None:
            fields.append("adapter_type = ?")
            params.append(adapter_type)
        if base_sha is not None:
            fields.append("base_sha = ?")
            params.append(base_sha)
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if result_sha is not None:
            fields.append("result_sha = ?")
            params.append(result_sha)
        if turns_used is not None:
            fields.append("turns_used = ?")
            params.append(turns_used)
        if credits_used is not None:
            fields.append("credits_used = ?")
            params.append(credits_used)
        if log_path is not None:
            fields.append("log_path = ?")
            params.append(log_path)
        if ended_at is not None:
            fields.append("ended_at = ?")
            params.append(ended_at)
        if not fields:
            return self.get_assignment(assignment_id)
        params.append(assignment_id)
        with self.db.transaction() as conn:
            conn.execute(f"UPDATE assignments SET {', '.join(fields)} WHERE id = ?", params)
        return self.get_assignment(assignment_id)

    # --- Checkpoints & Annotations (M2/M4 forward compatibility) ---

    def create_checkpoint(self, checkpoint: CheckpointRecord) -> CheckpointRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (
                    id, thread_id, stage, content_md, content_sha256, git_head_sha,
                    gate_type, permitted_next_stage, status, waits_for_person,
                    decision, decided_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint.id,
                    checkpoint.thread_id,
                    checkpoint.stage,
                    checkpoint.content_md,
                    checkpoint.content_sha256,
                    checkpoint.git_head_sha,
                    checkpoint.gate_type,
                    checkpoint.permitted_next_stage,
                    checkpoint.status,
                    int(checkpoint.waits_for_person),
                    checkpoint.decision,
                    checkpoint.decided_at,
                    checkpoint.created_at,
                ),
            )
        return checkpoint

    def get_checkpoint(self, checkpoint_id: str) -> CheckpointRecord | None:
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE id = ?", (checkpoint_id,)
            ).fetchone()
            return _row_to_checkpoint(row) if row is not None else None

    def get_latest_checkpoint(
        self, thread_id: str, stage: str | None = None
    ) -> CheckpointRecord | None:
        with self.db.read_connection() as conn:
            if stage is not None:
                row = conn.execute(
                    """
                    SELECT * FROM checkpoints
                    WHERE thread_id = ? AND stage = ?
                    ORDER BY created_at DESC, rowid DESC LIMIT 1
                    """,
                    (thread_id, stage),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM checkpoints
                    WHERE thread_id = ?
                    ORDER BY created_at DESC, rowid DESC LIMIT 1
                    """,
                    (thread_id,),
                ).fetchone()
            return _row_to_checkpoint(row) if row is not None else None

    def list_checkpoints(self, thread_id: str) -> list[CheckpointRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM checkpoints WHERE thread_id = ? ORDER BY rowid ASC",
                (thread_id,),
            ).fetchall()
            return [_row_to_checkpoint(r) for r in rows]

    def update_checkpoint_decision(
        self,
        checkpoint_id: str,
        *,
        status: str,
        decision: str,
        decided_at: str | None = None,
        waits_for_person: bool = False,
    ) -> CheckpointRecord | None:
        ts = decided_at or utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                """
                UPDATE checkpoints
                SET status = ?, decision = ?, decided_at = ?, waits_for_person = ?
                WHERE id = ?
                """,
                (status, decision, ts, int(waits_for_person), checkpoint_id),
            )
        return self.get_checkpoint(checkpoint_id)

    def mark_stale_checkpoints(self, thread_id: str, current_head_sha: str) -> int:
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE checkpoints
                SET status = 'stale'
                WHERE thread_id = ? AND status IN ('approved', 'pending')
                  AND git_head_sha != '' AND git_head_sha != ?
                """,
                (thread_id, current_head_sha),
            )
            return cur.rowcount

    def create_annotation(self, annotation: AnnotationRecord) -> AnnotationRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO annotations (
                    id, checkpoint_id, target_type, file_path, line_or_section,
                    comment, resolved, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    annotation.id,
                    annotation.checkpoint_id,
                    annotation.target_type,
                    annotation.file_path,
                    annotation.line_or_section,
                    annotation.comment,
                    int(annotation.resolved),
                    annotation.created_at,
                ),
            )
        return annotation

    def list_annotations(self, checkpoint_id: str) -> list[AnnotationRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM annotations WHERE checkpoint_id = ? ORDER BY rowid ASC",
                (checkpoint_id,),
            ).fetchall()
            return [_row_to_annotation(r) for r in rows]

    def resolve_annotation(self, annotation_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute("UPDATE annotations SET resolved = 1 WHERE id = ?", (annotation_id,))

    # --- Verification Runs ---

    def create_verification_run(self, run: VerificationRunRecord) -> VerificationRunRecord:
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO verification_runs (
                    id, thread_id, commit_sha, mode, passed,
                    scorecard_json, rule_evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.thread_id,
                    run.commit_sha,
                    run.mode,
                    int(run.passed),
                    json.dumps(run.scorecard),
                    json.dumps(run.rule_evidence),
                    run.created_at,
                ),
            )
        return run

    def get_latest_verification_run(
        self, thread_id: str, commit_sha: str | None = None
    ) -> VerificationRunRecord | None:
        with self.db.read_connection() as conn:
            if commit_sha is not None:
                row = conn.execute(
                    """
                    SELECT * FROM verification_runs
                    WHERE thread_id = ? AND commit_sha = ?
                    ORDER BY created_at DESC, rowid DESC LIMIT 1
                    """,
                    (thread_id, commit_sha),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM verification_runs
                    WHERE thread_id = ?
                    ORDER BY created_at DESC, rowid DESC LIMIT 1
                    """,
                    (thread_id,),
                ).fetchone()
            return _row_to_verification(row) if row is not None else None

    def list_verification_runs(self, thread_id: str) -> list[VerificationRunRecord]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM verification_runs WHERE thread_id = ? ORDER BY rowid ASC",
                (thread_id,),
            ).fetchall()
            return [_row_to_verification(r) for r in rows]
