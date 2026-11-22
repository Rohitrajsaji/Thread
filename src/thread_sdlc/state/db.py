"""SQLite WAL durable state manager and `.gitignore` protection for `.thread-state/`."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    goal TEXT NOT NULL DEFAULT '',
    track INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    base_sha TEXT NOT NULL DEFAULT '',
    risk_reasons_json TEXT NOT NULL DEFAULT '[]',
    credits_used REAL NOT NULL DEFAULT 0.0,
    turns_used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    paths_json TEXT NOT NULL DEFAULT '[]',
    verifies_rules_json TEXT NOT NULL DEFAULT '[]',
    worktree_branch TEXT,
    worktree_path TEXT,
    result_sha TEXT
);

CREATE TABLE IF NOT EXISTS assignments (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    adapter_type TEXT NOT NULL,
    status TEXT NOT NULL,
    base_sha TEXT NOT NULL DEFAULT '',
    result_sha TEXT,
    commit_trailer TEXT NOT NULL,
    turns_used INTEGER NOT NULL DEFAULT 0,
    credits_used REAL NOT NULL DEFAULT 0.0,
    log_path TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    content_md TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    git_head_sha TEXT NOT NULL DEFAULT '',
    gate_type TEXT NOT NULL,
    permitted_next_stage TEXT,
    status TEXT NOT NULL,
    waits_for_person INTEGER NOT NULL DEFAULT 0,
    decision TEXT,
    decided_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS annotations (
    id TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL,
    file_path TEXT,
    line_or_section TEXT,
    comment TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_runs (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    commit_sha TEXT NOT NULL,
    mode TEXT NOT NULL,
    passed INTEGER NOT NULL,
    scorecard_json TEXT NOT NULL DEFAULT '{}',
    rule_evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tickets_thread_id ON tickets(thread_id);
CREATE INDEX IF NOT EXISTS idx_assignments_ticket_id ON assignments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_thread_id ON checkpoints(thread_id);
CREATE INDEX IF NOT EXISTS idx_annotations_checkpoint_id ON annotations(checkpoint_id);
CREATE INDEX IF NOT EXISTS idx_verification_runs_thread_id ON verification_runs(thread_id);
CREATE INDEX IF NOT EXISTS idx_events_thread_id ON events(thread_id);
"""

_GITIGNORE_TOKENS = {".thread-state", ".thread-state/", "/.thread-state", "/.thread-state/"}


def ensure_state_gitignored(repo_root: Path) -> bool:
    """Ensure `.thread-state/` is listed in ``repo_root/.gitignore`` without clobbering entries.

    Returns True if `.gitignore` was created or modified, False if already covered.
    """
    gitignore_path = repo_root / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(".thread-state/\n", encoding="utf-8")
        return True

    existing = gitignore_path.read_text(encoding="utf-8")
    for raw_line in existing.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in _GITIGNORE_TOKENS:
            return False

    separator = "" if (not existing or existing.endswith("\n")) else "\n"
    gitignore_path.write_text(f"{existing}{separator}.thread-state/\n", encoding="utf-8")
    return True


class StateDatabase:
    """SQLite WAL connection and transaction manager for `.thread-state/thread.db`."""

    def __init__(
        self,
        db_path: Path | None = None,
        repo_root: Path | None = None,
        ensure_gitignore: bool = True,
    ) -> None:
        if db_path is None and repo_root is None:
            raise ValueError("Either db_path or repo_root must be provided.")
        if db_path is None:
            assert repo_root is not None
            db_path = repo_root / ".thread-state" / "thread.db"
        if repo_root is None and db_path.parent.name == ".thread-state":
            repo_root = db_path.parent.parent

        self._active: ContextVar[sqlite3.Connection | None] = ContextVar("thread_transaction", default=None)
        self.db_path = db_path.resolve()
        self.repo_root = repo_root.resolve() if repo_root is not None else None
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        if ensure_gitignore and self.repo_root is not None:
            ensure_state_gitignored(self.repo_root)

        self.initialize()

    def connect(self) -> sqlite3.Connection:
        """Open a configured SQLite connection with WAL mode and busy_timeout=5000."""
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def initialize(self) -> None:
        """Create schema tables and indexes if they do not exist."""
        conn = self.connect()
        try:
            conn.executescript(_SCHEMA_SQL)
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a write transaction serialized with ``BEGIN IMMEDIATE``."""
        active = self._active.get()
        if active is not None:
            yield active
            return
        conn = self.connect()
        token = self._active.set(conn)
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK;")
                except sqlite3.Error:
                    pass
            raise
        finally:
            self._active.reset(token)
            conn.close()

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        """Share the write snapshot inside a transaction."""
        active = self._active.get()
        if active is not None:
            yield active
            return
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()
