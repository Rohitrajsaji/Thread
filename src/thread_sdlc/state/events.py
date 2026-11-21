"""Secret-redacted SQLite event logger."""

from __future__ import annotations

import json
from typing import Any

from thread_sdlc.governance import redactor
from thread_sdlc.state.db import StateDatabase
from thread_sdlc.state.models import EventRecord, utc_now_iso


class EventLogger:
    """Persists events to SQLite after mandatory pre-storage secret redaction."""

    def __init__(self, db: StateDatabase) -> None:
        self.db = db

    def emit(
        self,
        thread_id: str | None,
        event_type: str,
        payload: dict[str, Any] | str | None = None,
    ) -> EventRecord:
        """Scrub ``payload`` via ``redactor`` and insert into ``events``."""
        if payload is None:
            serialized = "{}"
        elif isinstance(payload, dict):
            scrubbed_dict = redactor.redact_payload(payload)
            serialized = json.dumps(scrubbed_dict, ensure_ascii=False)
        else:
            serialized = redactor.redact_json(str(payload))

        # Mandatory pre-insert text scrubbing invariant
        safe_payload_json = redactor.redact_text(serialized)
        created_at = utc_now_iso()

        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (thread_id, type, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (thread_id, event_type, safe_payload_json, created_at),
            )
            row_id = cur.lastrowid

        return EventRecord(
            id=row_id,
            thread_id=thread_id,
            type=event_type,
            payload_json=safe_payload_json,
            created_at=created_at,
        )

    def list_events(
        self,
        thread_id: str | None = None,
        after_id: int = 0,
        limit: int = 200,
    ) -> list[EventRecord]:
        """Return events ordered ascending by ``id`` (supports SSE tailing)."""
        with self.db.read_connection() as conn:
            if thread_id is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE thread_id = ? AND id > ?
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (thread_id, after_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE id > ?
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (after_id, limit),
                ).fetchall()

        return [
            EventRecord(
                id=int(r["id"]),
                thread_id=r["thread_id"],
                type=r["type"],
                payload_json=r["payload_json"],
                created_at=r["created_at"],
            )
            for r in rows
        ]
