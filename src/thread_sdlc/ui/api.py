"""Local human review service. Only this process receives the launch credential."""
from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from thread_sdlc.state import StateDatabase, StateRepository, EventLogger
from thread_sdlc.orchestrator.engine import Workflow, InvalidTransitionError


class Note(BaseModel):
    comment: str = Field(min_length=1)
    target_type: str = "section"
    file_path: str | None = None
    line_or_section: str | None = None


class Decision(BaseModel):
    decision: str
    content_sha256: str
    git_head_sha: str
    reason: str = ""


class Merge(BaseModel):
    expected_head: str
    expected_base: str


def create_app(repo_root: Path, token: str, port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    origin = f"http://127.0.0.1:{port}"
    host = f"127.0.0.1:{port}"
    session = secrets.token_urlsafe(32)
    cookie = f"thread_session_{port}"
    exchanged = False
    db = StateDatabase(repo_root=repo_root)
    records = StateRepository(db)
    events = EventLogger(db)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        nonlocal exchanged
        if request.headers.get("host") != host:
            return JSONResponse({"detail": "Invalid local host"}, 403)
        if request.method not in ("GET", "HEAD") and request.headers.get("origin") != origin:
            return JSONResponse({"detail": "Invalid local origin"}, 403)
        if request.url.path == "/" and request.method == "GET" and "token" in request.query_params:
            if exchanged or not secrets.compare_digest(request.query_params["token"].encode(), token.encode()):
                return JSONResponse({"detail": "Invalid or expired launch link"}, 401)
            exchanged = True
            response = RedirectResponse("/", 303)
            response.set_cookie(cookie, session, httponly=True, samesite="strict")
        elif (secrets.compare_digest(request.cookies.get(cookie, "").encode(), session.encode())
              or secrets.compare_digest(request.headers.get("authorization", "").encode(), f"Bearer {token}".encode())):
            response = await call_next(request)
        else:
            response = JSONResponse({"detail": "Open the link printed by thread ui"}, 401)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"})
        return response

    async def conflict(request, exc):
        return JSONResponse({"detail": str(exc)}, 409)

    for cls in {InvalidTransitionError, ValueError, RuntimeError, PermissionError}:
        app.add_exception_handler(cls, conflict)

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": str(exc)}, 404)

    @app.get("/api/auth/session")
    def session_info():
        return {"reviewer": "Local reviewer"}

    @app.get("/api/threads")
    def threads():
        return records.list_threads()

    @app.get("/api/threads/{identifier}")
    def status(identifier: str):
        return Workflow(repo_root).status(identifier)

    @app.get("/api/events")
    async def stream(request: Request, thread_id: str | None = None, after: int = 0):
        async def messages():
            cursor = max(after, int(request.headers.get("last-event-id") or 0))
            while not await request.is_disconnected():
                rows = await asyncio.to_thread(events.list_events, thread_id, cursor)
                for event in rows:
                    cursor = event.id
                    yield f"id: {cursor}\ndata: {json.dumps(event.model_dump())}\n\n"
                if not rows:
                    yield ": keepalive\n\n"
                await asyncio.sleep(2)
        return StreamingResponse(messages(), media_type="text/event-stream")

    @app.post("/api/checkpoints/{identifier}/annotations")
    def annotate(identifier: str, note: Note):
        return Workflow(repo_root).annotate(identifier, **note.model_dump())

    @app.post("/api/checkpoints/{identifier}/decide")
    def decide(identifier: str, decision: Decision):
        return Workflow(repo_root).decide(identifier, **decision.model_dump())

    @app.get("/api/tickets/{identifier}/diff")
    def diff(identifier: str):
        return Workflow(repo_root).diff(identifier)

    @app.post("/api/tickets/{identifier}/merge")
    def merge(identifier: str, intent: Merge):
        return Workflow(repo_root).merge(identifier, **intent.model_dump())

    @app.post("/api/threads/{identifier}/resume")
    def resume(identifier: str):
        return Workflow(repo_root).start_or_resume(thread_id=identifier)

    static = Path(__file__).parent / "static"
    app.mount("/assets", StaticFiles(directory=static / "assets", check_dir=False), name="assets")

    @app.get("/")
    @app.get("/tasks/{identifier}")
    @app.get("/tasks/{identifier}/reviews/{review_id}")
    def index():
        return FileResponse(static / "index.html")

    return app
