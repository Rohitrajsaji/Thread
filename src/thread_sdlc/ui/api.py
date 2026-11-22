"""Local human review service. Only this process receives the launch credential."""
from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictBool

from thread_sdlc.config.loader import ConfigLoadError
from thread_sdlc.state import StateDatabase, StateRepository, EventLogger
from thread_sdlc.orchestrator.engine import Workflow, InvalidTransitionError
from .studio import (
    ConfigName, MAX_CONFIG_BYTES, list_observations, mission_control_status, promote_observation,
    read_config, save_config,
)


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


class PromoteObservation(BaseModel):
    confirm: StrictBool


class ConfigEdit(BaseModel):
    yaml: str = Field(max_length=MAX_CONFIG_BYTES)
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")


def create_app(repo_root: Path, token: str, port: int) -> FastAPI:
    repo_root = repo_root.resolve()
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

    for cls in {InvalidTransitionError, ValueError, RuntimeError, PermissionError, ConfigLoadError}:
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

    @app.get("/api/threads/{identifier}/proposal")
    def integration_proposal(identifier: str):
        return Workflow(repo_root).integration_diff(identifier)

    @app.post("/api/threads/{identifier}/merge")
    def merge_integration(identifier: str, intent: Merge):
        return Workflow(repo_root).merge_integration(identifier, **intent.model_dump())

    @app.post("/api/threads/{identifier}/resume")
    def resume(identifier: str):
        return Workflow(repo_root).start_or_resume(thread_id=identifier)

    @app.get("/api/mission-control")
    def mission_control():
        return mission_control_status(repo_root)

    def require_mission_control(*, graph: bool = False):
        if not mission_control_status(repo_root)["graph_enabled" if graph else "enabled"]:
            raise HTTPException(status_code=404, detail="This Mission Control feature is disabled")

    @app.get("/api/mission-control/graph")
    def knowledge_graph(
        query: str = Query(default="", max_length=250),
        provenance: Literal["observed", "inferred"] | None = None,
        limit: int = Query(default=30, ge=1, le=100),
    ):
        require_mission_control(graph=True)
        from thread_sdlc.context import ContextIndex

        return ContextIndex(repo_root).graph(query=query, provenance=provenance, limit=limit)

    @app.get("/api/mission-control/observations")
    def observations(limit: int = Query(default=30, ge=1, le=100)):
        require_mission_control()
        return {"observations": list_observations(repo_root, db, limit)}

    @app.post("/api/mission-control/observations/{identifier}/promote")
    def promote(identifier: int, intent: PromoteObservation):
        require_mission_control()
        if not intent.confirm:
            raise HTTPException(status_code=422, detail="Confirm promotion after reviewing the observation")
        try:
            return promote_observation(repo_root, db, identifier)
        except OSError:
            raise HTTPException(status_code=409, detail="Could not safely write the decision record") from None

    @app.get("/api/mission-control/config/{name}")
    def studio_config(name: ConfigName):
        require_mission_control()
        try:
            return read_config(repo_root, name)
        except OSError:
            raise HTTPException(status_code=409, detail="Could not safely read the configuration file") from None

    @app.post("/api/mission-control/config/{name}")
    def edit_studio_config(name: ConfigName, edit: ConfigEdit):
        require_mission_control()
        try:
            return save_config(repo_root, db, name, edit.yaml, edit.expected_revision)
        except OSError:
            raise HTTPException(status_code=409, detail="Could not safely write the configuration file") from None

    static = Path(__file__).parent / "static"
    app.mount("/assets", StaticFiles(directory=static / "assets", check_dir=False), name="assets")

    @app.get("/")
    @app.get("/tasks/{identifier}")
    @app.get("/tasks/{identifier}/reviews/{review_id}")
    def index():
        return FileResponse(static / "index.html")

    @app.get("/mission-control")
    @app.get("/mission-control/{view}")
    def mission_control_page(view: Literal["knowledge", "memory", "policy"] = "knowledge"):
        require_mission_control()
        return FileResponse(static / "index.html")

    return app
