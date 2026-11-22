"""Human-controlled Mission Control operations."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4

import yaml
from pydantic import BaseModel, ValidationError

from thread_sdlc.config.loader import load_thread_config
from thread_sdlc.config.models import PolicyConfig, ScopeConfig, ThreadConfig
from thread_sdlc.governance.redactor import redact_json, redact_text
from thread_sdlc.state import EventLogger, StateDatabase, StateRepository


ConfigName = Literal["config", "policy", "scope"]
_CONFIG_MODELS = {"config": ThreadConfig, "policy": PolicyConfig, "scope": ScopeConfig}
MAX_CONFIG_BYTES = 64 * 1024
_OBSERVATIONS = "type NOT GLOB 'mission_control.*'"


class _StudioYaml(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep=deep)
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, int, float, bool, type(None))) or key in keys:
                raise yaml.YAMLError("Invalid or duplicate mapping key")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def mission_control_status(repo_root: Path) -> dict[str, bool]:
    repo_root = repo_root.resolve()
    path = repo_root / ".thread" / "config.yaml"
    if path.resolve() != path:
        raise ValueError("Configuration must be inside the repository")
    if not path.exists():
        return {"enabled": False, "graph_enabled": False}
    features = load_thread_config(repo_root).features
    return {"enabled": features.m3d, "graph_enabled": features.m3d and features.m3c}


@contextmanager
def _directory(parent: Path | str, *, parent_fd: int | None = None) -> Iterator[int]:
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def _read_file(directory: int, name: str, limit: int, *, missing: bool = False) -> tuple[bytes, int]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if missing:
            return b"", 0
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Studio files must be regular files")
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Studio file exceeds the size limit")
        return value, stat.S_IMODE(info.st_mode)


def _write_file(directory: int, name: str, value: bytes, mode: int, *, replace: bool) -> None:
    temporary = f".thread-write-{uuid4().hex}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _revision(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_config(name: ConfigName, value: bytes) -> BaseModel:
    if len(value) > MAX_CONFIG_BYTES:
        raise ValueError("YAML exceeds the size limit")
    try:
        raw = yaml.load(value.decode("utf-8"), Loader=_StudioYaml)
        if not isinstance(raw, dict):
            raise ValueError("YAML must contain a top-level mapping")
        model = _CONFIG_MODELS[name].model_validate(raw)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        raise ValueError("Enter valid UTF-8 YAML") from None
    except ValidationError:
        raise ValueError(f"YAML does not match the {name} schema") from None
    if isinstance(model, (ThreadConfig, PolicyConfig)):
        if subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{model.base_branch}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        ).returncode:
            raise ValueError("Enter a valid base branch name")
    return model


def _config_result(name: ConfigName, value: bytes) -> dict:
    try:
        effective = _validate_config(name, value).model_dump()
    except ValueError:
        effective = None
    return {
        "name": name, "yaml": value.decode("utf-8"), "revision": _revision(value), "effective": effective,
    }


def read_config(root: Path, name: ConfigName) -> dict:
    with _directory(root) as root_fd, _directory(".thread", parent_fd=root_fd) as directory:
        contents, _ = _read_file(directory, f"{name}.yaml", MAX_CONFIG_BYTES)
    return _config_result(name, contents)


def _governing_values(model: BaseModel) -> dict:
    values = model.model_dump()
    if isinstance(model, ThreadConfig):
        values.pop("project_name")
        values.pop("ui_port")
    return values


def save_config(root: Path, db: StateDatabase, name: ConfigName, value: str, expected_revision: str) -> dict:
    filename = f"{name}.yaml"
    replacement = value.encode("utf-8")
    new_model = _validate_config(name, replacement)
    staled = 0
    with _directory(root) as root_fd, _directory(".thread", parent_fd=root_fd) as directory:
        previous = b""
        mode = 0
        wrote = False
        try:
            with db.transaction() as conn:
                previous, mode = _read_file(directory, filename, MAX_CONFIG_BYTES)
                if _revision(previous) != expected_revision:
                    raise ValueError("Configuration changed since it was opened. Reload before saving.")
                if previous == replacement:
                    return {**_config_result(name, previous), "staled_checkpoints": 0}
                try:
                    old_model = _validate_config(name, previous)
                except ValueError:
                    # A human may repair invalid YAML. Treat the repair as a governing change.
                    old_model = None
                changed = old_model is None or _governing_values(old_model) != _governing_values(new_model)
                if changed:
                    if conn.execute("SELECT 1 FROM assignments WHERE status='running' LIMIT 1").fetchone() or conn.execute(
                        "SELECT 1 FROM threads WHERE status IN ('Verifying','Merging') LIMIT 1"
                    ).fetchone():
                        raise ValueError("Wait for running workers, verification, and merge to finish")
                    policy = new_model if isinstance(new_model, PolicyConfig) else _validate_config(
                        "policy", _read_file(directory, "policy.yaml", MAX_CONFIG_BYTES)[0],
                    )
                    assert isinstance(policy, PolicyConfig)
                    staled = _invalidate_approvals(db, policy)
                if _read_file(directory, filename, MAX_CONFIG_BYTES)[0] != previous:
                    raise ValueError("Configuration changed during the update. Reload before saving.")
                _write_file(directory, filename, replacement, mode, replace=True)
                wrote = True
        except Exception:
            if wrote and _read_file(directory, filename, MAX_CONFIG_BYTES)[0] == replacement:
                _write_file(directory, filename, previous, mode, replace=True)
            raise
    return {**_config_result(name, replacement), "staled_checkpoints": staled}


def _invalidate_approvals(db: StateDatabase, policy: PolicyConfig) -> int:
    staled = 0
    records = StateRepository(db)
    events = EventLogger(db)
    with db.transaction() as conn:
        for thread in records.list_threads():
            if thread.status == "Completed":
                continue
            count = conn.execute(
                """UPDATE checkpoints SET status='stale', waits_for_person=0
                   WHERE thread_id=? AND stage IN ('spec','plan','diff') AND status IN ('pending','approved')""",
                (thread.id,),
            ).rowcount
            staled += count
            if thread.status != "PausedQuota":
                gates = policy.tracks.for_track(thread.track).required_gates
                stage = "SpecDraft" if thread.track == 3 or "spec" in gates else (
                    "PlanDraft" if "plan" in gates else "Executing"
                )
                records.update_thread(thread.id, status=stage)
            events.emit(thread.id, "mission_control.configuration_changed", {"staled_checkpoints": count})
    return staled


def _observation(row) -> dict:
    return {
        "id": row["id"], "thread_id": redact_text(row["thread_id"] or "") or None,
        "type": redact_text(row["type"]), "payload_json": redact_json(row["payload_json"]),
        "created_at": redact_text(row["created_at"]),
    }


def _decision_name(identifier: int) -> str:
    return f"observation-{identifier}.md"


def list_observations(root: Path, db: StateDatabase, limit: int) -> list[dict]:
    with db.read_connection() as conn:
        rows = conn.execute(
            f"SELECT id, thread_id, type, payload_json, created_at FROM events WHERE {_OBSERVATIONS} ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    decisions = root / ".thread" / "decisions"
    if decisions.exists() and decisions.resolve() != decisions:
        raise ValueError("Decision records must be inside the repository")
    observations = []
    for row in rows:
        path = decisions / _decision_name(row["id"])
        observation = _observation(row)
        observation["promoted_path"] = (
            path.relative_to(root).as_posix() if path.is_file() and not path.is_symlink() else None
        )
        observations.append(observation)
    return observations


def promote_observation(root: Path, db: StateDatabase, identifier: int) -> dict:
    if not 0 < identifier < 2**63:
        raise KeyError("Observation not found")
    with db.transaction() as conn:
        row = conn.execute(
            f"SELECT id, thread_id, type, payload_json, created_at FROM events WHERE id=? AND {_OBSERVATIONS}",
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError("Observation not found")
        observation = _observation(row)
        payload = observation.pop("payload_json")
        try:
            observation["payload"] = json.loads(payload)
        except json.JSONDecodeError:
            observation["payload"] = payload
        rendered = json.dumps(observation, ensure_ascii=False, indent=2)
        content = f"# Observation {identifier}\n\nPromoted by a local reviewer.\n\n```json\n{rendered}\n```\n".encode("utf-8")
        name = _decision_name(identifier)
        reused = False
        with _directory(root) as root_fd, _directory(".thread", parent_fd=root_fd) as thread_fd:
            try:
                os.mkdir("decisions", mode=0o755, dir_fd=thread_fd)
            except FileExistsError:
                pass
            with _directory("decisions", parent_fd=thread_fd) as decisions_fd:
                try:
                    _write_file(decisions_fd, name, content, 0o644, replace=False)
                except FileExistsError:
                    prior, _ = _read_file(decisions_fd, name, len(content))
                    if prior != content:
                        raise ValueError("A different decision record already exists for this observation")
                    reused = True
        path = f".thread/decisions/{name}"
        if not reused:
            EventLogger(db).emit(row["thread_id"], "mission_control.observation_promoted", {
                "observation_id": identifier, "path": path,
            })
        return {"path": path, "reused": reused}
