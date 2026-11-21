"""Loaders for `.thread/` config files from working tree or trusted Git base refs."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from thread_sdlc.config.models import (
    PolicyConfig,
    RulesMap,
    ScopeConfig,
    ThreadBundle,
    ThreadConfig,
)

TModel = TypeVar("TModel", bound=BaseModel)


class ConfigLoadError(Exception):
    """Raised when a `.thread/` configuration file is missing, unreadable, or invalid."""


def _parse_yaml_model(raw_text: str, model_cls: type[TModel], source_label: str) -> TModel:
    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"Invalid YAML in {source_label}: {exc}") from exc

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigLoadError(
            f"Expected YAML mapping at root of {source_label}, got {type(loaded).__name__}"
        )
    try:
        return model_cls.model_validate(loaded)
    except ValidationError as exc:
        raise ConfigLoadError(f"Schema validation failed for {source_label}: {exc}") from exc


def _read_local_thread_file(repo_root: Path, rel_path: str) -> str:
    path = repo_root / rel_path
    if not path.is_file():
        raise ConfigLoadError(f"Missing configuration file: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"Unable to read {path}: {exc}") from exc


def load_thread_config(repo_root: Path) -> ThreadConfig:
    """Load `.thread/config.yaml` from ``repo_root``."""
    raw = _read_local_thread_file(repo_root, ".thread/config.yaml")
    return _parse_yaml_model(raw, ThreadConfig, ".thread/config.yaml")


def load_policy_config(repo_root: Path) -> PolicyConfig:
    """Load `.thread/policy.yaml` from ``repo_root``."""
    raw = _read_local_thread_file(repo_root, ".thread/policy.yaml")
    return _parse_yaml_model(raw, PolicyConfig, ".thread/policy.yaml")


def load_scope_config(repo_root: Path) -> ScopeConfig:
    """Load `.thread/scope.yaml` from ``repo_root``."""
    raw = _read_local_thread_file(repo_root, ".thread/scope.yaml")
    return _parse_yaml_model(raw, ScopeConfig, ".thread/scope.yaml")


def load_rules_map(repo_root: Path) -> RulesMap:
    """Load `.thread/rules-map.yaml` from ``repo_root``."""
    raw = _read_local_thread_file(repo_root, ".thread/rules-map.yaml")
    return _parse_yaml_model(raw, RulesMap, ".thread/rules-map.yaml")


def load_constitution(repo_root: Path) -> str:
    """Load `.thread/constitution.md` if present, otherwise return empty string."""
    path = repo_root / ".thread/constitution.md"
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"Unable to read {path}: {exc}") from exc


def load_all(repo_root: Path) -> ThreadBundle:
    """Load all `.thread/` configs into a validated ``ThreadBundle``."""
    return ThreadBundle(
        config=load_thread_config(repo_root),
        policy=load_policy_config(repo_root),
        scope=load_scope_config(repo_root),
        rules_map=load_rules_map(repo_root),
        constitution=load_constitution(repo_root),
    )


def load_from_git_ref(repo_root: Path, base_ref: str, rel_path: str) -> str:
    """Load a file verbatim from Git history using ``git show <base_ref>:<rel_path>``."""
    if not base_ref or not base_ref.strip():
        raise ConfigLoadError("base_ref must be a non-empty Git ref or SHA")
    normalized = rel_path.replace("\\", "/").lstrip("/")
    posix_path = PurePosixPath(normalized).as_posix()
    if posix_path.startswith("./"):
        posix_path = posix_path[2:]
    if not posix_path or posix_path == "." or posix_path.startswith("../"):
        raise ConfigLoadError(f"Invalid relative git path: {rel_path!r}")

    proc = subprocess.run(
        ["git", "show", f"{base_ref}:{posix_path}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0:
        raise ConfigLoadError(
            f"Failed to load '{posix_path}' from git ref '{base_ref}': {proc.stderr.strip()}"
        )
    return proc.stdout


def load_policy_from_git_ref(repo_root: Path, base_ref: str) -> PolicyConfig:
    """Load `.thread/policy.yaml` from a committed Git ref."""
    raw = load_from_git_ref(repo_root, base_ref, ".thread/policy.yaml")
    return _parse_yaml_model(raw, PolicyConfig, f"{base_ref}:.thread/policy.yaml")


def load_scope_from_git_ref(repo_root: Path, base_ref: str) -> ScopeConfig:
    """Load `.thread/scope.yaml` from a committed Git ref."""
    raw = load_from_git_ref(repo_root, base_ref, ".thread/scope.yaml")
    return _parse_yaml_model(raw, ScopeConfig, f"{base_ref}:.thread/scope.yaml")


def load_rules_map_from_git_ref(repo_root: Path, base_ref: str) -> RulesMap:
    """Load `.thread/rules-map.yaml` from a committed Git ref."""
    raw = load_from_git_ref(repo_root, base_ref, ".thread/rules-map.yaml")
    return _parse_yaml_model(raw, RulesMap, f"{base_ref}:.thread/rules-map.yaml")


def _rev_parse_commit(repo_root: Path, ref: str) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None


def resolve_base_commit(
    repo_root: Path,
    explicit_base_ref: str | None = None,
    configured_base_branch: str = "main",
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve the trusted base commit SHA for clean-checkout verification.

    Precedence:
    1. Explicit ``explicit_base_ref`` (e.g. ``--base-ref``).
    2. Trusted GitHub Actions PR metadata (``GITHUB_EVENT_PATH`` ``pull_request.base.sha``
       or ``GITHUB_BASE_REF`` -> ``origin/<GITHUB_BASE_REF>`` / ``<GITHUB_BASE_REF>``).
    3. ``origin/<configured_base_branch>`` then ``<configured_base_branch>``.
    """
    env_map = env if env is not None else os.environ

    if explicit_base_ref:
        sha = _rev_parse_commit(repo_root, explicit_base_ref)
        if sha is None:
            raise ConfigLoadError(f"Unable to resolve explicit base ref: {explicit_base_ref!r}")
        return sha

    event_path_str = env_map.get("GITHUB_EVENT_PATH")
    if event_path_str:
        event_path = Path(event_path_str)
        if event_path.is_file():
            try:
                event_data = json.loads(event_path.read_text(encoding="utf-8"))
                pr = event_data.get("pull_request") if isinstance(event_data, dict) else None
                base = pr.get("base") if isinstance(pr, dict) else None
                base_sha = base.get("sha") if isinstance(base, dict) else None
                if isinstance(base_sha, str) and base_sha.strip():
                    sha = _rev_parse_commit(repo_root, base_sha.strip())
                    if sha is not None:
                        return sha
            except (OSError, json.JSONDecodeError):
                pass

    gh_base_ref = env_map.get("GITHUB_BASE_REF")
    if gh_base_ref:
        for candidate in (f"origin/{gh_base_ref}", gh_base_ref):
            sha = _rev_parse_commit(repo_root, candidate)
            if sha is not None:
                return sha

    for candidate in (f"origin/{configured_base_branch}", configured_base_branch):
        sha = _rev_parse_commit(repo_root, candidate)
        if sha is not None:
            return sha

    raise ConfigLoadError(
        f"Unable to resolve base commit from ref/branch {configured_base_branch!r} in {repo_root}"
    )
