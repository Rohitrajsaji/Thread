"""Render reviewable repository changes from the canonical Thread configuration."""
from __future__ import annotations

import difflib
import json
import os
import re
import tempfile
from pathlib import Path

import yaml

from thread_sdlc.compiler.ci import generate_ci
from thread_sdlc.config.detector import build_initial_configs, detect_stack
from thread_sdlc.config.models import ThreadConfig
from thread_sdlc.mcp_server.registry import TOOL_REGISTRY

START = "<!-- thread:managed:start -->"
END = "<!-- thread:managed:end -->"
JSON_WHITESPACE = re.compile(r"[ \t\r\n]*")


def managed(existing: str, body: str) -> str:
    newline = "\r\n" if "\r\n" in existing else "\n"
    block = newline.join([START, body.strip().replace("\n", newline), END])
    if START in existing or END in existing:
        if existing.count(START) != 1 or existing.count(END) != 1 or existing.index(END) < existing.index(START):
            raise ValueError("Ambiguous Thread markers. Resolve the marker pair before compiling.")
        return existing[:existing.index(START)] + block + existing[existing.index(END) + len(END):]
    return existing + (newline if existing and not existing.endswith("\n") else "") + block + newline


def _json_members(raw: str, start: int) -> tuple[dict[str, tuple[int, int]], int]:
    """Locate the member values and closing brace in an already validated object."""
    decode = json.JSONDecoder().raw_decode
    cursor = JSON_WHITESPACE.match(raw, start + 1).end()
    spans: dict[str, tuple[int, int]] = {}
    while raw[cursor] != "}":
        name, cursor = decode(raw, cursor)
        colon = JSON_WHITESPACE.match(raw, cursor).end()
        value_start = JSON_WHITESPACE.match(raw, colon + 1).end()
        _, value_end = decode(raw, value_start)
        if name in spans:
            raise ValueError(f"Ambiguous duplicate JSON member in MCP configuration: {name!r}")
        spans[name] = (value_start, value_end)
        cursor = JSON_WHITESPACE.match(raw, value_end).end()
        if raw[cursor] == ",":
            cursor = JSON_WHITESPACE.match(raw, cursor + 1).end()
    return spans, cursor


def _insert_json_member(
    raw: str, closing: int, name: str, value: dict, *, has_members: bool
) -> str:
    content_end = len(raw[:closing].rstrip(" \t\r\n"))
    closing_indent = raw[raw.rfind("\n", 0, closing) + 1:closing]
    prefix = "," if has_members else ""
    if "\n" in raw[:closing] and not closing_indent.strip():
        newline = "\r\n" if "\r\n" in raw else "\n"
        prefix += newline + closing_indent + "  "
    elif has_members:
        prefix += " "
    member = f"{json.dumps(name)}: {json.dumps(value)}"
    return raw[:content_end] + prefix + member + raw[content_end:]


def _mcp_config(raw: str) -> str:
    server = {"type": "stdio", "command": "thread", "args": ["mcp", "--repo", "${workspaceFolder}"]}
    if not raw:
        return json.dumps({"servers": {"thread": server}}, indent=2) + "\n"
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ValueError("Expected a JSON object in the VS Code MCP configuration.")
    roots, root_end = _json_members(raw, JSON_WHITESPACE.match(raw).end())
    if "servers" not in roots:
        return _insert_json_member(raw, root_end, "servers", {"thread": server}, has_members=bool(roots))
    servers = config["servers"]
    if not isinstance(servers, dict):
        raise ValueError("Expected a JSON object for the VS Code MCP servers.")
    members, closing = _json_members(raw, roots["servers"][0])
    if "thread" not in members:
        return _insert_json_member(raw, closing, "thread", server, has_members=bool(members))
    if servers["thread"] == server:
        return raw
    start, end = members["thread"]
    return raw[:start] + json.dumps(server) + raw[end:]


def configured_files(root: Path) -> dict[str, str]:
    bundle = build_initial_configs(detect_stack(root))
    files = {}
    for name, model in [("config", bundle.config), ("scope", bundle.scope), ("policy", bundle.policy), ("rules-map", bundle.rules_map)]:
        files[f".thread/{name}.yaml"] = yaml.safe_dump(model.model_dump(mode="json"), sort_keys=False)
    files[".thread/constitution.md"] = bundle.constitution
    return files


def changes(root: Path, *, initialize: bool = False) -> dict[Path, tuple[str, str]]:
    root = root.resolve()
    def read(name: str) -> str:
        path = root / name
        if path.resolve() != path:
            raise ValueError(f"Refusing symlinked configuration target: {name}")
        return path.read_bytes().decode() if path.exists() else ""

    rendered = {}
    if initialize:
        for name, value in configured_files(root).items():
            read(name)
            if not (root / name).exists():
                rendered[name] = value
    elif not (root / ".thread/config.yaml").is_file():
        raise ValueError("Initialize the repository with thread init first.")
    config_path = ".thread/config.yaml"
    config_yaml = rendered[config_path] if config_path in rendered else read(config_path)
    registry = TOOL_REGISTRY.for_config(ThreadConfig.model_validate(yaml.safe_load(config_yaml)))
    tools = "\n".join(f"- `{name}`" for name in registry)
    tool_ids = "\n".join(f"  - thread/{name}" for name in registry)
    template = (Path(__file__).parent / "templates/thread-agent.md").read_text()
    rendered[".github/agents/thread.agent.md"] = template.replace("{{TOOLS}}", tools).replace("{{TOOL_IDS}}", tool_ids)
    for name in ("AGENTS.md", ".github/copilot-instructions.md"):
        rendered[name] = managed(read(name), "Follow the repository rules in .thread/ and use the Thread agent for governed tasks.")
    name = ".vscode/mcp.json"
    rendered[name] = _mcp_config(read(name))
    for name, value in generate_ci().items():
        if name.endswith("CODEOWNERS") and any(
            (root / existing).exists() for existing in (name, "CODEOWNERS", "docs/CODEOWNERS")
        ):
            # Existing repository ownership takes precedence; never replace human rules.
            continue
        rendered[name] = value
    result = {}
    for name, value in rendered.items():
        old = read(name)
        if old != value:
            result[root / name] = (old, value)
    return result


def apply(root: Path, *, initialize: bool = False, preview: bool = False) -> str:
    pending = changes(root, initialize=initialize)
    diff = []
    for path, (before, after) in pending.items():
        name = str(path.relative_to(root.resolve()))
        diff.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=name, tofile=name))
        if preview:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as tmp:
            tmp.write(after.encode())
        try:
            os.chmod(tmp.name, path.stat().st_mode if path.exists() else 0o644)
            os.replace(tmp.name, path)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
    return "".join(diff)
