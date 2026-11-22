"""Keep the enabled MCP tools and generated Copilot agent permissions in sync."""

import asyncio
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from typer.testing import CliRunner

from thread_sdlc.cli.main import app
from thread_sdlc.config.loader import load_thread_config
from thread_sdlc.mcp_server.registry import TOOL_REGISTRY


M3_TOOLS = {
    "m3a": {"thread_dispatch_ready", "thread_integration_status"},
    "m3b": {"thread_goldfish_review"},
    "m3c": {
        "thread_rebuild_index", "thread_search_context", "thread_offload_context",
        "thread_fetch_context", "thread_knowledge_graph",
    },
    "m3d": {"thread_mission_control_status"},
}


@pytest.mark.parametrize("features", [
    ("m3a",), ("m3b",), ("m3c",), ("m3d",), tuple(M3_TOOLS),
])
def test_m3_enabled_tools_match_compiler_and_stdio(tmp_path: Path, features: tuple[str, ...]) -> None:
    cli = CliRunner()
    result = cli.invoke(app, ["init", "--repo", str(tmp_path)])
    assert result.exit_code == 0, result.output
    config = tmp_path / ".thread/config.yaml"
    data = yaml.safe_load(config.read_text())
    assert data["features"] == dict.fromkeys(M3_TOOLS, False)
    data["features"].update(dict.fromkeys(features, True))
    config.write_text(yaml.safe_dump(data), encoding="utf-8")

    result = cli.invoke(app, ["compile", "--repo", str(tmp_path)])
    assert result.exit_code == 0, result.output
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    expected = set(TOOL_REGISTRY).union(*(M3_TOOLS[name] for name in features))
    config_model = load_thread_config(tmp_path)
    assert set(TOOL_REGISTRY.for_config(config_model)) == expected

    generated = (tmp_path / ".github/agents/thread.agent.md").read_text()
    _, frontmatter, body = generated.split("---", 2)
    declared = yaml.safe_load(frontmatter)["tools"]
    assert len(declared) == len(expected)
    assert set(declared) == {f"thread/{name}" for name in expected}
    assert set(re.findall(r"\bthread_[a-z_]+\b", body)) == expected

    server = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from thread_sdlc.cli.main import app; app()", "mcp", "--repo", str(tmp_path)],
        cwd=tmp_path,
        env={
            "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )

    async def invoke(session: ClientSession, name: str, arguments: dict):
        result = (await session.call_tool(name, arguments)).model_dump(by_alias=True)
        assert not result["isError"], result
        if result.get("structuredContent") is not None:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    async def check_server():
        async with asyncio.timeout(20), stdio_client(server) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                exposed = [tool.name for tool in (await session.list_tools()).tools]
                if "m3c" in features:
                    text = "Inventory test completed."
                    stored = await invoke(session, "thread_offload_context", {"text": text})
                    restored = await invoke(session, "thread_fetch_context", {"reference": stored["reference"]})
                    assert restored["text"] == text
                if "m3d" in features:
                    studio = await invoke(session, "thread_mission_control_status", {})
                    assert studio == {"enabled": True, "graph_enabled": "m3c" in features}
                return exposed

    exposed = asyncio.run(check_server())
    assert len(exposed) == len(expected)
    assert set(exposed) == expected
