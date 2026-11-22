"""Verify compiled agent permissions against the actual MCP tool listing."""

import asyncio
from pathlib import Path
import re
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from typer.testing import CliRunner
import yaml

from thread_sdlc.cli.main import app
from thread_sdlc.mcp_server.registry import TOOL_REGISTRY


M1_TOOLS = {
    "thread_start_or_resume",
    "thread_plan_tickets",
    "thread_save_checkpoint",
    "thread_check_review",
    "thread_dispatch_worker",
    "thread_verify",
    "thread_complete",
    "thread_status",
}


def test_agent_and_stdio_register_exactly_the_m1_tools(tmp_path: Path) -> None:
    initialized = CliRunner().invoke(app, ["init", "--repo", str(tmp_path)])
    assert initialized.exit_code == 0, initialized.output
    generated = (tmp_path / ".github/agents/thread.agent.md").read_text()
    _, frontmatter, body = generated.split("---", 2)
    declared = yaml.safe_load(frontmatter)["tools"]
    assert set(declared) == {f"thread/{name}" for name in M1_TOOLS}
    assert len(declared) == len(M1_TOOLS)
    assert set(re.findall(r"\bthread_[a-z_]+\b", body)) == M1_TOOLS

    sources = Path(__file__).resolve().parents[2] / "src"
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c", "from thread_sdlc.cli.main import app; app()",
            "mcp", "--repo", str(tmp_path),
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(sources), "PYTHONDONTWRITEBYTECODE": "1"},
    )

    async def list_tools() -> list[str]:
        async with asyncio.timeout(20), stdio_client(server) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                return [tool.name for tool in (await session.list_tools()).tools]

    exposed = asyncio.run(list_tools())
    assert len(exposed) == len(M1_TOOLS)
    assert set(exposed) == set(TOOL_REGISTRY) == M1_TOOLS
