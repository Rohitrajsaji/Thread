"""Expose only the worker-facing workflow actions on a local stdio connection."""
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer
except ModuleNotFoundError as error:
    if error.name != "mcp.server.mcpserver":
        raise
    from mcp.server.fastmcp import FastMCP as MCPServer

from thread_sdlc.orchestrator.engine import Workflow

from .registry import TOOL_REGISTRY


def create_server(repo_root: Path) -> MCPServer:
    workflow = Workflow(repo_root)
    server = MCPServer("Thread")
    for name, method in TOOL_REGISTRY.items():
        server.add_tool(getattr(workflow, method.__name__), name=name)
    return server


def run(repo_root: Path) -> None:
    create_server(repo_root).run(transport="stdio")


if __name__ == "__main__":
    run(Path.cwd())
