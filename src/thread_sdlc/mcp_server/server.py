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
    tools = TOOL_REGISTRY.for_config(workflow.bundle.config)
    context = None
    for name, target in tools.items():
        if target.service == "workflow":
            tool = getattr(workflow, target.method)
        elif target.service == "context":
            if context is None:
                from thread_sdlc.context import ContextIndex

                context = ContextIndex(workflow.root)
            tool = getattr(context, target.method)
        else:
            tool = _studio_status(workflow.root)
        server.add_tool(tool, name=name)
    return server


def _studio_status(repo_root: Path):
    from thread_sdlc.ui.studio import mission_control_status

    def status() -> dict:
        """Report which local Mission Control views are enabled."""
        return mission_control_status(repo_root)

    return status


def run(repo_root: Path) -> None:
    create_server(repo_root).run(transport="stdio")


if __name__ == "__main__":
    run(Path.cwd())
