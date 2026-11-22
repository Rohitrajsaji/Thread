"""Default and repository-enabled tool declarations."""
from typing import Callable, Literal, NamedTuple

from thread_sdlc.config.models import ThreadConfig
from thread_sdlc.orchestrator.engine import Workflow


class ToolTarget(NamedTuple):
    service: Literal["workflow", "context", "studio"]
    method: str


class ToolRegistry(dict[str, Callable]):
    """Keep the M1 tool set as the default and resolve opt-ins per repository."""

    def for_config(self, config: ThreadConfig) -> dict[str, ToolTarget]:
        tools = {name: ToolTarget("workflow", method.__name__) for name, method in self.items()}
        for feature, entries in EXPANSION_TOOLS.items():
            if getattr(config.features, feature):
                tools.update(entries)
        return tools


TOOL_REGISTRY = ToolRegistry({
    "thread_start_or_resume": Workflow.start_or_resume,
    "thread_plan_tickets": Workflow.plan_tickets,
    "thread_save_checkpoint": Workflow.save_checkpoint,
    "thread_check_review": Workflow.check_review,
    "thread_dispatch_worker": Workflow.dispatch_worker,
    "thread_verify": Workflow.verify,
    "thread_complete": Workflow.complete,
    "thread_status": Workflow.status,
})

EXPANSION_TOOLS = {
    "m3a": {
        "thread_dispatch_ready": ToolTarget("workflow", "dispatch_ready"),
        "thread_integration_status": ToolTarget("workflow", "integration_status"),
    },
    "m3b": {
        "thread_goldfish_review": ToolTarget("workflow", "goldfish_review"),
    },
    "m3c": {
        "thread_rebuild_index": ToolTarget("context", "rebuild"),
        "thread_search_context": ToolTarget("context", "search"),
        "thread_offload_context": ToolTarget("context", "offload"),
        "thread_fetch_context": ToolTarget("context", "fetch"),
        "thread_knowledge_graph": ToolTarget("context", "graph"),
    },
    "m3d": {
        "thread_mission_control_status": ToolTarget("studio", "mission_control_status"),
    },
}
