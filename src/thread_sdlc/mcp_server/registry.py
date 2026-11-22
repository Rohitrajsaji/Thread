"""Milestone-one tool declarations shared by the compiler and MCP transport."""
from thread_sdlc.orchestrator.engine import Workflow

TOOL_REGISTRY = {
    "thread_start_or_resume": Workflow.start_or_resume,
    "thread_plan_tickets": Workflow.plan_tickets,
    "thread_save_checkpoint": Workflow.save_checkpoint,
    "thread_check_review": Workflow.check_review,
    "thread_dispatch_worker": Workflow.dispatch_worker,
    "thread_verify": Workflow.verify,
    "thread_complete": Workflow.complete,
    "thread_status": Workflow.status,
}
