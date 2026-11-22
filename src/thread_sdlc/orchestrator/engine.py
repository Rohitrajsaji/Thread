"""Repository-local workflow shared by human review, CLI and Copilot tools."""
from __future__ import annotations

import hashlib
import json
import subprocess
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from thread_sdlc.config.loader import load_all
from thread_sdlc.governance.redactor import redact_text
from thread_sdlc.state.db import StateDatabase
from thread_sdlc.state.events import EventLogger
from thread_sdlc.state.models import AnnotationRecord, CheckpointRecord, ThreadRecord, TicketRecord, VerificationRunRecord
from thread_sdlc.state.repositories import StateRepository
from thread_sdlc.workers.adapter import MockWorkerAdapter
from thread_sdlc.workers.copilot_cli import CopilotCliSubprocessAdapter
from thread_sdlc.workers.copilot_sdk import CopilotSdkAdapter, probe_sdk
from thread_sdlc.workers.manager import WorkerManager
from thread_sdlc.workers.worktree import WorktreeManager

from .router import classify, protected


class InvalidTransitionError(ValueError):
    """The requested operation does not apply to the current revision or stage."""


class PlannedTicket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=1)
    role: str
    depends_on: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    verifies_rules: list[str] = Field(default_factory=list)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        raise InvalidTransitionError(redact_text(result.stderr.strip()) or "Git operation failed")
    return result.stdout.rstrip("\n")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidTransitionError(message)


class Workflow:
    def __init__(self, repo_root: Path):
        self.root = Path(repo_root).resolve()
        self.bundle = load_all(self.root)
        self.db = StateDatabase(repo_root=self.root)
        self.repo = StateRepository(self.db)
        self.events = EventLogger(self.db)
        self.worktrees = WorktreeManager(self.root)

    def _target(self) -> str:
        return _git(self.root, "rev-parse", "--verify", f"refs/heads/{self.bundle.policy.base_branch}^{{commit}}")

    def _thread(self, thread_id: str) -> ThreadRecord:
        t = self.repo.get_thread(thread_id)
        if t is None:
            raise KeyError(thread_id)
        return t

    def _ticket(self, ticket_id: str) -> TicketRecord:
        t = self.repo.get_ticket(ticket_id)
        if t is None:
            raise KeyError(ticket_id)
        return t

    def _checkpoint(self, checkpoint_id: str) -> CheckpointRecord:
        cp = self.repo.get_checkpoint(checkpoint_id)
        if cp is None:
            raise KeyError(checkpoint_id)
        return cp

    def _gates(self, track: int) -> list[str]:
        gates = self.bundle.policy.tracks.for_track(track).required_gates
        return list(dict.fromkeys((["spec", "plan"] if track == 3 else []) + gates))

    def _draft(self, track: int) -> str:
        gates = self._gates(track)
        return "SpecDraft" if "spec" in gates else "PlanDraft" if "plan" in gates else "Executing"

    def _stale(self, thread_id: str, stages: tuple[str, ...]) -> None:
        for stage in stages:
            with self.db.transaction() as conn:
                conn.execute("UPDATE checkpoints SET status='stale', waits_for_person=0 WHERE thread_id=? AND stage=? AND status IN ('pending','approved')", (thread_id, stage))

    def _refresh(self, thread_id: str) -> ThreadRecord:
        with self.db.transaction():
            t = self._thread(thread_id)
            if t.status in ("Completed", "Merging"):
                return t
            current = self._target()
            if t.base_sha != current:
                self._stale(t.id, ("spec", "plan", "diff"))
                self.repo.update_thread(t.id, base_sha=current, status=self._draft(t.track))
                self.events.emit(t.id, "base_changed", {"previous": t.base_sha, "current": current})
            return self._thread(t.id)

    def start_or_resume(self, request: str = "", artifacts: list[str] | None = None, thread_id: str | None = None) -> dict:
        if thread_id or not request.strip():
            return self.status(thread_id)
        track, reasons = classify(request, artifacts or [], self.bundle.policy)
        with self.db.transaction():
            t = ThreadRecord(id=f"t-{uuid4().hex}", title=redact_text(request.strip())[:120], goal=redact_text(request), base_sha=self._target(), track=track, risk_reasons=reasons)
            self.repo.create_thread(t)
            self.events.emit(t.id, "Classified", {"track": track, "artifacts": artifacts or []})
            self.repo.update_thread(t.id, status=self._draft(track))
        return self.status(t.id)

    def status(self, thread_id: str | None = None) -> dict:
        if thread_id is None:
            latest = self.repo.get_latest_thread()
            if latest is None:
                raise KeyError("No active thread")
            thread_id = latest.id
        t = self._refresh(thread_id)
        cps = self.repo.list_checkpoints(t.id)
        return {"thread": t.model_dump(), "tickets": [v.model_dump() for v in self.repo.list_tickets(t.id)],
                "checkpoints": [v.model_dump() for v in cps],
                "annotations": [v.model_dump() for cp in cps for v in self.repo.list_annotations(cp.id)],
                "events": [v.model_dump() for v in self.events.list_events(t.id)],
                "verification_runs": [v.model_dump() for v in self.repo.list_verification_runs(t.id)]}

    def _escalate(self, t: ThreadRecord, paths: list[str]) -> bool:
        cap = self.bundle.policy.tracks.for_track(t.track).max_files
        reasons = protected(paths, self.bundle.policy)
        if cap and len(set(paths)) > cap:
            reasons.append("File count exceeds track limit")
        if t.track == 3 or not reasons:
            return False
        self._stale(t.id, ("spec", "plan", "diff"))
        self.repo.update_thread(t.id, track=3, status="SpecDraft", risk_reasons=reasons)
        self.events.emit(t.id, "Escalated", {"track": 3, "reasons": reasons})
        return True

    def plan_tickets(self, thread_id: str, tickets: list[dict]) -> dict:
        proposed = [PlannedTicket.model_validate(x) for x in tickets]
        ids = {x.id for x in proposed}
        _require(bool(ids) and len(ids) == len(proposed), "Provide uniquely named tickets")
        with self.db.transaction():
            t = self._refresh(thread_id)
            existing = self.repo.list_tickets(t.id)
            _require(t.status == "PlanDraft" or (t.status == "Executing" and t.track == 1 and not existing), "A new ticket plan requires a draft stage")
            known = {x.id: x for x in existing}
            graph = {x.id: x.depends_on for x in existing}
            graph.update({x.id: x.depends_on for x in proposed})
            for item in proposed:
                old = self.repo.get_ticket(item.id)
                _require(old is None or old.thread_id == t.id, "Ticket ID already in use")
                _require(item.role in self.bundle.scope.roles and set(item.depends_on) <= graph.keys(), "Unknown role or dependency")
                if item.id in known:
                    _require(known[item.id].status == "pending", "Started ticket cannot be rewritten")
            try:
                list(TopologicalSorter(graph).static_order())
            except CycleError as exc:
                raise InvalidTransitionError("Ticket dependencies contain a cycle") from exc
            self.repo.upsert_tickets(t.id, [TicketRecord(thread_id=t.id, **x.model_dump()) for x in proposed])
            self._escalate(t, [p for x in self.repo.list_tickets(t.id) for p in x.paths])
        return self.status(t.id)

    def save_checkpoint(self, thread_id: str, stage: str, content_md: str, artifact_path: str | None = None) -> dict:
        stage = stage.lower()
        _require(stage in ("spec", "plan", "summary") and bool(content_md.strip()), "Supply a spec, plan or summary with content")
        with self.db.transaction():
            t = self._refresh(thread_id)
            content_md = redact_text(content_md)
            digest = _digest(content_md)
            cp = self.repo.get_latest_checkpoint(t.id, stage)
            if cp and cp.content_sha256 == digest and cp.git_head_sha == t.base_sha and cp.status in ("pending", "approved", "saved"):
                return cp.model_dump()
            if stage == "summary":
                _require(t.status in ("Executing", "WaitingDiffApproval", "Verifying"), "Summary requires execution")
                status, successor = "saved", t.status
            else:
                _require(t.status in (f"{stage.title()}Draft", f"Waiting{stage.title()}Approval") or
                         (cp is not None and cp.status == "approved" and t.status in ("PlanDraft", "Executing", "WaitingDiffApproval") and not self.repo.list_running_assignments(t.id)),
                         "Checkpoint not allowed in this stage")
                self._stale(t.id, ("spec", "plan", "diff") if stage == "spec" else ("plan", "diff"))
                if stage == "plan":
                    _require(bool(self.repo.list_tickets(t.id)), "Register tickets before reviewing the plan")
                status = "pending"
                successor = "PlanDraft" if stage == "spec" else "Executing"
                self.repo.update_thread(t.id, status=f"Waiting{stage.title()}Approval")
            cp = CheckpointRecord(id=f"cp-{uuid4().hex}", thread_id=t.id, stage=stage, content_md=content_md, content_sha256=digest, git_head_sha=t.base_sha, gate_type=stage, permitted_next_stage=successor, status=status, waits_for_person=status=="pending")
            self.repo.create_checkpoint(cp)
            self.events.emit(t.id, "checkpoint_saved", {"checkpoint": cp.id, "stage": stage, "artifact": artifact_path})
            return cp.model_dump()

    def check_review(self, thread_id: str, checkpoint_id: str | None = None) -> dict:
        self._refresh(thread_id)
        cp = self._checkpoint(checkpoint_id) if checkpoint_id else self.repo.get_latest_checkpoint(thread_id)
        _require(cp is not None and cp.thread_id == thread_id, "Review not found for thread")
        return {"checkpoint": cp.model_dump(), "annotations": [a.model_dump() for a in self.repo.list_annotations(cp.id)]}

    def annotate(self, checkpoint_id: str, comment: str, target_type: str = "section", file_path: str | None = None, line_or_section: str | None = None) -> dict:
        with self.db.transaction():
            cp = self._checkpoint(checkpoint_id)
            self._refresh(cp.thread_id)
            _require(self._checkpoint(cp.id).status == "pending" and bool(comment.strip()), "Comment requires a current open review")
            return self.repo.create_annotation(AnnotationRecord(id=f"note-{uuid4().hex}", checkpoint_id=cp.id, comment=redact_text(comment.strip()), target_type=target_type, file_path=file_path, line_or_section=line_or_section)).model_dump()

    def decide(self, checkpoint_id: str, decision: str, content_sha256: str, git_head_sha: str, reason: str = "") -> dict:
        cp = self._checkpoint(checkpoint_id)
        self._refresh(cp.thread_id)
        with self.db.transaction():
            cp = self._checkpoint(checkpoint_id)
            t = self._thread(cp.thread_id)
            _require(decision in ("approved", "changes_requested"), "Unknown decision")
            _require(cp.content_sha256 == content_sha256 == _digest(cp.content_md) and cp.git_head_sha == git_head_sha, "Reviewed revision differs")
            _require(t.base_sha == self._target(), "Target branch moved")
            if cp.status == decision:
                return cp.model_dump()
            _require(cp.status == "pending" and t.status == f"Waiting{cp.stage.title()}Approval", "Review is closed or superseded")
            if decision == "changes_requested":
                _require(bool(reason.strip()), "Supply a blocking reason")
                self.annotate(cp.id, reason, target_type="changes_requested")
                next_stage = "Executing" if cp.stage == "diff" else f"{cp.stage.title()}Draft"
            else:
                _require(cp.stage in ("spec","plan"), "Use the guarded merge operation to approve a diff")
                next_stage = cp.permitted_next_stage
            self.repo.update_thread(t.id, status=next_stage)
            self.repo.update_checkpoint_decision(cp.id,status=decision,decision=decision)
            self.events.emit(t.id, "review_decided", {"checkpoint":cp.id, "decision":decision})
            return self._checkpoint(cp.id).model_dump()

    def _check_documents(self, t: ThreadRecord) -> None:
        for stage in self._gates(t.track):
            if stage == "diff":
                continue
            cp = self.repo.get_latest_checkpoint(t.id, stage)
            _require(cp is not None and cp.status == "approved" and cp.git_head_sha == t.base_sha and cp.content_sha256 == _digest(cp.content_md), f"Current {stage} approval required")

    def _adapter(self, policy):
        kind = self.bundle.config.adapter
        if kind == "mock":
            return MockWorkerAdapter(policy)
        if kind == "sdk" or (kind == "auto" and probe_sdk().available):
            return CopilotSdkAdapter(policy)
        return CopilotCliSubprocessAdapter(policy)

    def _latest_proposal(self, thread_id: str) -> TicketRecord:
        completed = [x for x in self.repo.list_tickets(thread_id) if x.status == "done" and x.result_sha]
        for ticket in reversed(completed):
            if all(self._ancestor(x.result_sha, ticket.result_sha) for x in completed):
                return ticket
        raise InvalidTransitionError("A single proposal containing the completed tickets is required")

    def _ancestor(self, ancestor: str, head: str) -> bool:
        return subprocess.run(["git","merge-base","--is-ancestor",ancestor,head], cwd=self.root, capture_output=True).returncode == 0

    async def dispatch_worker(self, thread_id: str, ticket_id: str, instructions: str) -> dict:
        with self.db.transaction():
            t = self._refresh(thread_id)
            ticket = self._ticket(ticket_id)
            _require(ticket.thread_id == t.id and t.status == "Executing", "Dispatch requires an executing thread and its ticket")
            self._check_documents(t)
            _require(all(self._ticket(dep).status == "done" for dep in ticket.depends_on), "Ticket dependencies are incomplete")
            if ticket.status == "done":
                return {"status":"completed", "result_sha":ticket.result_sha,"worker_invoked":False}
            completed = [x for x in self.repo.list_tickets(t.id) if x.status == "done"]
            base = self._latest_proposal(t.id).result_sha if completed else t.base_sha
            self.worktrees.ensure_worktree(t.id, ticket.id, base)
        manager = WorkerManager(repo_root=self.root,db=self.db,policy=self.bundle.policy,scope=self.bundle.scope,adapter_factory=self._adapter)
        result = await manager.dispatch_ticket(thread_id,ticket_id,instructions)
        return result.model_dump(mode="json")

    def diff(self, ticket_id: str) -> dict:
        ticket = self._ticket(ticket_id)
        t = self._thread(ticket.thread_id)
        _require(bool(ticket.result_sha and ticket.worktree_branch), "Ticket has no proposal")
        head = _git(self.root, "rev-parse", "--verify", f"refs/heads/{ticket.worktree_branch}^{{commit}}")
        _require(ticket.result_sha == head, "Proposal changed after assignment")
        return {"ticket_id":ticket.id, "thread_id":t.id, "base_sha":t.base_sha,"head_sha":head,"target_branch":self.bundle.policy.base_branch,
                "diff":redact_text(_git(self.root,"diff","--no-ext-diff","--no-textconv",t.base_sha,head,"--"))}

    def verify(self, thread_id: str, ticket_id: str | None = None) -> dict:
        from thread_sdlc.governance.engine import verify_repository
        t = self._refresh(thread_id)
        _require(t.status in ("Executing", "Verifying", "WaitingDiffApproval"), "Execution approval required before verifying")
        self._check_documents(t)
        ticket = self._ticket(ticket_id) if ticket_id else self._latest_proposal(t.id)
        _require(ticket.thread_id == t.id, "Ticket belongs to another thread")
        proposal = self.diff(ticket.id)
        head = proposal["head_sha"]
        wt = self.worktrees.worktree_path_for(ticket.id)
        _require(_git(wt,"rev-parse","HEAD") == head and not _git(wt,"status","--porcelain"), "Verification requires a clean proposal")
        paths = _git(wt,"diff","--name-only","--no-renames","-z",t.base_sha,head,"--").split("\x00")
        with self.db.transaction():
            if self._escalate(t,[p for p in paths if p]):
                return {"passed": False,"status":"Escalated","thread":self._thread(t.id).model_dump()}
            self.repo.update_thread(t.id,status="Verifying")
        report = verify_repository(wt, base_sha=t.base_sha)
        with self.db.transaction():
            current = self._refresh(t.id)
            _require(current.status == "Verifying" and current.base_sha == t.base_sha and report.commit_sha == head == self.diff(ticket.id)["head_sha"], "Proposal or review stage changed during verification")
            run = VerificationRunRecord(id=f"run-{uuid4().hex}",thread_id=t.id,commit_sha=head,mode="local",passed=report.passed,scorecard=report.scorecard,rule_evidence=report.rule_evidence)
            self.repo.create_verification_run(run)
            self._stale(t.id, ("diff",))
            next_stage = "Executing"
            tickets = self.repo.list_tickets(t.id)
            if report.passed and all(x.status == "done" for x in tickets) and self._latest_proposal(t.id).result_sha == head:
                content = proposal["diff"]
                cp = CheckpointRecord(id=f"cp-{uuid4().hex}",thread_id=t.id,stage="diff",content_md=content,content_sha256=_digest(content),git_head_sha=head,gate_type="diff",permitted_next_stage="Completed",waits_for_person=True)
                self.repo.create_checkpoint(cp)
                next_stage = "WaitingDiffApproval"
            self.repo.update_thread(t.id,status=next_stage)
            self.events.emit(t.id, "verification_finished", {"run":run.id,"passed":run.passed,"head":head})
            return run.model_dump()

    def _merge_intent(self, thread_id: str) -> dict | None:
        with self.db.read_connection() as conn:
            row = conn.execute("SELECT payload_json FROM events WHERE thread_id=? AND type='merge_intent' ORDER BY id DESC LIMIT 1",(thread_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def merge(self, ticket_id: str, expected_head: str, expected_base: str) -> dict:
        ticket = self._ticket(ticket_id)
        with self.db.transaction():
            t = self._refresh(ticket.thread_id)
            intent = self._merge_intent(t.id)
            if t.status in ("Completed","Merging"):
                _require(intent is not None and (ticket_id,expected_head,expected_base)==(intent["ticket_id"],intent["head"],intent["base"]), "Different merge already recorded")
                if t.status == "Completed":
                    return {"status":"Completed","result_sha":expected_head}
            else:
                _require(t.status=="WaitingDiffApproval", "Final review required")
                self._check_documents(t)
                cp = self.repo.get_latest_checkpoint(t.id,"diff")
                run = self.repo.get_latest_verification_run(t.id,expected_head)
                _require(cp is not None and cp.status=="pending" and cp.git_head_sha == expected_head and run is not None and run.passed, "Current verification and diff review required")
                proposal = self.diff(ticket.id)
                _require(self._latest_proposal(t.id).result_sha == proposal["head_sha"] == expected_head and self._target() == t.base_sha == expected_base,"Review revision or target moved")
                _require(
                    cp.content_sha256 == _digest(cp.content_md) and cp.content_md == proposal["diff"],
                    "Reviewed diff content differs from the proposal",
                )
                _require(all(x.status=="done" for x in self.repo.list_tickets(t.id)) and self._ancestor(expected_base,expected_head),"All tickets must be ready on a fast-forward proposal")
                intent = {"ticket_id":ticket.id,"head":expected_head,"base":expected_base,"checkpoint":cp.id,"target":self.bundle.policy.base_branch}
                self.events.emit(t.id,"merge_intent",intent)
                self.repo.update_thread(t.id,status="Merging")

        # Git checks the lease while holding its ref lock. updateInstead also
        # protects dirty checked-out target files and synchronizes a clean tree.
        with self.db.transaction():
            target_ref = f"refs/heads/{intent['target']}"
            current = _git(self.root,"rev-parse","--verify",target_ref)
            if current == expected_base:
                try:
                    # A local push launches a separate receiver. Set its
                    # checked-out branch and hook behavior on that process.
                    _git(
                        self.root, "push", "--no-verify",
                        "--receive-pack=git -c receive.denyCurrentBranch=updateInstead -c core.hooksPath=/dev/null receive-pack",
                        f"--force-with-lease={target_ref}:{expected_base}",
                        str(self.root), f"{expected_head}:{target_ref}",
                    )
                except InvalidTransitionError:
                    if _git(self.root,"rev-parse","--verify",target_ref) != expected_head:
                        # Preserve intent to reconcile an interrupted submission.
                        raise
            _require(_git(self.root,"rev-parse","--verify",target_ref) == expected_head, "Merge target moved; refresh the review")
            cp = self._checkpoint(intent["checkpoint"])
            if cp.status != "approved":
                self.repo.update_checkpoint_decision(cp.id,status="approved",decision="approved")
                self.events.emit(t.id,"merged",intent)
            self.repo.update_thread(t.id,status="Completed")
            return {"status":"Completed","result_sha":expected_head,"target":intent["target"]}

    def complete(self, thread_id: str) -> dict:
        t = self._refresh(thread_id)
        _require(t.status == "Completed" and self._merge_intent(t.id) is not None, "Complete requires the human merge receipt")
        return self.status(t.id)
