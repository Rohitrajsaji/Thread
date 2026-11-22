"""Deterministic repository verification against an immutable committed checkout."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Any
from xml.etree.ElementTree import ParseError

from pydantic import BaseModel, Field
import yaml

from thread_sdlc.config.loader import (ConfigLoadError, load_from_git_ref, load_policy_from_git_ref,
                                      load_scope_from_git_ref, load_rules_map_from_git_ref, resolve_base_commit)
from thread_sdlc.config.models import ThreadConfig
from .contracts import compare_openapi
from .redactor import contains_secret
from .review import current_pr
from .rules_evidence import observe_rules, run_configured
from .scope import changed_paths, git, protected_files


class VerificationReport(BaseModel):
    commit_sha: str = ""
    passed: bool = False
    scorecard: dict[str, Any] = Field(default_factory=dict)
    rule_evidence: list[dict[str, Any]] = Field(default_factory=list)


def _check(report: VerificationReport, key: str, errors: list[str]) -> None:
    report.scorecard[key] = {"passed": not errors, "issues": errors}


def _blob(root: Path, commit: str, path: str) -> str | None:
    if not git(root, "ls-tree", "-z", commit, "--", path):
        return None
    return git(root, "show", f"{commit}:{path}")


def verify_repository(repo_root: Path, *, ci: bool = False, base_sha: str | None = None) -> VerificationReport:
    """Check committed HEAD using trusted base rules. Local results are advisory."""
    root = repo_root.resolve()
    result = VerificationReport()
    try:
        head = result.commit_sha = git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
        hosted = ci and os.environ.get("GITHUB_ACTIONS") == "true"
        if hosted:
            pr = current_pr(root, head)
            base = pr["base"]["sha"]
            revision = f"{base}:{head}"
            if os.environ.get("THREAD_TRUSTED_REVISION") != revision:
                raise ValueError("Trusted review job did not confirm this PR revision")
            if base_sha and resolve_base_commit(root, base_sha) != base:
                raise ValueError("Explicit base differs from the PR event")
        else:
            base = resolve_base_commit(root, base_sha)
        if git(root, "diff", "--name-only", "HEAD", "--").strip():
            raise ValueError("Commit tracked changes before verifying this revision")
        if git(root, "ls-tree", "-z", head, "--", ".thread-state"):
            raise ValueError("The candidate has committed local Thread state")
        # Validate every trusted configuration before running any candidate code.
        load_policy_from_git_ref(root, base)
        scope = load_scope_from_git_ref(root, base)
        rules = load_rules_map_from_git_ref(root, base)
        config = ThreadConfig.model_validate(yaml.safe_load(load_from_git_ref(root, base, ".thread/config.yaml")))
        changed = changed_paths(root, base, head)
        mapped = {node.split("::")[0] for r in rules.rules.values() for node in r.test_nodeids}
        protected = protected_files(changed, scope, mapped)
        approved = hosted and os.environ.get("THREAD_TRUSTED_REVIEW") == f"{base}:{head}"
        _check(result, "protected_files", [] if approved or not ci else protected)
        errors: list[str] = []
        for path in changed:
            if path.endswith((".md", ".rst", ".txt")):
                text = _blob(root, head, path) or ""
                if any(marker in text for marker in ("<INVENTED>", "NEEDS_INPUT", "UNAPPROVED_ASSUMPTION")):
                    errors.append(path)
        _check(result, "provenance", errors)
        errors = []
        for path in changed:
            patch = git(root, "diff", "--no-ext-diff", "--no-textconv", "--unified=0", base, head, "--", path)
            if any(contains_secret(line[1:]) for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++ ")):
                errors.append(path)
        _check(result, "secrets", errors)
        errors = []
        for path in changed:
            if Path(path).name.lower() in {"openapi.yaml", "openapi.yml", "openapi.json"}:
                errors.extend(compare_openapi(_blob(root, base, path), _blob(root, head, path)))
        _check(result, "openapi", errors)
        if any(not entry["passed"] for entry in result.scorecard.values()):
            return result
        with TemporaryDirectory(prefix="thread-verify-") as tmp:
            checkout = Path(tmp) / "checkout"
            home = Path(tmp) / "home"
            home.mkdir()
            git(root, "clone", "--quiet", "--no-local", "--no-checkout", "--", str(root), str(checkout))
            git(checkout, "checkout", "--quiet", "--detach", head)
            for name, cmd in config.commands.model_dump().items():
                if cmd:
                    _check(result, name, [] if run_configured(cmd, checkout, home) else [f"Configured {name} command failed"])
            result.rule_evidence = observe_rules(checkout, rules, head, home)
            _check(result, "business_rules", [
                row["rule_id"] for row in result.rule_evidence if row["outcome"] != "passed"
            ])
        result.passed = all(check["passed"] for check in result.scorecard.values())
    except (ConfigLoadError, OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError,
            subprocess.SubprocessError, ParseError) as exc:
        # Candidate process output can contain secrets. Report only bounded error metadata.
        detail = type(exc).__name__ if isinstance(exc, subprocess.SubprocessError) else str(exc)
        from .redactor import redact_text
        _check(result, "verification_error", [redact_text(detail)[:500]])
    return result
