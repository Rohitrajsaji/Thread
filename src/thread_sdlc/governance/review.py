"""Confirm exact-head approval using GitHub's PR, ruleset and review records.

The generated workflow runs this module on a separate GitHub-hosted runner
before candidate project code executes. The verification job receives only
the approved base/head pair from the trusted job.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

from thread_sdlc.config.loader import load_policy_from_git_ref, load_rules_map_from_git_ref, load_scope_from_git_ref
from .scope import changed_paths, git, protected_files


def current_pr(root: Path, head: str) -> dict:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    if (pr["head"]["sha"] != head or pr["base"]["repo"]["full_name"] != os.environ["GITHUB_REPOSITORY"]
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", pr["base"]["sha"])):
        raise ValueError("PR event and checkout revisions disagree")
    policy = load_policy_from_git_ref(root, pr["base"]["sha"])
    if pr["base"]["ref"] != policy.base_branch:
        raise ValueError("PR does not target the branch configured by the base policy")
    return pr


def _owners(text: str, path: str) -> list[str]:
    owners = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].strip().split()
        if not fields:
            continue
        pattern = fields[0]
        # Accept auditable, anchored simple patterns and directory rules. Treat
        # unknown CODEOWNERS grammar as indeterminate, never as approval.
        if not re.fullmatch(r"[/\w.*/-]+", pattern):
            raise ValueError("Unsupported CODEOWNERS pattern")
        anchored = "/" in pattern.rstrip("/") or pattern.startswith("/")
        directory = pattern.endswith("/")
        pattern = pattern.strip("/")
        parts = pattern.split("/")
        if not anchored and len(parts) == 1:
            path_parts = path.split("/")
            matches = any(fnmatchcase(segment, pattern) for segment in (path_parts[:-1] if directory else path_parts))
        elif parts[-1] == "**" and "**" not in parts[:-1]:
            path_parts = path.split("/")
            matches = len(path_parts) >= len(parts) and all(
                fnmatchcase(item, glob) for item, glob in zip(path_parts, parts[:-1])
            )
        elif "**" in parts:
            raise ValueError("Unsupported recursive CODEOWNERS pattern")
        else:
            path_parts = path.split("/")
            matches = len(path_parts) >= len(parts) + directory and all(
                fnmatchcase(item, glob) for item, glob in zip(path_parts, parts)
            )
        if matches:
            owners = [field.lower() for field in fields[1:] if field.startswith("@")]
    return owners


def _api(*args: str):
    result = subprocess.run(["gh", "api", *args], check=True, capture_output=True, timeout=30)
    return json.loads(result.stdout)


def _check_current_revision(pr: dict) -> str | None:
    repo = pr["base"]["repo"]["full_name"]
    owner, name = repo.split("/")
    number = int(pr["number"])
    branch = quote(pr["base"]["ref"], safe="")
    rules = _api(f"repos/{repo}/rules/branches/{branch}")
    required = [r["parameters"] for r in rules if r.get("type") == "pull_request"]
    if not any(r.get("require_code_owner_review") and r.get("dismiss_stale_reviews_on_push") for r in required):
        raise ValueError("Base branch lacks required code-owner and stale-review rules")
    query = """query($owner:String!,$name:String!,$number:Int!){
      repository(owner:$owner,name:$name){pullRequest(number:$number){
      reviewDecision headRefOid baseRefOid state}}}"""
    current = _api("graphql", "-f", f"query={query}", "-f", f"owner={owner}", "-f", f"name={name}",
                   "-F", f"number={number}")["data"]["repository"]["pullRequest"]
    if (current["headRefOid"], current["baseRefOid"], current["state"]) != (
        pr["head"]["sha"], pr["base"]["sha"], "OPEN"
    ):
        raise ValueError("GitHub no longer reports this open PR revision")
    return current["reviewDecision"]


def confirmed_review(root: Path, pr: dict, protected: list[str], decision: str | None) -> bool:
    if decision != "APPROVED":
        return False
    repo = pr["base"]["repo"]["full_name"]
    owner = repo.split("/", 1)[0]
    number = int(pr["number"])
    pages = _api("--paginate", "--slurp", f"repos/{repo}/pulls/{number}/reviews?per_page=100")
    reviews: dict[str, dict] = {}
    for review in sorted((r for page in pages for r in page), key=lambda r: r["id"]):
        if review["state"] in {"APPROVED", "DISMISSED", "CHANGES_REQUESTED"}:
            reviews[review["user"]["login"].lower()] = review
    approved = set()
    for user, review in reviews.items():
        if (review["state"] != "APPROVED" or review["commit_id"] != pr["head"]["sha"]
                or user == pr["user"]["login"].lower()):
            continue
        try:
            permissions = _api(f"repos/{repo}/collaborators/{quote(user, safe='')}/permission")
        except subprocess.CalledProcessError:
            continue
        if permissions.get("permission") in {"write", "admin"}:
            approved.add(user)
    base = pr["base"]["sha"]
    contents = ""
    for candidate in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        if git(root, "ls-tree", "--name-only", base, "--", candidate).strip():
            contents = git(root, "show", f"{base}:{candidate}")
            break
    team_approvals = {}
    for path in protected:
        owners = _owners(contents, path)
        if any(f"@{user}" in owners for user in approved):
            continue
        matched = False
        for team in (o[1:] for o in owners if "/" in o):
            org, slug = team.split("/", 1)
            if org != owner.lower() or not re.fullmatch(r"[a-z0-9-]+", slug):
                continue
            if team in team_approvals:
                matched |= team_approvals[team]
                continue
            team_approvals[team] = False
            try:
                team_repository = _api(
                    f"orgs/{org}/teams/{slug}/repos/{repo}",
                    "-H", "Accept: application/vnd.github.v3.repository+json",
                )
            except subprocess.CalledProcessError:
                continue
            if not team_repository.get("permissions", {}).get("push"):
                continue
            for user in approved:
                try:
                    membership = _api(f"orgs/{org}/teams/{slug}/memberships/{quote(user, safe='')}")
                except subprocess.CalledProcessError:
                    continue
                if membership.get("state") == "active":
                    team_approvals[team] = matched = True
                    break
        if not matched:
            return False
    return True


def main() -> None:
    root = Path.cwd()
    head = git(root, "rev-parse", "HEAD").strip()
    pr = current_pr(root, head)
    base = pr["base"]["sha"]
    decision = _check_current_revision(pr)
    rules = load_rules_map_from_git_ref(root, base)
    protected = protected_files(changed_paths(root, base, head), load_scope_from_git_ref(root, base),
                                {n.split("::")[0] for r in rules.rules.values() for n in r.test_nodeids})
    revision = f"{base}:{head}"
    approved = protected and confirmed_review(root, pr, protected, decision)
    print(f"revision={revision}")
    print(f"reviewed={revision if approved else ''}")


if __name__ == "__main__":
    main()
