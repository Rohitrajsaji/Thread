"""Map intake and changed paths to repository review policy."""
import re

from thread_sdlc.config.models import PolicyConfig
from thread_sdlc.workers.permissions import glob_match


def protected(paths: list[str], policy: PolicyConfig) -> list[str]:
    return [path for path in paths if any(glob_match(path, pat) for pat in policy.protected_paths)]


def classify(request: str, artifacts: list[str], policy: PolicyConfig) -> tuple[int, list[str]]:
    words = " ".join([request, *artifacts]).lower()
    matched = protected(artifacts, policy)
    if matched or re.search(r'\b(openapi|migration|migrations|regulated|full.stack|database schema)\b', words):
        return 3, matched or ["Contract, database, or full-stack scope"]
    if re.search(r'\b(typo|rename|one.line|spelling|surgical|quick fix|small fix)\b', words):
        return 1, ["Small, localized change"]
    return 2, ["Implementation plan required"]
