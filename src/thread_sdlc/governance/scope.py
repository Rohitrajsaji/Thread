"""Changed paths and independently protected verification inputs."""
from fnmatch import fnmatchcase
from pathlib import Path
import subprocess

from thread_sdlc.config.models import ScopeConfig

PROTECTED = (
    ".thread/*",
    ".github/workflows/*", ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS",
    "src/thread_sdlc/governance/*", "src/thread_sdlc/cli/*", "scripts/verify*",
    "tests/acceptance/*", "conftest.py", "*/conftest.py", "pytest.ini", ".pytest.ini",
    "pytest.toml", ".pytest.toml",
    "pyproject.toml", "setup.cfg", "tox.ini",
)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, timeout=60
    ).stdout.decode("utf-8", errors="surrogateescape")


def changed_paths(root: Path, base: str, head: str) -> list[str]:
    # Include both endpoints of a rename by expressing it as delete + create.
    return git(root, "diff", "--name-only", "--no-renames", "-z", base, head, "--").split("\0")[:-1]


def protected_files(changed: list[str], scope: ScopeConfig, mapped_tests: set[str]) -> list[str]:
    patterns = (*PROTECTED, *scope.deny_gate_files)
    return [path for path in changed if path in mapped_tests or any(
        fnmatchcase(path, pattern) for pattern in patterns
    )]
