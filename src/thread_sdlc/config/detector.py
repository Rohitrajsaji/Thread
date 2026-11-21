"""Repository stack detection and initial `.thread/` configuration synthesis."""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

from thread_sdlc.config.models import (
    CommandsConfig,
    PolicyConfig,
    RoleScope,
    RulesMap,
    ScopeConfig,
    ThreadBundle,
    ThreadConfig,
    default_roles,
)


class DetectedStack(BaseModel):
    """Summary of languages, frameworks, commands, and directory conventions in a repo."""

    project_name: str
    base_branch: str = "main"
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    commands: CommandsConfig = Field(default_factory=CommandsConfig)
    detected_paths: dict[str, list[str]] = Field(default_factory=dict)


def _detect_git_base_branch(repo_root: Path) -> str:
    if not (repo_root / ".git").exists():
        return "main"

    sym = subprocess.run(
        ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if sym.returncode == 0 and sym.stdout.strip():
        ref = sym.stdout.strip()
        return ref.removeprefix("origin/")

    cur = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if cur.returncode == 0 and cur.stdout.strip():
        return cur.stdout.strip()
    return "main"


def _read_json_safe(path: Path) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _read_pyproject_safe(path: Path) -> dict[str, object]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def detect_stack(repo_root: Path) -> DetectedStack:
    """Inspect ``repo_root`` to infer languages, frameworks, commands, and paths."""
    root = repo_root.resolve()
    languages: list[str] = []
    frameworks: list[str] = []
    project_name = root.name or "thread-project"
    base_branch = _detect_git_base_branch(root)

    test_cmd: str | None = None
    lint_cmd: str | None = None
    build_cmd: str | None = None

    pyproject_path = root / "pyproject.toml"
    requirements_path = root / "requirements.txt"
    pytest_ini_path = root / "pytest.ini"

    has_python = (
        pyproject_path.exists()
        or requirements_path.exists()
        or pytest_ini_path.exists()
        or (root / "app").is_dir()
        or (root / "src").is_dir()
    )

    if pyproject_path.exists():
        py_data = _read_pyproject_safe(pyproject_path)
        project_tbl = py_data.get("project")
        if isinstance(project_tbl, dict):
            raw_name = project_tbl.get("name")
            if isinstance(raw_name, str) and raw_name.strip():
                project_name = raw_name.strip()
            deps_blob = " ".join(str(x) for x in (project_tbl.get("dependencies") or [])).lower()
            opt_tbl = project_tbl.get("optional-dependencies")
            if isinstance(opt_tbl, dict):
                for vals in opt_tbl.values():
                    if isinstance(vals, list):
                        deps_blob += " " + " ".join(str(x) for x in vals).lower()
            for fw in ("fastapi", "django", "flask", "pytest", "ruff"):
                if fw in deps_blob and fw not in frameworks:
                    frameworks.append(fw)
        tool_tbl = py_data.get("tool")
        if isinstance(tool_tbl, dict):
            if "ruff" in tool_tbl and "ruff" not in frameworks:
                frameworks.append("ruff")
            if "pytest" in tool_tbl and "pytest" not in frameworks:
                frameworks.append("pytest")
        if "build-system" in py_data:
            build_cmd = "python -m build"

    if requirements_path.exists():
        req_text = requirements_path.read_text(encoding="utf-8", errors="ignore").lower()
        for fw in ("fastapi", "django", "flask", "pytest", "ruff"):
            if fw in req_text and fw not in frameworks:
                frameworks.append(fw)

    if has_python:
        languages.append("python")
        test_cmd = "pytest -q"
        if "ruff" in frameworks or (root / "ruff.toml").exists() or (root / ".ruff.toml").exists():
            lint_cmd = "ruff check ."

    # Node / TypeScript inspection
    pkg_candidates = [
        (root / "package.json", ""),
        (root / "frontend" / "package.json", "frontend"),
        (root / "web" / "package.json", "web"),
    ]
    for pkg_path, prefix in pkg_candidates:
        if not pkg_path.exists():
            continue
        pkg = _read_json_safe(pkg_path)
        if not prefix and isinstance(pkg.get("name"), str) and pkg["name"].strip():
            if not pyproject_path.exists():
                project_name = pkg["name"].strip()

        lang = "typescript" if (pkg_path.parent / "tsconfig.json").exists() else "javascript"
        if lang not in languages:
            languages.append(lang)

        deps_combined = {}
        for dep_key in ("dependencies", "devDependencies"):
            dep_val = pkg.get(dep_key)
            if isinstance(dep_val, dict):
                deps_combined.update(dep_val)
        for fw in ("react", "vite", "next", "express"):
            if fw in deps_combined and fw not in frameworks:
                frameworks.append(fw)

        scripts = pkg.get("scripts")
        if isinstance(scripts, dict):
            npm_prefix = f"npm --prefix {prefix}" if prefix else "npm"
            if isinstance(scripts.get("test"), str):
                node_test = f"{npm_prefix} test"
                if test_cmd is None:
                    test_cmd = node_test
                elif prefix:
                    test_cmd = f"{test_cmd} && {node_test}"
            if isinstance(scripts.get("lint"), str) and lint_cmd is None:
                lint_cmd = f"{npm_prefix} run lint"
            if isinstance(scripts.get("build"), str):
                node_build = f"{npm_prefix} run build"
                build_cmd = node_build if not prefix or build_cmd is None else build_cmd

    # Other ecosystems
    if (root / "go.mod").exists():
        if "go" not in languages:
            languages.append("go")
        test_cmd = test_cmd or "go test ./..."
        build_cmd = build_cmd or "go build ./..."

    if (root / "Cargo.toml").exists():
        if "rust" not in languages:
            languages.append("rust")
        test_cmd = test_cmd or "cargo test"
        build_cmd = build_cmd or "cargo build"

    if (root / "pom.xml").exists():
        if "java" not in languages:
            languages.append("java")
        test_cmd = test_cmd or "mvn test"

    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        if "java" not in languages:
            languages.append("java")
        test_cmd = test_cmd or "./gradlew test"

    # Path discovery
    backend_paths = [f"{d}/**" for d in ("app", "src", "backend") if (root / d).is_dir()]
    frontend_paths = [f"{d}/**" for d in ("frontend", "web") if (root / d).is_dir()]
    if (root / "src").is_dir():
        frontend_paths.append("src/**/ui/**")
    tests_paths = ["tests/**"] if (root / "tests").is_dir() else []
    migrations_paths = ["db/migrations/**"] if (root / "db" / "migrations").is_dir() else []
    contracts_paths = ["contracts/openapi.yaml"] if (root / "contracts" / "openapi.yaml").exists() else []

    detected_paths = {
        "backend": backend_paths or ["app/**", "src/**"],
        "frontend": frontend_paths or ["frontend/**", "web/**"],
        "tests": tests_paths or ["tests/**"],
        "migrations": migrations_paths or ["db/migrations/**"],
        "contracts": contracts_paths or ["contracts/openapi.yaml"],
    }

    return DetectedStack(
        project_name=project_name,
        base_branch=base_branch,
        languages=languages,
        frameworks=frameworks,
        commands=CommandsConfig(test=test_cmd, lint=lint_cmd, build=build_cmd),
        detected_paths=detected_paths,
    )


def build_initial_configs(detected: DetectedStack) -> ThreadBundle:
    """Build initial `.thread/` configuration bundle from a detected stack."""
    config = ThreadConfig(
        project_name=detected.project_name,
        base_branch=detected.base_branch,
        commands=detected.commands,
    )
    policy = PolicyConfig(base_branch=detected.base_branch)

    roles = default_roles()
    backend_paths = list(
        dict.fromkeys(
            detected.detected_paths.get("backend", [])
            + detected.detected_paths.get("migrations", [])
            + detected.detected_paths.get("contracts", [])
            + detected.detected_paths.get("tests", [])
        )
    )
    frontend_paths = list(
        dict.fromkeys(
            detected.detected_paths.get("frontend", [])
            + detected.detected_paths.get("tests", [])
        )
    )
    roles["backend"] = RoleScope(
        allowed_paths=backend_paths,
        denied_paths=roles["backend"].denied_paths,
        allowed_shell_prefixes=roles["backend"].allowed_shell_prefixes,
        readonly=False,
    )
    roles["frontend"] = RoleScope(
        allowed_paths=frontend_paths,
        denied_paths=roles["frontend"].denied_paths,
        allowed_shell_prefixes=roles["frontend"].allowed_shell_prefixes,
        readonly=False,
    )
    scope = ScopeConfig(roles=roles)
    rules_map = RulesMap()
    constitution = (
        f"# {detected.project_name} Engineering Constitution\n\n"
        "- Respect `.thread/policy.yaml` gates and `.thread/scope.yaml` role boundaries.\n"
        "- Never fabricate verification evidence; mark all observed results accurately.\n"
        "- Never commit secrets, tokens, or unredacted `.env` credentials.\n"
    )
    return ThreadBundle(
        config=config,
        policy=policy,
        scope=scope,
        rules_map=rules_map,
        constitution=constitution,
    )
