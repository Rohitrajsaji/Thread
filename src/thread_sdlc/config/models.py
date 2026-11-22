"""Pydantic v2 configuration models for `.thread/` repository configuration."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CommandsConfig(BaseModel):
    """Repository verification, lint, and build commands."""

    test: str | None = None
    lint: str | None = None
    build: str | None = None


class ExpansionFeatures(BaseModel):
    """Independent opt-ins for Milestone 3 capabilities."""

    model_config = ConfigDict(extra="forbid")

    m3a: bool = False
    m3b: bool = False
    m3c: bool = False
    m3d: bool = False


class ThreadConfig(BaseModel):
    """`.thread/config.yaml` schema."""

    project_name: str
    base_branch: str = "main"
    adapter: Literal["auto", "sdk", "cli", "mock"] = "auto"
    ui_port: int = Field(default=4242, ge=0, le=65535)
    commands: CommandsConfig = Field(default_factory=CommandsConfig)
    enabled_milestones: list[str] = Field(default_factory=lambda: ["M0", "M1"])
    features: ExpansionFeatures = Field(default_factory=ExpansionFeatures)

    def is_m3_enabled(self) -> bool:
        """Return True when any M3 milestone flag is enabled."""
        return any(self.features.model_dump().values())


class TrackPolicy(BaseModel):
    """Gate and sizing policy for a single delivery track."""

    max_files: int | None = Field(default=None, ge=1)
    required_gates: list[Literal["spec", "plan", "diff"]] = Field(default_factory=list)


class TracksConfig(BaseModel):
    """Track 1 / 2 / 3 policy configuration."""

    track_1: TrackPolicy = Field(default_factory=lambda: TrackPolicy(max_files=3, required_gates=[]))
    track_2: TrackPolicy = Field(
        default_factory=lambda: TrackPolicy(required_gates=["plan", "diff"])
    )
    track_3: TrackPolicy = Field(
        default_factory=lambda: TrackPolicy(required_gates=["spec", "plan", "diff"])
    )

    def for_track(self, track: int) -> TrackPolicy:
        """Return the policy for track 1, 2, or 3."""
        mapping = {1: self.track_1, 2: self.track_2, 3: self.track_3}
        if track not in mapping:
            raise ValueError(f"Unsupported track number: {track!r}. Expected 1, 2, or 3.")
        return mapping[track]


class CapsConfig(BaseModel):
    """Hard execution limits for workers, turns, retries, and credits."""

    max_workers_per_thread: int = Field(default=1, ge=1)
    max_retries_per_ticket: int = Field(default=3, ge=0)
    max_turns_per_assignment: int = Field(default=30, ge=1)
    max_credits_per_thread: float = Field(default=500.0, gt=0)
    max_goldfish_reviews: int = Field(default=3, ge=0)


def default_protected_paths() -> list[str]:
    """Default repository paths requiring governance protection."""
    return [
        ".thread/policy.yaml",
        ".thread/scope.yaml",
        ".thread/rules-map.yaml",
        ".github/workflows/**",
        "tests/acceptance/**",
        "db/migrations/**",
        "contracts/openapi.yaml",
    ]


class PolicyConfig(BaseModel):
    """`.thread/policy.yaml` schema."""

    base_branch: str = "main"
    tracks: TracksConfig = Field(default_factory=TracksConfig)
    protected_paths: list[str] = Field(default_factory=default_protected_paths)
    caps: CapsConfig = Field(default_factory=CapsConfig)


class RoleScope(BaseModel):
    """Filesystem and shell permission boundaries for a worker role."""

    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    allowed_shell_prefixes: list[str] = Field(default_factory=list)
    readonly: bool = False

    @model_validator(mode="after")
    def _validate_readonly(self) -> RoleScope:
        if self.readonly and self.allowed_paths:
            raise ValueError("Read-only roles must not declare allowed_paths.")
        return self


def default_deny_gate_files() -> list[str]:
    """Default gate/governance files denied to implementation workers."""
    return [
        ".thread/policy.yaml",
        ".thread/scope.yaml",
        ".thread/rules-map.yaml",
        ".github/workflows/**",
        "tests/acceptance/**",
    ]


def default_roles() -> dict[str, RoleScope]:
    """Default role scopes for backend, frontend, verifier, and reviewer_readonly."""
    shared_denied = [
        ".thread/policy.yaml",
        ".thread/scope.yaml",
        ".thread/rules-map.yaml",
        ".github/workflows/**",
    ]
    return {
        "backend": RoleScope(
            allowed_paths=["app/**", "src/**", "db/**", "contracts/**", "tests/**"],
            denied_paths=list(shared_denied),
            allowed_shell_prefixes=["pytest", "python", "ruff", "git status", "git diff"],
            readonly=False,
        ),
        "frontend": RoleScope(
            allowed_paths=["frontend/**", "web/**", "src/**/ui/**", "tests/**"],
            denied_paths=list(shared_denied),
            allowed_shell_prefixes=["npm test", "npm run build", "npm run lint", "git status", "git diff"],
            readonly=False,
        ),
        "verifier": RoleScope(
            allowed_paths=["tests/**"],
            denied_paths=list(shared_denied),
            allowed_shell_prefixes=["pytest", "python -m pytest", "git status", "git diff"],
            readonly=False,
        ),
        "reviewer_readonly": RoleScope(
            allowed_paths=[],
            denied_paths=["**"],
            allowed_shell_prefixes=["git status", "git diff", "git log", "git show"],
            readonly=True,
        ),
    }


class ScopeConfig(BaseModel):
    """`.thread/scope.yaml` schema."""

    roles: dict[str, RoleScope] = Field(default_factory=default_roles)
    deny_gate_files: list[str] = Field(default_factory=default_deny_gate_files)

    @model_validator(mode="after")
    def _validate_required_roles(self) -> ScopeConfig:
        defaults = default_roles()
        if "reviewer_readonly" in self.roles:
            reviewer = self.roles["reviewer_readonly"]
            if not reviewer.readonly or reviewer.allowed_paths:
                raise ValueError(
                    "Role 'reviewer_readonly' must have readonly=True and empty allowed_paths."
                )
        for name, role_default in defaults.items():
            if name not in self.roles:
                self.roles[name] = role_default.model_copy(deep=True)
        return self


class RuleMapping(BaseModel):
    """Mapping between a business rule ID and deterministic verification checks."""

    rule_id: str
    description: str = ""
    test_nodeids: list[str] = Field(default_factory=list)
    command: str | None = None


class RulesMap(BaseModel):
    """`.thread/rules-map.yaml` schema."""

    rules: dict[str, RuleMapping] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _populate_rule_ids(cls, data: object) -> object:
        if isinstance(data, dict) and isinstance(data.get("rules"), dict):
            updated_rules: dict[str, object] = {}
            for key, value in data["rules"].items():
                if isinstance(value, dict) and "rule_id" not in value:
                    updated_value = dict(value)
                    updated_value["rule_id"] = str(key)
                    updated_rules[str(key)] = updated_value
                else:
                    updated_rules[str(key)] = value
            copied = dict(data)
            copied["rules"] = updated_rules
            return copied
        return data


class ThreadBundle(BaseModel):
    """Complete loaded `.thread/` configuration bundle."""

    config: ThreadConfig
    policy: PolicyConfig
    scope: ScopeConfig
    rules_map: RulesMap
    constitution: str = ""
