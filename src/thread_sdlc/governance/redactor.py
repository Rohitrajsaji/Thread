"""Pre-storage secret redaction for logs, worker streams, and SQLite events."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import TracebackType
from typing import Any

REDACTED = "[REDACTED]"

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9-]+ )?PRIVATE KEY-----"
)
_PEM_TRUNCATED_RE = re.compile(r"-----BEGIN (?:[A-Z0-9-]+ )?PRIVATE KEY-----[\s\S]*")
_PEM_START_LINE_RE = re.compile(r"-----BEGIN (?:[A-Z0-9-]+ )?PRIVATE KEY-----")
_PEM_END_LINE_RE = re.compile(r"-----END (?:[A-Z0-9-]+ )?PRIVATE KEY-----")

_GITHUB_CLASSIC_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_-]{8,}\b")
_GITHUB_PAT_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b")

_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")
_AWS_SECRET_KEY_RE = re.compile(
    r"""(?i)((?:\\?["'])?(?:aws_secret_access_key|secret_access_key|SecretAccessKey)(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)[A-Za-z0-9/+=]{32,}((?:\\?["'])?)"""
)

_GCP_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{16,}\b")
_GCP_SA_JSON_KEY_RE = re.compile(r'(?i)("private_key(?:_id)?"\s*:\s*")((?:[^"\\]|\\.)+)(")')
_GCP_SA_JSON_ESCAPED_KEY_RE = re.compile(
    r'(?i)(\\"private_key(?:_id)?\\"\s*:\s*\\")((?:(?!\\")[^\n])+)(\\")'
)

_AUTH_BEARER_HEADER_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*bearer\s+)([^\s\"'`,;}{\\]+)"
)
_STANDALONE_BEARER_RE = re.compile(
    r"\b(Bearer\s+)(?:eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9\-._~+/]{12,}=*)"
)

_URL_CREDENTIALS_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:)([^@/\s]+)(@)")

_ENV_SECRET_KV_RE = re.compile(
    r"""(?im)(^|[\s;|&"'{\[,:])((?:export\s+)?[A-Za-z_][A-Za-z0-9_]*(?:_SECRET|_TOKEN|_KEY|_PASSWORD|_PASSWD|_PWD|_CREDENTIAL|_CREDENTIALS)|(?:export\s+)?(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|BEARER_TOKEN))\s*=\s*(?:"((?:[^"\\\n]|\\.)*)"|'([^'\n]*)'|\\"((?:[^\\"\n]|\\\\\\"|\\[^"\n])*)\\"|([^\s"'`\\;\n]+))"""
)

_SENSITIVE_DICT_KEY_RE = re.compile(
    r"^(?:"
    r"(?i:.*(?:secret|password|passwd|authorization))"
    r"|(?i:(?:.*_)?(?:pwd|token|private_key_id|credentials?))"
    r"|(?i:(?:.*_)?(?:api|private|access|auth|signing|encryption)_?key(?:_id)?)"
    r"|.*[a-z](?:Token|Pwd)"
    r"|.*(?:Api|Private|Access|Secret|Auth|Signing|Encryption)Key(?:Id)?"
    r")$"
)


def _replace_env_kv(match: re.Match[str]) -> str:
    prefix = match.group(1)
    key = match.group(2)
    dq_val = match.group(3)
    sq_val = match.group(4)
    esc_dq_val = match.group(5)
    uq_val = match.group(6)
    raw_val = (
        dq_val
        if dq_val is not None
        else (
            sq_val
            if sq_val is not None
            else (esc_dq_val if esc_dq_val is not None else (uq_val or ""))
        )
    )
    if raw_val == "" or raw_val.startswith("[REDACTED"):
        return match.group(0)
    if dq_val is not None:
        return f'{prefix}{key}="{REDACTED}"'
    if sq_val is not None:
        return f"{prefix}{key}='{REDACTED}'"
    if esc_dq_val is not None:
        return f'{prefix}{key}=\\"{REDACTED}\\"'
    return f"{prefix}{key}={REDACTED}"


def redact_text(text: str) -> str:
    """Scrub secrets from arbitrary text before writing logs or storing in SQLite."""
    if not text:
        return text

    scrubbed = text
    scrubbed = _PEM_BLOCK_RE.sub(REDACTED, scrubbed)
    scrubbed = _PEM_TRUNCATED_RE.sub(REDACTED, scrubbed)
    scrubbed = _GCP_SA_JSON_KEY_RE.sub(rf"\1{REDACTED}\3", scrubbed)
    scrubbed = _GCP_SA_JSON_ESCAPED_KEY_RE.sub(rf"\1{REDACTED}\3", scrubbed)
    scrubbed = _GITHUB_CLASSIC_TOKEN_RE.sub(REDACTED, scrubbed)
    scrubbed = _GITHUB_PAT_RE.sub(REDACTED, scrubbed)
    scrubbed = _AWS_ACCESS_KEY_RE.sub(REDACTED, scrubbed)
    scrubbed = _AWS_SECRET_KEY_RE.sub(rf"\1{REDACTED}\2", scrubbed)
    scrubbed = _GCP_API_KEY_RE.sub(REDACTED, scrubbed)
    scrubbed = _AUTH_BEARER_HEADER_RE.sub(rf"\1{REDACTED}", scrubbed)
    scrubbed = _STANDALONE_BEARER_RE.sub(rf"\1{REDACTED}", scrubbed)
    scrubbed = _URL_CREDENTIALS_RE.sub(rf"\1{REDACTED}\3", scrubbed)
    scrubbed = _ENV_SECRET_KV_RE.sub(_replace_env_kv, scrubbed)
    return scrubbed


def redact_line(line: str) -> str:
    """Scrub a single line of text."""
    return redact_text(line)


def redact_payload(data: Any) -> Any:
    """Recursively scrub secrets from structured dict/list/tuple payloads."""
    if isinstance(data, str):
        stripped = data.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                parsed = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return redact_text(data)
            if isinstance(parsed, (dict, list)):
                scrubbed_obj = redact_payload(parsed)
                return redact_text(json.dumps(scrubbed_obj, ensure_ascii=False))
        return redact_text(data)
    if isinstance(data, list):
        return [redact_payload(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_payload(item) for item in data)
    if isinstance(data, dict):
        redacted: dict[Any, Any] = {}
        for key, value in data.items():
            key_str = str(key)
            if isinstance(value, str) and value and _SENSITIVE_DICT_KEY_RE.match(key_str):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_payload(value)
        return redacted
    return data


def redact_json(raw_json: str) -> str:
    """Scrub secrets from a JSON string, falling back to plain text scrubbing."""
    try:
        parsed = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        return redact_text(raw_json)
    scrubbed_obj = redact_payload(parsed)
    return redact_text(json.dumps(scrubbed_obj, ensure_ascii=False))


def contains_secret(text: str) -> bool:
    """Return True when ``redact_text(text)`` modifies ``text``."""
    return redact_text(text) != text


class StreamRedactor:
    """Stateful line-by-line secret scrubber handling multi-line PEM blocks."""

    def __init__(self, max_pem_lines: int = 200) -> None:
        self._in_pem_block = False
        self._pem_lines_seen = 0
        self._max_pem_lines = max_pem_lines

    def scrub_line(self, line: str) -> str:
        """Scrub a single streamed line while preserving trailing newline if present."""
        has_nl = line.endswith("\n")
        suffix = "\n" if has_nl else ""

        if self._in_pem_block:
            self._pem_lines_seen += 1
            if _PEM_END_LINE_RE.search(line) or self._pem_lines_seen >= self._max_pem_lines:
                self._in_pem_block = False
                self._pem_lines_seen = 0
            return f"{REDACTED}{suffix}"

        if _PEM_START_LINE_RE.search(line) and not _PEM_END_LINE_RE.search(line):
            self._in_pem_block = True
            self._pem_lines_seen = 1
            return f"{REDACTED}{suffix}"

        return redact_text(line)


class RedactedLogWriter:
    """Context manager that scrubs every line before writing to disk."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._redactor = StreamRedactor()
        self._handle: Any = None

    def __enter__(self) -> RedactedLogWriter:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")
        return self

    def write_line(self, line: str) -> str:
        """Scrub ``line``, append newline if needed, write and flush."""
        scrubbed = self._redactor.scrub_line(line)
        if not scrubbed.endswith("\n"):
            scrubbed = f"{scrubbed}\n"
        if self._handle is not None:
            self._handle.write(scrubbed)
            self._handle.flush()
        return scrubbed

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
