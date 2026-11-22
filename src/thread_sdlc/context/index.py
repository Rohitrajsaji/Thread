"""Repository-local source index, provenance graph, and output storage."""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
import subprocess
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import astuple
from pathlib import Path, PurePosixPath
from typing import Literal

from thread_sdlc.governance.redactor import redact_payload, redact_text

from .embedding import Embedder, FastEmbedAdapter
from .structure import CODE_SUFFIXES, DOCUMENT_SUFFIXES, Node, extract, import_keys, module_keys

Provenance = Literal["observed", "inferred"]
OutputKind = Literal["text", "test", "diff"]

MAX_FILES = 1200
MAX_FILE_BYTES = 128 * 1024
MAX_INDEX_BYTES = 24 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SEMANTIC_DOCUMENTS = 128
_TOKEN = re.compile(r"[^\W_]+")
_REFERENCE = re.compile(r"context:[0-9a-f]{64}")
_TEST_SUMMARY = re.compile(r"\b\d+ (?:passed|failed|errors?|warnings?|skipped|xfailed|xpassed)\b")
_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS documents
USING fts5(path, symbols, body, tokenize='unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, kind TEXT NOT NULL,
    path TEXT, line INTEGER
);
CREATE TABLE IF NOT EXISTS edges (
    source TEXT NOT NULL REFERENCES nodes(id), target TEXT NOT NULL REFERENCES nodes(id),
    relation TEXT NOT NULL, provenance TEXT NOT NULL CHECK (provenance IN ('observed', 'inferred')),
    path TEXT NOT NULL, line INTEGER NOT NULL,
    PRIMARY KEY(source, target, relation, provenance, path, line)
);
CREATE INDEX IF NOT EXISTS edges_target ON edges(target);
CREATE TABLE IF NOT EXISTS offloads (
    reference TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL,
    preview TEXT NOT NULL, chars INTEGER NOT NULL
);
"""


def _repository_files(root: Path) -> list[str]:
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--cached", "-z", "--"], cwd=root, check=True,
            capture_output=True, timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("The context index requires a readable Git working tree") from exc
    return sorted({os.fsdecode(path) for path in listing.split(b"\x00") if path})


def _indexable(path: str) -> bool:
    file = PurePosixPath(path)
    return (
        bool(file.parts) and not file.is_absolute() and not any(part.startswith(".") for part in file.parts)
        and file.suffix.lower() in CODE_SUFFIXES | DOCUMENT_SUFFIXES
        and not (set(file.parts) & {"node_modules", "vendor", "dist", "build", "__pycache__"})
        and not file.name.lower().endswith((".min.js", ".min.mjs"))
        and path.isprintable() and redact_text(path) == path
    )


def _read_source(root_fd: int, path: str) -> bytes | None:
    directory = os.dup(root_fd)
    descriptors = [directory]
    try:
        *parents, filename = PurePosixPath(path).parts
        for parent in parents:
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            descriptors.append(directory)
        source = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(source, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
                return None
            contents = handle.read(MAX_FILE_BYTES + 1)
            return contents if len(contents) <= MAX_FILE_BYTES and b"\x00" not in contents else None
    except OSError:
        return None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _preview(text: str, kind: OutputKind) -> str:
    lines = text.splitlines()
    if kind == "diff":
        files = [line for line in lines if line.startswith("diff --git ")]
        added = sum(line.startswith("+") and not line.startswith("+++") for line in lines)
        removed = sum(line.startswith("-") and not line.startswith("---") for line in lines)
        return "\n".join([f"{len(files)} files, +{added} / -{removed}", *files[:12]])[:1400]
    if kind == "test":
        selected = [line for line in lines if (
            line.lstrip().startswith(("FAILED", "ERROR", "FAIL:", "E "))
            or _TEST_SUMMARY.search(line)
        )]
        if selected:
            return "\n".join(selected[:10] + selected[-2:] if len(selected) > 12 else selected)[:1400]
    return text[:1400]


def _cosine(first: Sequence[float], second: Sequence[float]) -> float:
    if not first or len(first) != len(second):
        raise ValueError("Embedding dimensions differ")
    magnitude = math.hypot(*first) * math.hypot(*second)
    return sum(x * y for x, y in zip(first, second)) / magnitude if magnitude else 0.0


class ContextIndex:
    """Keep derived search and graph data separate from workflow state."""

    def __init__(self, repo_root: Path, *, embedder: Embedder | None = None) -> None:
        self.root = Path(repo_root).resolve(strict=True)
        self.db_path = self.root / ".thread-state" / "context.db"
        self._embedder = embedder

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        state = self.db_path.parent
        state.mkdir(mode=0o700, exist_ok=True)
        if state.is_symlink() or not state.is_dir():
            raise ValueError("The context state directory must be a real repository directory")
        for suffix in ("", "-wal", "-shm", "-journal"):
            file = state / (self.db_path.name + suffix)
            try:
                info = file.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("The context database and its sidecars must be regular files")
        descriptor = os.open(self.db_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(self.db_path, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(_SCHEMA)
            yield conn

    def rebuild(self) -> dict:
        """Replace the derived index with a bounded snapshot of tracked source and docs."""
        documents: list[tuple[str, str, str]] = []
        modules: dict[str, set[str]] = {}
        nodes: dict[str, Node] = {}
        edges: set[tuple[str, str, str, str, str, int]] = set()
        imports: set[tuple[str, str, str, int]] = set()
        size = 0
        skipped = 0
        truncated = False
        files = _repository_files(self.root)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for path in files:
                if not _indexable(path):
                    skipped += 1
                    continue
                if len(documents) == MAX_FILES:
                    truncated = True
                    break
                contents = _read_source(root_fd, path)
                if contents is None:
                    skipped += 1
                    continue
                try:
                    raw = contents.decode("utf-8")
                except UnicodeDecodeError:
                    skipped += 1
                    continue
                if size + len(contents) > MAX_INDEX_BYTES:
                    truncated = True
                    break
                size += len(contents)
                file = Node(f"file:{path}", PurePosixPath(path).name, "file", path)
                nodes[file.id] = file
                for key in module_keys(path):
                    modules.setdefault(key, set()).add(file.id)
                relationships = extract(path, raw)
                for relationship in relationships:
                    target = relationship.node
                    nodes[target.id] = target
                    edges.add((relationship.source, target.id, relationship.relation,
                               relationship.provenance, path, relationship.line))
                    if relationship.relation == "imports":
                        imports.add((path, target.id, target.label, relationship.line))
                symbols = " ".join(item.node.label for item in relationships)
                documents.append((path, symbols, redact_text(raw)))
        finally:
            os.close(root_fd)
        for path, source, label, line in imports:
            candidates = {node for key in import_keys(path, label) for node in modules.get(key, ())}
            if len(candidates) == 1:
                edges.add((source, next(iter(candidates)), "resolves_to", "inferred", path, line))

        with self._connect() as conn, conn:
            conn.execute("DELETE FROM edges")
            conn.execute("DELETE FROM nodes")
            conn.execute("DELETE FROM documents")
            conn.executemany("INSERT INTO documents VALUES (?, ?, ?)", documents)
            conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?)", map(astuple, nodes.values()))
            conn.executemany("INSERT INTO edges VALUES (?, ?, ?, ?, ?, ?)", sorted(edges))
        return {
            "files": len(documents), "nodes": len(nodes), "edges": len(edges),
            "skipped": skipped, "truncated": truncated, "source_bytes": size,
        }

    def search(self, query: str, limit: int = 20, semantic: bool = False) -> dict:
        """Find source files by ranked tokens, with opt-in local semantic ranking."""
        if not 1 <= limit <= 100:
            raise ValueError("Search limit must be between 1 and 100")
        query = redact_text(query[:2000])
        tokens = list(dict.fromkeys(_TOKEN.findall(query)))[:24]
        if not tokens:
            return {"mode": "lexical", "results": []}
        expression = " OR ".join(f'"{token}"' for token in tokens)
        with self._connect() as conn:
            results = conn.execute(
                """SELECT path, snippet(documents, 2, '', '', ' … ', 22) AS snippet,
                          -bm25(documents, 3.0, 5.0, 1.0) AS score
                   FROM documents WHERE documents MATCH ?
                   ORDER BY score DESC, path LIMIT ?""",
                (expression, limit),
            ).fetchall()
            lexical = [{**dict(row), "snippet": row["snippet"][:500]} for row in results]
            if semantic:
                if ranked := self._semantic(conn, query, [row["path"] for row in lexical], limit):
                    return {"mode": "semantic", "results": ranked}
        return {"mode": "lexical", "results": lexical, "semantic_fallback": semantic}

    def _semantic(
        self, conn: sqlite3.Connection, query: str, preferred: list[str], limit: int,
    ) -> list[dict]:
        adapter = self._embedder
        if adapter is None and (model_dir := os.environ.get("THREAD_CONTEXT_MODEL_DIR")):
            name = os.environ.get("THREAD_CONTEXT_MODEL_NAME", "BAAI/bge-small-en-v1.5")
            adapter = self._embedder = FastEmbedAdapter(Path(model_dir), name)
        if adapter is None:
            return []
        placeholders = ",".join("?" for _ in preferred) or "NULL"
        documents = conn.execute(
            f"""SELECT path, symbols, substr(body, 1, 2000) AS body FROM documents
                ORDER BY CASE WHEN path IN ({placeholders}) THEN 0 ELSE 1 END, path
                LIMIT ?""",
            (*preferred, MAX_SEMANTIC_DOCUMENTS),
        ).fetchall()
        if not documents:
            return []
        texts = [query, *(f"{row['path']}\n{row['symbols'][:1000]}\n{row['body']}" for row in documents)]
        try:
            query_vector, *vectors = adapter.embed(texts)
            if len(vectors) != len(documents):
                return []
            scored = [
                {"path": row["path"], "snippet": row["body"][:500], "score": _cosine(query_vector, vector)}
                for row, vector in zip(documents, vectors)
            ]
        except Exception:
            # Optional model loading and inference must not block lexical search.
            return []
        valid = (item for item in scored if math.isfinite(item["score"]))
        return sorted(valid, key=lambda item: (-item["score"], item["path"]))[:limit]

    def offload(self, text: str, kind: OutputKind = "text") -> dict:
        """Store redacted tool output and return a compact preview and reference."""
        if kind not in {"text", "test", "diff"}:
            raise ValueError("Output kind must be text, test, or diff")
        if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES or "\x00" in text:
            raise ValueError("Output must be UTF-8 text of at most one MiB")
        body = redact_payload(text)
        if len(body.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("Redacted output exceeds one MiB")
        digest = hashlib.sha256(f"{kind}\x00{body}".encode()).hexdigest()
        reference = f"context:{digest}"
        preview = _preview(body, kind)
        with self._connect() as conn, conn:
            conn.execute(
                "INSERT OR IGNORE INTO offloads VALUES (?, ?, ?, ?, ?)",
                (reference, kind, body, preview, len(body)),
            )
        return {"reference": reference, "kind": kind, "chars": len(body),
                "preview": preview, "compacted": preview != body}

    def fetch(self, reference: str, offset: int = 0, limit: int = 8000) -> dict:
        """Read a character range from the redacted output store."""
        if not _REFERENCE.fullmatch(reference):
            raise ValueError("Invalid context reference")
        if not 0 <= offset <= MAX_OUTPUT_BYTES or not 1 <= limit <= 16000:
            raise ValueError("Output offset or limit is out of bounds")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT kind, substr(body, ?, ?) AS text, chars FROM offloads WHERE reference = ?",
                (offset + 1, limit, reference),
            ).fetchone()
        if row is None:
            raise ValueError("Unknown context reference")
        end = offset + len(row["text"])
        return {"reference": reference, **dict(row), "offset": offset,
                "next_offset": end if end < row["chars"] else None}

    def graph(self, query: str = "", provenance: Provenance | None = None, limit: int = 100) -> dict:
        """Return bounded relationship matches and their endpoint nodes."""
        if provenance not in {None, "observed", "inferred"}:
            raise ValueError("Graph provenance must be observed or inferred")
        if not 1 <= limit <= 500:
            raise ValueError("Graph limit must be between 1 and 500")
        parameters = {"query": query[:300], "provenance": provenance, "limit": limit}
        with self._connect() as conn, conn:
            conn.execute("BEGIN")
            edges = conn.execute(
                """SELECT edges.* FROM edges
                   JOIN nodes AS parent ON parent.id = edges.source
                   JOIN nodes AS child ON child.id = edges.target
                   WHERE (:provenance IS NULL OR edges.provenance = :provenance)
                     AND (instr(lower(parent.label || ' ' || coalesce(parent.path, '') ||
                                ' ' || child.label || ' ' || coalesce(child.path, '') ||
                                ' ' || edges.relation), lower(:query)) > 0)
                   ORDER BY edges.source, edges.target, edges.relation,
                            edges.provenance, edges.path, edges.line LIMIT :limit""",
                parameters,
            ).fetchall()
            endpoints = sorted({edge[column] for edge in edges for column in ("source", "target")})
            nodes = []
            for start in range(0, len(endpoints), 500):
                batch = endpoints[start:start + 500]
                placeholders = ",".join("?" for _ in batch)
                nodes.extend(conn.execute(
                    f"SELECT * FROM nodes WHERE id IN ({placeholders}) ORDER BY id", batch,
                ).fetchall())
            if provenance is None and len(nodes) < limit:
                existing = {node["id"] for node in nodes}
                candidates = conn.execute(
                    """SELECT * FROM nodes
                       WHERE instr(lower(label || ' ' || coalesce(path, '')), lower(:query)) > 0
                       ORDER BY id LIMIT :limit""",
                    parameters,
                )
                nodes.extend([node for node in candidates if node["id"] not in existing][:limit - len(nodes)])
        return {"nodes": [dict(node) for node in nodes], "edges": [dict(edge) for edge in edges]}
