"""Extract structural relationships without importing repository source."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from thread_sdlc.governance.redactor import redact_text

DOCUMENT_SUFFIXES = {".md", ".rst", ".txt"}
CODE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs",
    ".java", ".kt", ".cs", ".c", ".h", ".cpp", ".hpp", ".rb", ".swift",
}
MAX_RELATIONSHIPS = 160
_DECLARATION = re.compile(
    r"^\s*(?:(?:export|default|public|protected|private|static|async|pub)\s+)*"
    r"(?P<kind>class|interface|struct|enum|trait|function|def|func|fn)\s+"
    r"(?:\([^)]*\)\s*)?(?P<label>[A-Za-z_$][\w$]*)",
)
_RULE = re.compile(r"\bBR-[A-Z0-9]+(?:-[A-Z0-9]+)+\b")


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    kind: str
    path: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class Relationship:
    node: Node
    source: str
    relation: str
    provenance: str
    line: int


class _PythonStructure(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.parents = [f"file:{path}"]
        self.results: list[Relationship] = []

    def generic_visit(self, node: ast.AST) -> None:
        if len(self.results) < MAX_RELATIONSHIPS:
            super().generic_visit(node)

    def _define(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef, kind: str) -> None:
        if len(self.results) == MAX_RELATIONSHIPS:
            return
        label = redact_text(node.name)
        symbol = Node(f"symbol:{self.path}:{node.lineno}:{label}", label, kind, self.path, node.lineno)
        self.results.append(Relationship(symbol, self.parents[-1], "defines", "observed", node.lineno))
        self.parents.append(symbol.id)
        self.generic_visit(node)
        self.parents.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._define(node, "class")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._define(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._define(node, "function")

    def _import(self, module: str, line: int) -> None:
        if len(self.results) == MAX_RELATIONSHIPS:
            return
        label = redact_text(module)
        key = f"{self.path}:{label}" if label.startswith(".") else label
        self.results.append(
            Relationship(Node(f"module:{key}", label, "module"), self.parents[-1], "imports", "observed", line)
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._import(alias.name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._import("." * node.level + node.module, node.lineno)
        else:
            for alias in node.names:
                self._import("." * node.level + alias.name, node.lineno)


def extract(path: str, source: str) -> list[Relationship]:
    """Find AST facts, inferred fallback declarations, and observed rule mentions."""
    suffix = PurePosixPath(path).suffix.lower()
    results: list[Relationship] = []
    if suffix in {".py", ".pyi"}:
        visitor = _PythonStructure(path)
        try:
            visitor.visit(ast.parse(source))
        except (SyntaxError, ValueError, RecursionError):
            pass
        else:
            return visitor.results

    for lineno, line in enumerate(source.splitlines(), 1):
        if suffix in DOCUMENT_SUFFIXES:
            for match in _RULE.finditer(line):
                label = match.group()
                results.append(Relationship(Node(f"rule:{label}", label, "business_rule"),
                                            f"file:{path}", "mentions", "observed", lineno))
                if len(results) == MAX_RELATIONSHIPS:
                    return results
        elif match := _DECLARATION.match(line):
            label = redact_text(match["label"])
            kind = "function" if match["kind"] in {"function", "def", "func", "fn"} else match["kind"]
            node = Node(f"symbol:{path}:{lineno}:{label}", label, kind, path, lineno)
            results.append(Relationship(node, f"file:{path}", "defines", "inferred", lineno))
            if len(results) == MAX_RELATIONSHIPS:
                break
    return results


def module_keys(path: str) -> tuple[str, ...]:
    file = PurePosixPath(path)
    if file.suffix not in {".py", ".pyi"}:
        return ()
    parts = file.with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    names = [".".join(parts)] if parts else []
    if len(parts) > 1 and parts[0] == "src":
        names.append(".".join(parts[1:]))
    return tuple(names)


def import_keys(path: str, label: str) -> tuple[str, ...]:
    if not label.startswith("."):
        return (label,)
    module = label.lstrip(".")
    parents = PurePosixPath(path).parent.parts
    ascend = len(label) - len(module) - 1
    if ascend > len(parents):
        return ()
    parent = parents[: len(parents) - ascend]
    keys = [".".join((*parent, module))]
    if parent and parent[0] == "src":
        keys.append(".".join((*parent[1:], module)))
    return tuple(keys)
