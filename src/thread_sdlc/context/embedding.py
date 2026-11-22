"""Optional embedding inference from a locally provisioned ONNX model."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> Sequence[Sequence[float]]: ...


class FastEmbedAdapter:
    """Load local model files on first use and do not request remote files."""

    def __init__(self, model_dir: Path, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self.model_dir = model_dir
        self.model_name = model_name
        self._model = None

    def embed(self, texts: list[str]) -> Sequence[Sequence[float]]:
        if self._model is None:
            if not self.model_dir.is_dir():
                raise FileNotFoundError("The local embedding model directory does not exist")
            from fastembed import TextEmbedding

            self._model = TextEmbedding(
                model_name=self.model_name,
                specific_model_path=str(self.model_dir),
                local_files_only=True,
                threads=1,
            )
        return [vector.tolist() for vector in self._model.embed(texts, parallel=None)]
