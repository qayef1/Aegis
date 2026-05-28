from __future__ import annotations

from typing import Any, List

from app.config import get_settings


class EmbeddingEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.model: Any | None = None

    def _ensure_model(self) -> Any:
        if self.model is None:
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer(self.settings.embedding_model)
        return self.model

    def encode(self, texts: List[str]) -> List[List[float]]:
        vectors = self._ensure_model().encode(texts, normalize_embeddings=True)
        return [vector.tolist() for vector in vectors]
