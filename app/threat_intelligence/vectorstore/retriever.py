from __future__ import annotations

from typing import Dict, List

from app.config import get_settings
from app.threat_intelligence.processors.embedder import EmbeddingEngine
from app.threat_intelligence.vectorstore.chroma_store import ChromaThreatStore
from app.threat_intelligence.vectorstore.similarity_engine import flatten_query_result
from app.utils.logger import get_logger


logger = get_logger(__name__)


class ThreatIntelRetriever:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.embedder: EmbeddingEngine | None = None
        self.store: ChromaThreatStore | None = None

    def _ensure_components(self) -> tuple[EmbeddingEngine, ChromaThreatStore]:
        if self.embedder is None:
            self.embedder = EmbeddingEngine()
        if self.store is None:
            self.store = ChromaThreatStore()
        return self.embedder, self.store

    def retrieve(self, query: str) -> List[Dict[str, object]]:
        try:
            embedder, store = self._ensure_components()
            embedding = embedder.encode([query])[0]
            result = store.query(embedding, top_k=self.settings.retriever_top_k)
            return flatten_query_result(result)
        except Exception as exc:
            logger.warning("Threat intel retrieval skipped: %s", exc)
            return []
