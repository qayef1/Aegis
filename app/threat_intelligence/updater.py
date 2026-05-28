from __future__ import annotations

from typing import List

from app.database.db import get_db_session
from app.database.models import ThreatIntelDocument
from app.threat_intelligence.collectors.cve_collector import CVECollector
from app.threat_intelligence.collectors.ioc_collector import IOCCollector
from app.threat_intelligence.collectors.malware_collector import MalwareCollector
from app.threat_intelligence.collectors.mitre_collector import MitreCollector
from app.threat_intelligence.collectors.sigma_collector import SigmaCollector
from app.threat_intelligence.collectors.yara_collector import YaraCollector
from app.threat_intelligence.processors.chunker import chunk_text
from app.threat_intelligence.processors.cleaner import clean_text
from app.threat_intelligence.processors.embedder import EmbeddingEngine
from app.threat_intelligence.vectorstore.chroma_store import ChromaThreatStore
from app.utils.logger import get_logger


logger = get_logger(__name__)


class ThreatIntelUpdater:
    def __init__(self) -> None:
        self.collectors = [
            MitreCollector(),
            CVECollector(),
            MalwareCollector(),
            SigmaCollector(),
            YaraCollector(),
            IOCCollector(),
        ]
        self.embedder: EmbeddingEngine | None = None
        self.store: ChromaThreatStore | None = None

    def _ensure_components(self) -> tuple[EmbeddingEngine, ChromaThreatStore]:
        if self.embedder is None:
            self.embedder = EmbeddingEngine()
        if self.store is None:
            self.store = ChromaThreatStore()
        return self.embedder, self.store

    async def sync(self) -> int:
        try:
            documents: List[dict] = []
            for collector in self.collectors:
                documents.extend(await collector.collect())
            ids: List[str] = []
            chunks: List[str] = []
            metadatas: List[dict] = []
            for document in documents:
                content = clean_text(str(document["content"]))
                for index, chunk in enumerate(chunk_text(content)):
                    chunk_id = f"{document['external_id']}::{index}"
                    ids.append(chunk_id)
                    chunks.append(chunk)
                    metadatas.append(
                        {
                            "source_name": document["metadata"].get("source_name", "unknown"),
                            "title": document["title"],
                            "external_id": document["external_id"],
                            **document["metadata"],
                        }
                    )
                with get_db_session() as session:
                    exists = (
                        session.query(ThreatIntelDocument)
                        .filter(ThreatIntelDocument.external_id == str(document["external_id"]))
                        .first()
                    )
                    if not exists:
                        session.add(
                            ThreatIntelDocument(
                                source_name=str(document["metadata"].get("source_name", "unknown")),
                                external_id=str(document["external_id"]),
                                title=str(document["title"]),
                                content=content,
                                metadata_json=document["metadata"],
                            )
                        )
            if ids:
                embedder, store = self._ensure_components()
                embeddings = embedder.encode(chunks)
                store.upsert(ids=ids, documents=chunks, embeddings=embeddings, metadatas=metadatas)
            logger.info("Threat intelligence sync complete: %s chunks", len(ids))
            return len(ids)
        except Exception as exc:
            logger.warning("Threat intelligence sync skipped: %s", exc)
            return 0
