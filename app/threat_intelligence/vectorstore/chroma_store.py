from __future__ import annotations

from typing import Any, Dict, List

from app.config import get_settings


class ChromaThreatStore:
    def __init__(self) -> None:
        settings = get_settings()
        import chromadb

        client = chromadb.PersistentClient(path=settings.chroma_path)
        self.collection: Any = client.get_or_create_collection(name="aegisai-threat-intel")

    def upsert(self, ids: List[str], documents: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, object]]) -> None:
        self.collection.upsert(ids=ids, documents=documents, embeddings=embeddings, metadatas=metadatas)

    def query(self, query_embedding: List[float], top_k: int = 4) -> Dict[str, List[object]]:
        return self.collection.query(query_embeddings=[query_embedding], n_results=top_k)
