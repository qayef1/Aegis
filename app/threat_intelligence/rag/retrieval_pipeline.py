from __future__ import annotations

from typing import Dict, List

from app.schemas import SuspiciousEvent
from app.threat_intelligence.rag.context_builder import build_context
from app.threat_intelligence.rag.prompt_augmentation import build_query_from_events
from app.threat_intelligence.vectorstore.retriever import ThreatIntelRetriever


class RetrievalPipeline:
    def __init__(self) -> None:
        self.retriever = ThreatIntelRetriever()

    def retrieve_context(self, events: List[SuspiciousEvent]) -> tuple[str, List[Dict[str, object]]]:
        query = build_query_from_events(events)
        records = self.retriever.retrieve(query)
        return build_context(records), records
