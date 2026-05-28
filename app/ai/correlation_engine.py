from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List

from app.ai.llm_engine import LLMEngine
from app.ai.prompts import join_lines
from app.database.history import AttackHistoryStore
from app.database.models import EventRecord
from app.schemas import CorrelatedThreat, SuspiciousEvent
from app.threat_intelligence.rag.retrieval_pipeline import RetrievalPipeline
from app.utils.helpers import unique_preserve_order


class CorrelationEngine:
    def __init__(self) -> None:
        self.buffer: Deque[SuspiciousEvent] = deque(maxlen=50)
        self.llm = LLMEngine()
        self.history = AttackHistoryStore()
        self.retrieval = RetrievalPipeline()

    async def correlate(self, session, event_records: List[EventRecord]) -> CorrelatedThreat | None:
        if not event_records:
            return None
        events = [
            SuspiciousEvent(
                event_type=record.event_type,
                source=record.source,
                title=record.title,
                summary=record.summary,
                severity=record.severity,
                confidence=record.confidence,
                risk_score=record.risk_score,
                indicators=record.indicators,
                raw_evidence=record.raw_evidence,
                mitre_techniques=record.mitre_techniques,
                metadata=record.metadata_json,
                created_at=record.created_at,
            )
            for record in event_records
        ]
        for event in events:
            self.buffer.append(event)
        if len(events) < 2 and events[0].risk_score < 80:
            return None
        attack_chain = unique_preserve_order([event.event_type for event in list(self.buffer)[-6:]])
        evidence_lines = []
        for event in events:
            for item in event.raw_evidence:
                evidence_lines.append(f"{item.get('type')}: {item.get('line')}")
        actor_key = next(
            (
                str(event.indicators.get("source_ip"))
                for event in events
                if event.indicators.get("source_ip")
            ),
            "unknown",
        )
        historical_records = self.history.recent_for_actor(session, actor_key)
        history_text = join_lines([record.summary for record in historical_records]) or "- no previous history"
        retrieved_context_text, retrieved_records = self.retrieval.retrieve_context(events)
        event_summary = join_lines([event.summary for event in events])
        mitre = join_lines(unique_preserve_order(tech for event in events for tech in event.mitre_techniques))
        narrative = await self.llm.analyze(
            event_summary=event_summary,
            evidence=join_lines(evidence_lines),
            history=history_text,
            retrieved_context=retrieved_context_text,
            mitre=mitre,
        )
        severity = "critical" if any(event.severity == "critical" for event in events) or len(attack_chain) >= 4 else "high"
        confidence = min(99, max(event.confidence for event in events) + min(10, len(attack_chain) * 2))
        risk_score = min(100, max(event.risk_score for event in events) + min(15, len(attack_chain) * 2))
        summary = f"Correlated attack chain observed: {' -> '.join(attack_chain)}"
        self.history.record(session, actor_key, attack_chain[-1], summary, {"attack_chain": attack_chain})
        return CorrelatedThreat(
            title="Possible multi-stage intrusion sequence detected",
            narrative=narrative,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            event_ids=[record.id for record in event_records],
            mitre_techniques=unique_preserve_order(tech for event in events for tech in event.mitre_techniques),
            raw_evidence=[item for event in events for item in event.raw_evidence],
            recommendations=[
                "Review the source IP and account activity immediately.",
                "Contain active sessions and isolate affected host if unauthorized.",
                "Preserve logs and process history for DFIR follow-up.",
            ],
            retrieved_context=retrieved_records,
            historical_context=[
                {"summary": record.summary, "created_at": record.created_at.isoformat()} for record in historical_records
            ],
        )
