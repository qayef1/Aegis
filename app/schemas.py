from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RawObservation(BaseModel):
    source: str
    category: str
    payload: Dict[str, Any]
    observed_at: datetime = Field(default_factory=utcnow)


class SuspiciousEvent(BaseModel):
    event_type: str
    source: str
    title: str
    summary: str
    severity: str
    confidence: int
    risk_score: int
    indicators: Dict[str, Any] = Field(default_factory=dict)
    raw_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class CorrelatedThreat(BaseModel):
    title: str
    narrative: str
    severity: str
    confidence: int
    risk_score: int
    event_ids: List[int] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    raw_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    retrieved_context: List[Dict[str, Any]] = Field(default_factory=list)
    historical_context: List[Dict[str, Any]] = Field(default_factory=list)
