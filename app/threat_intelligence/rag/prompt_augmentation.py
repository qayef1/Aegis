from __future__ import annotations

from typing import List

from app.schemas import SuspiciousEvent


def build_query_from_events(events: List[SuspiciousEvent]) -> str:
    parts = []
    for event in events:
        parts.append(f"{event.event_type} {event.summary}")
    return " ".join(parts)
