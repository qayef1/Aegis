from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


class WebAppDetector(BaseDetector):
    name = "webapp_detector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self.failures: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.usernames_by_ip: Dict[str, set[str]] = defaultdict(set)

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "web_auth":
            return []
        payload = observation.payload
        if payload.get("method") != "POST":
            return []
        if int(payload.get("status", 0)) == 200:
            return []
        now = datetime.now(timezone.utc)
        ip = payload.get("ip", "unknown")
        bucket = self.failures[ip]
        bucket.append(now)
        self.usernames_by_ip[ip].add(str(payload.get("username", "unknown")))
        cutoff = now - timedelta(seconds=self.settings.brute_force_window_seconds)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) < self.settings.brute_force_threshold:
            return []
        confidence = min(95, 55 + len(bucket) * 5 + len(self.usernames_by_ip[ip]) * 4)
        score = score_bundle("high", confidence)
        return [
            SuspiciousEvent(
                event_type="webapp_bruteforce",
                source="webapp",
                title=f"Web login brute force suspected from {ip}",
                summary=f"Observed {len(bucket)} failed POST /login attempts from {ip} across {len(self.usernames_by_ip[ip])} usernames.",
                raw_evidence=[{"type": "webapp_log", "line": payload.get("raw", "")}],
                indicators={
                    "source_ip": ip,
                    "username_count": len(self.usernames_by_ip[ip]),
                    "attempt_count": len(bucket),
                },
                mitre_techniques=map_event_type("webapp_bruteforce"),
                metadata={"path": payload.get("path"), **score},
                **score,
            )
        ]
