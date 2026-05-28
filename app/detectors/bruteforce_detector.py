from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Tuple

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


class BruteForceDetector(BaseDetector):
    name = "bruteforce_detector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self.failures: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(deque)

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "authentication":
            return []
        payload = observation.payload
        if payload.get("outcome") != "failure":
            return []
        now = datetime.now(timezone.utc)
        key = (payload.get("ip", "unknown"), payload.get("username", "unknown"))
        bucket = self.failures[key]
        bucket.append(now)
        cutoff = now - timedelta(seconds=self.settings.brute_force_window_seconds)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) < self.settings.brute_force_threshold:
            return []
        service = "ssh"
        score = score_bundle("high", min(99, 60 + len(bucket) * 5))
        return [
            SuspiciousEvent(
                event_type=f"{service}_bruteforce",
                source="auth",
                title=f"{service.upper()} brute force suspected from {key[0]}",
                summary=f"Detected {len(bucket)} failed login attempts for user {key[1]} from source IP {key[0]} within the configured window.",
                raw_evidence=[{"type": "auth_log", "line": payload.get("raw", "")}],
                indicators={"source_ip": key[0], "username": key[1], "attempt_count": len(bucket)},
                mitre_techniques=map_event_type("ssh_bruteforce"),
                metadata={"service": service, **score},
                **score,
            )
        ]
