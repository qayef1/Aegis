from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


class DDoSDetector(BaseDetector):
    name = "ddos_detector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self.packet_counts: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.alerted_sources: set[str] = set()

    def tick(self) -> None:
        for src_ip in list(self.packet_counts):
            bucket = self.packet_counts[src_ip]
            for _ in range(min(self.settings.ddos_counter_decay_per_tick, len(bucket))):
                bucket.popleft()
            if not bucket:
                del self.packet_counts[src_ip]
                self.alerted_sources.discard(src_ip)
            elif len(bucket) < self.settings.ddos_packet_threshold:
                self.alerted_sources.discard(src_ip)

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "packet_summary":
            return []
        if observation.payload.get("is_local_source"):
            return []
        protocol = str(observation.payload.get("protocol", "UNKNOWN"))
        flags = str(observation.payload.get("flags", ""))
        src_port = int(observation.payload.get("src_port", 0) or 0)
        if protocol == "TCP" and ("S" not in flags or "A" in flags):
            return []
        if protocol == "UDP" and src_port in {53, 123, 443, 853}:
            return []
        if protocol not in {"TCP", "UDP", "ICMP"}:
            return []
        src_ip = str(observation.payload.get("src_ip", "unknown"))
        now = datetime.now(timezone.utc)
        bucket = self.packet_counts[src_ip]
        bucket.append(now)
        cutoff = now - timedelta(seconds=self.settings.packet_window_seconds)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) < self.settings.ddos_packet_threshold:
            self.alerted_sources.discard(src_ip)
            return []
        if src_ip in self.alerted_sources:
            return []
        self.alerted_sources.add(src_ip)
        threshold_ratio = len(bucket) / max(1, self.settings.ddos_packet_threshold)
        if threshold_ratio >= 5:
            score = score_bundle("critical", 92)
        else:
            score = score_bundle("high", min(89, 78 + int(threshold_ratio * 3)))
        return [
            SuspiciousEvent(
                event_type="ddos",
                source="packets",
                title=f"Possible {protocol} flood from {src_ip}",
                summary=f"Observed {len(bucket)} packets from {src_ip} inside a {self.settings.packet_window_seconds}-second sliding window.",
                raw_evidence=[{"type": "packet", "line": str(observation.payload)}],
                indicators={"source_ip": src_ip, "pps_window_count": len(bucket), "protocol": protocol},
                mitre_techniques=map_event_type("ddos"),
                metadata=score,
                **score,
            )
        ]
