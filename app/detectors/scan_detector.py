from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Tuple

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


class ScanDetector(BaseDetector):
    name = "scan_detector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self.port_hits: Dict[str, Deque[Tuple[datetime, int]]] = defaultdict(deque)
        self.alerted_sources: set[str] = set()

    def tick(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.settings.packet_window_seconds)
        for src_ip in list(self.port_hits):
            hits = self.port_hits[src_ip]
            while hits and hits[0][0] < cutoff:
                hits.popleft()
            if not hits:
                del self.port_hits[src_ip]
                self.alerted_sources.discard(src_ip)
            else:
                ports = {hit_port for _, hit_port in hits}
                if len(ports) < self.settings.scan_unique_port_threshold:
                    self.alerted_sources.discard(src_ip)

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "packet_summary":
            return []
        payload = observation.payload
        if payload.get("is_local_source"):
            return []
        src_ip = str(payload.get("src_ip", "unknown"))
        port = int(payload.get("dst_port", 0))
        flags = str(payload.get("flags", ""))
        if payload.get("protocol") != "TCP" or port == 0:
            return []
        is_syn_probe = "S" in flags and "A" not in flags
        is_fin_probe = "F" in flags and "A" not in flags
        is_null_probe = flags == ""
        if not (is_syn_probe or is_fin_probe or is_null_probe):
            return []
        now = datetime.now(timezone.utc)
        hits = self.port_hits[src_ip]
        hits.append((now, port))
        cutoff = now - timedelta(seconds=self.settings.packet_window_seconds)
        while hits and hits[0][0] < cutoff:
            hits.popleft()
        ports = {hit_port for _, hit_port in hits}
        if len(ports) < self.settings.scan_unique_port_threshold:
            self.alerted_sources.discard(src_ip)
            return []
        if src_ip in self.alerted_sources:
            return []
        self.alerted_sources.add(src_ip)
        fingerprint = "syn" if "S" in flags else "fin" if "F" in flags else "xmas" if "FPU" in flags else "null"
        score = score_bundle("high", 85)
        return [
            SuspiciousEvent(
                event_type="port_scan",
                source="packets",
                title=f"Port scanning suspected from {src_ip}",
                summary=f"Source {src_ip} contacted {len(ports)} unique TCP ports within {self.settings.packet_window_seconds} seconds.",
                raw_evidence=[{"type": "packet", "line": str(payload)}],
                indicators={
                    "source_ip": src_ip,
                    "unique_ports": sorted(ports)[:50],
                    "scan_speed": len(hits),
                    "fingerprint": fingerprint,
                },
                mitre_techniques=map_event_type("port_scan"),
                metadata=score,
                **score,
            )
        ]
