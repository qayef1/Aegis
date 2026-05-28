from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


MALICIOUS_PROCESS_MARKERS = [
    "nc -e",
    "bash -i",
    "curl http",
    "wget http",
    "python -c",
    "xmrig",
    "minerd",
    "socat TCP",
]


class ProcessDetector(BaseDetector):
    name = "process_detector"

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "process_execution":
            return []
        cmdline = str(observation.payload.get("cmdline", ""))
        if not any(marker in cmdline for marker in MALICIOUS_PROCESS_MARKERS):
            return []
        score = score_bundle("high", 88)
        return [
            SuspiciousEvent(
                event_type="process_anomaly",
                source="process",
                title=f"Suspicious process execution detected: PID {observation.payload.get('pid')}",
                summary=f"Process command line matched known risky execution patterns: {cmdline}",
                raw_evidence=[{"type": "process", "line": str(observation.payload)}],
                indicators=observation.payload,
                mitre_techniques=map_event_type("process_anomaly"),
                metadata=score,
                **score,
            )
        ]
