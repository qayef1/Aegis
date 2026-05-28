from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


class FileIntegrityDetector(BaseDetector):
    name = "file_integrity_detector"

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "file_integrity":
            return []
        path = str(observation.payload.get("path"))
        score = score_bundle("critical", 87)
        return [
            SuspiciousEvent(
                event_type="file_integrity",
                source="fim",
                title=f"Sensitive file modified: {path}",
                summary=f"File integrity monitoring detected a hash change for sensitive path {path}.",
                raw_evidence=[{"type": "fim", "line": str(observation.payload)}],
                indicators=observation.payload,
                mitre_techniques=map_event_type("file_integrity"),
                metadata=score,
                **score,
            )
        ]
