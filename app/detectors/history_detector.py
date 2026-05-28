from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


DANGEROUS_HISTORY_MARKERS = ["rm -rf /", "history -c", "shred ", "echo '' >", "nohup ", "crontab -e", "base64 -d"]


class HistoryDetector(BaseDetector):
    name = "history_detector"

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "command_history":
            return []
        command = str(observation.payload.get("command", ""))
        if not any(marker in command for marker in DANGEROUS_HISTORY_MARKERS):
            return []
        score = score_bundle("high", 80)
        return [
            SuspiciousEvent(
                event_type="command_execution",
                source="history",
                title="Suspicious command history entry detected",
                summary=f"History monitoring identified a destructive or stealth-oriented command: {command}",
                raw_evidence=[{"type": "shell_history", "line": command}],
                indicators={"command": command},
                mitre_techniques=map_event_type("command_execution"),
                metadata=score,
                **score,
            )
        ]
