from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


SUSPICIOUS_PATTERNS = [
    "sudo ",
    "chmod +s",
    "setcap ",
    "usermod ",
    "passwd ",
    "/etc/sudoers",
    "systemctl enable",
]


class PrivilegeDetector(BaseDetector):
    name = "privilege_detector"

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "command_history":
            return []
        command = str(observation.payload.get("command", ""))
        if not any(pattern in command for pattern in SUSPICIOUS_PATTERNS):
            return []
        score = score_bundle("high", 84)
        return [
            SuspiciousEvent(
                event_type="privilege_escalation",
                source="history",
                title="Suspicious privilege escalation command observed",
                summary=f"Command history contains potentially privileged or persistence-related action: {command}",
                raw_evidence=[{"type": "shell_history", "line": command}],
                indicators={"command": command, "history_file": observation.payload.get("history_file")},
                mitre_techniques=map_event_type("privilege_escalation"),
                metadata=score,
                **score,
            )
        ]
