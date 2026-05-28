from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


EXFIL_COMMAND_MARKERS = ["scp ", "rsync ", "curl -T", "curl --upload-file", "tar -czf", "zip ", "gpg -c"]


class ExfiltrationDetector(BaseDetector):
    name = "exfiltration_detector"

    def __init__(self) -> None:
        self.settings = get_settings()

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category == "command_history":
            command = str(observation.payload.get("command", ""))
            if not any(marker in command for marker in EXFIL_COMMAND_MARKERS):
                return []
            score = score_bundle("high", 86)
            return [
                SuspiciousEvent(
                    event_type="data_exfiltration",
                    source="history",
                    title="Potential exfiltration workflow command observed",
                    summary=f"Command history contains archive creation or upload behavior: {command}",
                    raw_evidence=[{"type": "shell_history", "line": command}],
                    indicators={"command": command},
                    mitre_techniques=map_event_type("data_exfiltration"),
                    metadata=score,
                    **score,
                )
            ]
        if observation.category == "network_connection":
            remote = str(observation.payload.get("remote_address", "unknown"))
            status = str(observation.payload.get("status", ""))
            if status != "ESTABLISHED" or remote == "unknown":
                return []
            remote_port = int(remote.split(":")[-1])
            if remote_port not in {22, 443, 8443}:
                return []
            score = score_bundle("medium", 65)
            return [
                SuspiciousEvent(
                    event_type="data_exfiltration",
                    source="connections",
                    title="Outbound encrypted session observed",
                    summary=f"Established outbound connection to {remote} may support exfiltration when combined with staging evidence.",
                    raw_evidence=[{"type": "connection", "line": str(observation.payload)}],
                    indicators={"remote_address": remote, "pid": observation.payload.get("pid")},
                    mitre_techniques=map_event_type("data_exfiltration"),
                    metadata=score,
                    **score,
                )
            ]
        return []
