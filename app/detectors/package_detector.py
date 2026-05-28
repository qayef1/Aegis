from __future__ import annotations

from typing import List

from app.ai.mitre_mapper import map_event_type
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.risk import score_bundle


RISKY_PACKAGES = {"nmap", "hydra", "netcat", "socat", "masscan", "john", "medusa"}


class PackageDetector(BaseDetector):
    name = "package_detector"

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "package_change":
            return []
        package = str(observation.payload.get("package", ""))
        if package not in RISKY_PACKAGES:
            return []
        score = score_bundle("medium", 75)
        return [
            SuspiciousEvent(
                event_type="package_install",
                source="packages",
                title=f"Suspicious package activity detected: {package}",
                summary=f"Package manager logs show installation or removal of offensive tooling package {package}.",
                raw_evidence=[{"type": "package_log", "line": observation.payload.get("raw", "")}],
                indicators={"package": package, "log_file": observation.payload.get("log_file")},
                mitre_techniques=map_event_type("package_install"),
                metadata=score,
                **score,
            )
        ]
