from __future__ import annotations

from datetime import datetime
from typing import List

from app.ai.mitre_mapper import map_event_type
from app.config import get_settings
from app.detectors.base import BaseDetector
from app.schemas import RawObservation, SuspiciousEvent
from app.utils.geoip import lookup_ip
from app.utils.risk import score_bundle


class LoginAnomalyDetector(BaseDetector):
    name = "login_anomaly_detector"

    def __init__(self) -> None:
        self.settings = get_settings()

    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        if observation.category != "authentication":
            return []
        payload = observation.payload
        if payload.get("outcome") != "success":
            return []
        ip = str(payload.get("ip", "unknown"))
        username = str(payload.get("username", "unknown"))
        geo = lookup_ip(ip)
        findings: List[str] = []
        if ip not in self.settings.trusted_login_ip_list:
            findings.append("login from untrusted source IP")
        if geo["country"] not in self.settings.allowed_country_list and geo["country"] not in {"LOCAL", "UNKNOWN"}:
            findings.append(f"country {geo['country']} is not allowlisted")
        current_hour = datetime.now().hour
        start_hour, end_hour = [int(part.split(":")[0]) for part in self.settings.normal_working_hours.split("-")]
        if not (start_hour <= current_hour <= end_hour):
            findings.append("login occurred outside normal working hours")
        if not findings:
            return []
        score = score_bundle("medium", 72)
        return [
            SuspiciousEvent(
                event_type="login_anomaly",
                source="auth",
                title=f"Login anomaly for user {username}",
                summary=f"Successful login from {ip} triggered anomaly checks: {', '.join(findings)}.",
                raw_evidence=[{"type": "auth_log", "line": payload.get("raw", "")}],
                indicators={"source_ip": ip, "username": username, "geo": geo},
                mitre_techniques=map_event_type("login_anomaly"),
                metadata={"findings": findings, **score},
                **score,
            )
        ]
