from __future__ import annotations

from typing import Dict, List


MITRE_LOOKUP: Dict[str, List[str]] = {
    "ssh_bruteforce": ["T1110"],
    "ftp_bruteforce": ["T1110"],
    "webapp_bruteforce": ["T1110", "T1078"],
    "port_scan": ["T1595"],
    "ddos": ["T1498"],
    "login_anomaly": ["T1078"],
    "privilege_escalation": ["T1548", "T1059"],
    "command_execution": ["T1059", "T1105"],
    "package_install": ["T1059", "T1588"],
    "data_exfiltration": ["T1041", "T1560"],
    "file_integrity": ["T1098", "T1543"],
    "process_anomaly": ["T1057", "T1496"],
}


def map_event_type(event_type: str) -> List[str]:
    return MITRE_LOOKUP.get(event_type, [])
