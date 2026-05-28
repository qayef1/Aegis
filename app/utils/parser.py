from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional


AUTH_FAILURE_RE = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*?(Failed password|Invalid user|authentication failure).*?(from\s(?P<ip>\d+\.\d+\.\d+\.\d+))?.*?(for\s(invalid user\s)?(?P<username>[\w.@-]+))?",
)
AUTH_SUCCESS_RE = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*?(Accepted password|session opened|login succeeded).*?(from\s(?P<ip>\d+\.\d+\.\d+\.\d+))?.*?(for\s(?P<username>[\w.@-]+))?",
)
PACKAGE_RE = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}).*?(install|remove|upgrade)\s(?P<package>[\w.+-]+)")
WEBAPP_RE = re.compile(
    r"(?P<timestamp>[\d\-T:+]+)\s+\|\s+(?P<ip>[\d.]+)\s+\|\s+(?P<method>\w+)\s+\|\s+(?P<path>\S+)\s+\|\s+username=(?P<username>[^|]+)\s+\|\s+status=(?P<status>\d+)"
)


def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    for regex, outcome in ((AUTH_FAILURE_RE, "failure"), (AUTH_SUCCESS_RE, "success")):
        match = regex.search(line)
        if match:
            data = match.groupdict()
            ip = data.get("ip")
            username = data.get("username")
            if not ip:
                ip_match = re.search(r"(?:from|rhost=)\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", line)
                ip = ip_match.group("ip") if ip_match else None
            if not username:
                user_match = re.search(
                    r"(?:for\s+(?:invalid user\s+)?|user=|authenticating user\s+)(?P<username>[\w.@-]+)",
                    line,
                )
                username = user_match.group("username") if user_match else None
            return {
                "timestamp": data.get("timestamp"),
                "ip": ip or "unknown",
                "username": username or "unknown",
                "outcome": outcome,
                "raw": line,
            }
    return None


def parse_package_line(line: str) -> Optional[Dict[str, Any]]:
    match = PACKAGE_RE.search(line)
    if not match:
        return None
    return {**match.groupdict(), "raw": line}


def parse_webapp_line(line: str) -> Optional[Dict[str, Any]]:
    match = WEBAPP_RE.search(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["username"] = data["username"].strip()
    data["raw"] = line
    return data


def safe_parse_iso(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
