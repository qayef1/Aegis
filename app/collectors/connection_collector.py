from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import psutil

from app.collectors.base import BaseCollector
from app.schemas import RawObservation


class ConnectionCollector(BaseCollector):
    name = "connection_collector"

    def __init__(self) -> None:
        self._seen: Dict[Tuple[str, str, str, str], float] = {}

    async def collect(self) -> List[RawObservation]:
        observations: List[RawObservation] = []
        now = datetime.now(timezone.utc).timestamp()
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
            key = (conn.type.name if hasattr(conn.type, "name") else str(conn.type), laddr, raddr, conn.status)
            if key in self._seen and conn.status == "ESTABLISHED":
                continue
            self._seen[key] = now
            observations.append(
                RawObservation(
                    source="connections",
                    category="network_connection",
                    payload={
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "local_address": laddr,
                        "remote_address": raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                    },
                )
            )
        return observations
