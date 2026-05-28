from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

import psutil

from app.collectors.base import BaseCollector
from app.schemas import RawObservation


class ProcessCollector(BaseCollector):
    name = "process_collector"

    def __init__(self) -> None:
        self._seen: Dict[int, float] = {}

    async def collect(self) -> List[RawObservation]:
        observations: List[RawObservation] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "ppid", "create_time"]):
            info = proc.info
            pid = info["pid"]
            create_time = float(info.get("create_time") or 0.0)
            if self._seen.get(pid) == create_time:
                continue
            self._seen[pid] = create_time
            observations.append(
                RawObservation(
                    source="process",
                    category="process_execution",
                    payload={
                        "pid": pid,
                        "name": info.get("name") or "unknown",
                        "cmdline": " ".join(info.get("cmdline") or []),
                        "username": info.get("username") or "unknown",
                        "ppid": info.get("ppid") or 0,
                        "create_time": create_time,
                    },
                )
            )
        return observations
