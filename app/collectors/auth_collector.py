from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.schemas import RawObservation
from app.utils.parser import parse_auth_line


class AuthCollector(BaseCollector):
    name = "auth_collector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._offsets: Dict[str, int] = {}

    async def collect(self) -> List[RawObservation]:
        observations: List[RawObservation] = []
        for log_path in self.settings.auth_log_path_list:
            path = Path(log_path)
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    lines = [line.rstrip("\n") for line in handle.readlines()]
            except OSError:
                continue
            total_lines = len(lines)
            start_index = self._offsets.get(str(path))
            if start_index is None:
                self._offsets[str(path)] = total_lines
                continue
            if start_index > total_lines:
                start_index = 0
            new_lines = lines[start_index:total_lines]
            self._offsets[str(path)] = total_lines
            for line in new_lines[-300:]:
                parsed = parse_auth_line(line)
                if not parsed:
                    continue
                observations.append(
                    RawObservation(
                        source="auth",
                        category="authentication",
                        payload={**parsed, "log_file": str(path)},
                    )
                )
        return observations
