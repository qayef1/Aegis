from __future__ import annotations

from pathlib import Path
from typing import List

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.schemas import RawObservation
from app.utils.parser import parse_webapp_line


class WebAppCollector(BaseCollector):
    name = "webapp_collector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._offset: int | None = None

    async def collect(self) -> List[RawObservation]:
        path = Path(self.settings.webapp_log_file)
        if not path.exists():
            return []
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = [line.rstrip("\n") for line in handle.readlines()]
        except OSError:
            return []
        total_lines = len(lines)
        start_index = self._offset
        if start_index is None:
            self._offset = total_lines
            return []
        if start_index > total_lines:
            start_index = 0
        new_lines = lines[start_index:total_lines]
        self._offset = total_lines
        observations: List[RawObservation] = []
        for line in new_lines[-300:]:
            parsed = parse_webapp_line(line)
            if parsed:
                observations.append(RawObservation(source="webapp", category="web_auth", payload=parsed))
        return observations
