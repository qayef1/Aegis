from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.schemas import RawObservation


class HistoryCollector(BaseCollector):
    name = "history_collector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._offsets: Dict[str, int] = {}

    async def collect(self) -> List[RawObservation]:
        observations: List[RawObservation] = []
        for history_path in self.settings.history_file_list:
            path = Path(history_path)
            if not path.exists() or not path.is_file():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    all_lines = [line.strip() for line in handle.readlines() if line.strip()]
            except OSError:
                continue
            total_lines = len(all_lines)
            start_index = self._offsets.get(str(path))
            if start_index is None:
                self._offsets[str(path)] = total_lines
                continue
            if start_index > total_lines:
                start_index = 0
            new_lines = all_lines[start_index:total_lines]
            for line in new_lines[-200:]:
                observations.append(
                    RawObservation(
                        source="history",
                        category="command_history",
                        payload={"command": line, "history_file": str(path)},
                    )
                )
            self._offsets[str(path)] = total_lines
        return observations
