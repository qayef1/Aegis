from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.schemas import RawObservation
from app.utils.logger import get_logger


logger = get_logger(__name__)


class FileIntegrityCollector(BaseCollector):
    name = "file_integrity_collector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._hashes: Dict[str, str] = {}

    async def collect(self) -> List[RawObservation]:
        observations: List[RawObservation] = []
        for file_path in self.settings.sensitive_path_list:
            path = Path(file_path).expanduser()
            if not path.exists() or not path.is_file():
                continue
            if not os.access(path, os.R_OK):
                logger.warning("Skipping unreadable sensitive path: %s", path)
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            previous = self._hashes.get(str(path))
            self._hashes[str(path)] = digest
            if previous and previous != digest:
                observations.append(
                    RawObservation(
                        source="fim",
                        category="file_integrity",
                        payload={"path": str(path), "old_hash": previous, "new_hash": digest},
                    )
                )
        return observations
