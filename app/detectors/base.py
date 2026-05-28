from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from app.schemas import RawObservation, SuspiciousEvent


class BaseDetector(ABC):
    name: str

    @abstractmethod
    async def process(self, observation: RawObservation) -> List[SuspiciousEvent]:
        raise NotImplementedError

    def tick(self) -> None:
        return None
