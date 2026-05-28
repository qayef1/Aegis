from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from app.schemas import RawObservation


class BaseCollector(ABC):
    name: str

    @abstractmethod
    async def collect(self) -> List[RawObservation]:
        raise NotImplementedError
