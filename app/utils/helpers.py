from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent(path: str) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def tail_lines(path: str, limit: int = 1000) -> List[str]:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return []
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()
    return [line.rstrip("\n") for line in lines[-limit:]]


def unique_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
