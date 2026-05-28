from __future__ import annotations

from typing import Dict


def normalize_document(source: str, title: str, content: str, metadata: Dict[str, str]) -> Dict[str, object]:
    return {
        "source_name": source,
        "title": title.strip(),
        "content": content.strip(),
        "metadata": metadata,
    }
