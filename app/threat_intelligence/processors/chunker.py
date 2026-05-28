from __future__ import annotations

from typing import List


def chunk_text(text: str, chunk_size: int = 450, overlap: int = 50) -> List[str]:
    words = text.split()
    if not words:
        return []
    chunks: List[str] = []
    step = max(1, chunk_size - overlap)
    for index in range(0, len(words), step):
        chunk = " ".join(words[index : index + chunk_size]).strip()
        if chunk:
            chunks.append(chunk)
    return chunks
