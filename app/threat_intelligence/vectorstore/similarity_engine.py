from __future__ import annotations

from typing import Dict, List


def flatten_query_result(result: Dict[str, List[object]]) -> List[Dict[str, object]]:
    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0] if result.get("distances") else [0.0] * len(documents)
    output: List[Dict[str, object]] = []
    for document, metadata, distance in zip(documents, metadatas, distances):
        output.append({"document": document, "metadata": metadata or {}, "distance": distance})
    return output
