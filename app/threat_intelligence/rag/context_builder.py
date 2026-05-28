from __future__ import annotations

from typing import Dict, List


def build_context(records: List[Dict[str, object]]) -> str:
    if not records:
        return "- no additional threat intelligence retrieved"
    lines = []
    for record in records:
        metadata = record.get("metadata", {})
        title = metadata.get("title", "intel")
        source = metadata.get("source_name", "local")
        lines.append(f"{title} ({source}): {str(record.get('document', ''))[:300]}")
    return "\n".join(f"- {line}" for line in lines)
