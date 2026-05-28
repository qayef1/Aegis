from __future__ import annotations

from typing import Dict, List


class SigmaCollector:
    async def collect(self) -> List[Dict[str, object]]:
        return [
            {
                "external_id": "sigma-linux-suspicious-sudo",
                "title": "Suspicious sudo and persistence commands",
                "content": "Look for sudo immediately after new remote login, setuid changes, sudoers edits, or service persistence changes.",
                "metadata": {"source_name": "Sigma", "category": "privilege_escalation"},
            }
        ]
