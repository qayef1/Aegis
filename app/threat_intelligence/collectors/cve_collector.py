from __future__ import annotations

from typing import Dict, List


class CVECollector:
    async def collect(self) -> List[Dict[str, object]]:
        return [
            {
                "external_id": "CVE-local-ssh-abuse",
                "title": "SSH exposed service abuse pattern",
                "content": "Public SSH services often experience password spraying and brute force attempts before valid account compromise.",
                "metadata": {"source_name": "CVE-Reference", "category": "credential_access"},
            }
        ]
