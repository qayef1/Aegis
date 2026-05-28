from __future__ import annotations

from typing import Dict, List

import httpx


class MitreCollector:
    url = "https://attack.mitre.org/techniques/enterprise/"

    async def collect(self) -> List[Dict[str, object]]:
        static_docs = [
            {
                "external_id": "T1110",
                "title": "Brute Force",
                "content": "Brute force attempts target remote services through repeated credential guessing.",
                "metadata": {"source_name": "MITRE", "technique": "T1110"},
            },
            {
                "external_id": "T1595",
                "title": "Active Scanning",
                "content": "Adversaries scan for open ports and exposed services before compromise.",
                "metadata": {"source_name": "MITRE", "technique": "T1595"},
            },
            {
                "external_id": "T1041",
                "title": "Exfiltration Over C2 Channel",
                "content": "Adversaries may transfer staged data over outbound channels including SCP and HTTPS.",
                "metadata": {"source_name": "MITRE", "technique": "T1041"},
            },
        ]
        return static_docs
