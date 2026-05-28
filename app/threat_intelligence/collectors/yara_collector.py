from __future__ import annotations

from typing import Dict, List


class YaraCollector:
    async def collect(self) -> List[Dict[str, object]]:
        return [
            {
                "external_id": "yara-miner-behavior",
                "title": "Cryptominer behavior notes",
                "content": "Long-running xmrig or minerd processes with outbound pools are strong mining indicators.",
                "metadata": {"source_name": "YARA-Reference", "category": "resource_hijacking"},
            }
        ]
