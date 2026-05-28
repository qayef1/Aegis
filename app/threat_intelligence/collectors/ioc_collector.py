from __future__ import annotations

from typing import Dict, List


class IOCCollector:
    async def collect(self) -> List[Dict[str, object]]:
        return [
            {
                "external_id": "ioc-suspicious-scp",
                "title": "SCP exfiltration indicator",
                "content": "Unexpected outbound SCP sessions to unknown infrastructure can indicate data theft.",
                "metadata": {"source_name": "IOC-Reference", "ioc_tag": "scp"},
            }
        ]
