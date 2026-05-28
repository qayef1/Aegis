from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.schemas import RawObservation
from app.utils.logger import get_logger

try:
    from scapy.all import IP, TCP, UDP, ICMP, AsyncSniffer  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = ICMP = AsyncSniffer = None


logger = get_logger(__name__)


class PacketCollector(BaseCollector):
    name = "packet_collector"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._buffer: Deque[Dict[str, str | int | float]] = deque(maxlen=2000)
        self._started = False
        self._sniffers: List[AsyncSniffer] = []
        self._disabled = False

    def _handle_packet(self, packet) -> None:
        if IP is None or IP not in packet:
            return
        proto = "OTHER"
        dst_port = 0
        flags = ""
        if TCP and TCP in packet:
            proto = "TCP"
            dst_port = int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
        elif UDP and UDP in packet:
            proto = "UDP"
            dst_port = int(packet[UDP].dport)
        elif ICMP and ICMP in packet:
            proto = "ICMP"

        self._buffer.append(
            {
                "src_ip": str(packet[IP].src),
                "dst_ip": str(packet[IP].dst),
                "protocol": proto,
                "dst_port": dst_port,
                "flags": flags,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def _ensure_started(self) -> None:
        if self._started or self._disabled or AsyncSniffer is None:
            return
        try:
            for interface in self.settings.monitored_interface_list:
                sniffer = AsyncSniffer(iface=interface, prn=self._handle_packet, store=False)
                sniffer.start()
                self._sniffers.append(sniffer)
            self._started = True
        except Exception as exc:
            self._disabled = True
            logger.warning("Packet collector disabled: %s", exc)

    async def collect(self) -> List[RawObservation]:
        self._ensure_started()
        observations = [
            RawObservation(source="packets", category="packet_summary", payload=item) for item in list(self._buffer)
        ]
        self._buffer.clear()
        return observations
