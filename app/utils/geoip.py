from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Dict


PRIVATE_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
]


def lookup_ip(ip: str) -> Dict[str, str]:
    try:
        address = ip_address(ip)
    except ValueError:
        return {"country": "UNKNOWN", "asn": "UNKNOWN", "classification": "invalid"}

    for network in PRIVATE_RANGES:
        if address in network:
            return {"country": "LOCAL", "asn": "PRIVATE", "classification": "internal"}

    first_octet = int(ip.split(".")[0])
    country = "US" if first_octet < 64 else "SG" if first_octet < 128 else "DE" if first_octet < 192 else "BR"
    return {"country": country, "asn": f"AS{first_octet * 100}", "classification": "external"}
