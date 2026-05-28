from __future__ import annotations

import argparse

from scapy.all import IP, ICMP, TCP, UDP, send  # type: ignore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--mode", choices=["syn", "udp", "icmp"], default="syn")
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()

    if args.mode == "syn":
        packet = IP(dst=args.target) / TCP(dport=range(20, 120), flags="S")
    elif args.mode == "udp":
        packet = IP(dst=args.target) / UDP(dport=53)
    else:
        packet = IP(dst=args.target) / ICMP()
    send(packet, count=args.count, verbose=False)


if __name__ == "__main__":
    main()
