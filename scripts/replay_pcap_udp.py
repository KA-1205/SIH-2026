#!/usr/bin/env python3
"""SIH26145 — replay a pcap's UDP PAYLOADS through the software-diode relay.

The relay (diode/relay.py send) forwards each datagram it receives on
127.0.0.1:10500 verbatim to the monitor side. This replayer is the capture-side
twin of attacks/generate.py: instead of synthesising traffic it reads real
packets and re-emits their UDP payloads to the relay socket at the original
inter-packet timing, so the live pipeline sees the same window structure the
model was trained on (a pcap replayed at 2x no longer preserves IAT features).

Only IPv4 UDP frames contribute: the diode is a UDP transport, so a packet the
relay could not carry never reaches the monitor.

Usage (inside ns-source):
  python scripts/replay_pcap_udp.py --pcap data/soak/fri_benign_udp_3min.pcap
"""
from __future__ import annotations

import argparse
import socket
import sys
import time

import dpkt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--dst", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10500)
    ap.add_argument("--multiplier", type=float, default=1.0,
                    help="1.0 preserves original timing (IAT-sensitive features)")
    ap.add_argument("--max-seconds", type=float, default=0.0, help="0 = whole file")
    args = ap.parse_args()

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (args.dst, args.port)
    sent = 0
    first_ts = None
    t_wall0 = None
    last_report = 0.0

    with open(args.pcap, "rb") as fh:
        try:
            cap = dpkt.pcap.Reader(fh)
        except ValueError:
            fh.seek(0)
            cap = dpkt.pcapng.Reader(fh)
        for ts, buf in cap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP) or ip.p != dpkt.ip.IP_PROTO_UDP:
                    continue
                payload = bytes(ip.data.data)
            except Exception:                                   # noqa: BLE001
                continue
            if first_ts is None:
                first_ts = ts
                t_wall0 = time.time()
            target = (ts - first_ts) / max(args.multiplier, 1e-6)
            wait = target - (time.time() - t_wall0)
            if wait > 0:
                time.sleep(wait)
            tx.sendto(payload, dst)
            sent += 1
            now = time.time()
            if now - last_report >= 5.0:
                last_report = now
                print(f"[replay] {sent} pkts, t+{target:.1f}s", flush=True)
            if args.max_seconds and target >= args.max_seconds:
                break

    print(f"[replay] done: {sent} UDP payloads -> {args.dst}:{args.port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())