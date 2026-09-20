#!/usr/bin/env python3
"""SIH26145 — run the WS-2 detectors over a pcap and report every evidence row.

This is the offline twin of the live detector path: it exists to answer one
question honestly — do the deterministic detectors stay QUIET on known-benign
traffic? (The model-based strands cannot: see the benign soak logs.)

Usage:
  .venv/bin/python scripts/detector_soak_offline.py data/soak/fri_benign_3min.pcap
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detectors import scan as scan_detector            # noqa: E402
from detectors import DetectorCoordinator              # noqa: E402

WINDOW_S = 5.0


def main() -> int:
    pcap = sys.argv[1] if len(sys.argv) > 1 else "data/soak/fri_benign_3min.pcap"
    coord = DetectorCoordinator()
    rows: list[dict] = []
    per_window: dict[int, dict] = {}
    n = 0

    fh = open(pcap, "rb")
    try:
        cap = dpkt.pcap.Reader(fh)
        is_pcap = True
    except ValueError:
        fh.seek(0)
        cap = dpkt.pcapng.Reader(fh)
        is_pcap = False
    _ = is_pcap

    first = None
    last_flush = -1
    for ts, buf in cap:
        if first is None:
            first = ts
            last_flush = int(ts // WINDOW_S)
        wid = int(ts // WINDOW_S)
        if wid > last_flush:
            for w in range(last_flush + 1, wid):
                rows.extend(coord.flush(w * WINDOW_S, w))
            last_flush = wid
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            payload, dport = b"", 0
            if ip.p == 17 and isinstance(ip.data, dpkt.udp.UDP):
                dport, payload = ip.data.dport, bytes(ip.data.data)
            elif ip.p == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                dport, payload = ip.data.dport, bytes(ip.data.data)
            elif ip.p == 1:
                payload = bytes(ip.data)
            src = ".".join(map(str, ip.src))
            dst = ".".join(map(str, ip.dst))
            coord.feed({"t": ts, "window_id": wid, "src": src, "dst_ip": dst,
                        "dst_port": dport, "proto": ip.p, "size": len(ip),
                        "payload": payload, "tap": True})
            agg = per_window.setdefault(wid, {"n": 0, "ports": set(), "bytes": 0,
                                              "dur": 0.0, "t0": ts, "tl": ts})
            agg["n"] += 1
            agg["bytes"] += len(ip)
            agg["ports"].add(dport)
            agg["tl"] = ts
            if len(agg["ports"]) < 4096:
                pass
        except Exception:                                   # noqa: BLE001
            continue
        n += 1

    for w in range(last_flush, last_flush + 2):
        rows.extend(coord.flush(w * WINDOW_S, w))

    # bucket-shape scan detector over the same windows
    for wid, agg in per_window.items():
        row = scan_detector.on_event({"n_packets": agg["n"],
                                      "n_dst_ports": len(agg["ports"]),
                                      "duration_s": max(agg["tl"] - agg["t0"], WINDOW_S),
                                      "src": f"win{wid}"})
        if row:
            rows.append(row)

    print(f"packets parsed: {n:,}   windows: {len(per_window):,}")
    hits = Counter(r["threat_class"] for r in rows)
    print(f"detector evidence rows (>= min_score): {len(rows)}")
    for cls, c in hits.most_common():
        ex = next(r for r in rows if r["threat_class"] == cls)
        print(f"  {cls:14s} {c:5d}   e.g. score={ex['score']:.2f}  {ex.get('why','')[:70]}")
    if not rows:
        print("  (none — detectors stayed silent on this benign capture)")
    return 0 if not rows else 1


if __name__ == "__main__":
    sys.exit(main())