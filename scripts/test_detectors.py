#!/usr/bin/env python3
"""SIH26145 — Detector regression tests (no sudo / no netns required).

Run:  .venv/bin/python scripts/test_detectors.py
Each detector must fire on its synthetic attack and stay quiet on a benign
stand-in. Exit code 0 = all gates green (the WS-1/WS-2 acceptance floor).
"""
from __future__ import annotations

import math
import random
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.beacon import BeaconDetector            # noqa: E402
from detectors.dns_dga import DGADetector, parse_dns_query  # noqa: E402
from detectors.exfil import ExfilDetector              # noqa: E402
from detectors.tls import TLSPrototype, parse_client_hello  # noqa: E402
from detectors.volumetric import VolumetricDetector   # noqa: E402
from detectors import scan as scan_detector            # noqa: E402
from detectors import DetectorCoordinator             # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    tag = "OK " if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


def dns_query(name: str) -> bytes:
    hdr = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + qname + struct.pack(">HH", 1, 1)


def tls_hello(cipers: tuple = (0x1303, 0x1301, 0x1302)) -> bytes:
    cs = struct.pack(">H", len(cipers) * 2) + b"".join(struct.pack(">H", c) for c in cipers)
    # handshake: type(1) len(3) legacy_version(2) random(32) sid_len(1) + CS + ext
    body = (b"\x01\x00\x00\x31\x03\x04" + b"\x00" * 32 + b"\x00"
            + cs + b"\x00\x04\x00\x00\x00\x00")
    return b"\x16\x03\x04" + struct.pack(">H", len(body)) + body


def main() -> None:
    rng = random.Random(42)
    t0 = time.time() - 1000_000.0

    print("volumetric")
    v = VolumetricDetector()
    for _ in range(150):
        v.on_event({"tap": True, "window_id": 7, "src": "10.0.0.1", "proto": 17})
    check("quiet on stable sources", v.flush_window(0.0, 7) is None)
    # an ordinary many-host LAN: dozens of sources but each PERSISTS across the
    # window (the CICIDS benign trace shape) — must stay quiet
    for i in range(600):
        src = f"10.0.{i % 12}.5"
        v.on_event({"tap": True, "window_id": 7, "src": src, "proto": 17})
    check("quiet on many-host LAN (persistent sources)",
          v.flush_window(0.0, 7) is None)
    # the worst benign window the trace actually contains: 1356 distinct hosts
    # at 83% churn (one-shot fan-in ~1125) — a REAL internet window, must NOT
    # read as a flood (that was the regression most recently caught live)
    for _ in range(1356):
        src = f"172.{_ % 220}.{(_ // 220) % 255}.1"
        for rep in range((_ % 3) + 1):   # most hosts talk 1-3 frames -> 83% churn
            v.on_event({"tap": True, "window_id": 7, "src": src, "proto": 17})
    check("quiet on benign heavy-rotation burst (CICIDS 1356-host window)",
          v.flush_window(0.0, 7) is None)
    for _ in range(20000):
        s = "%d.%d.%d.%d" % tuple(rng.randrange(1, 255) for _ in range(4))
        v.on_event({"tap": True, "window_id": 8, "src": s, "proto": 17})
    row = v.flush_window(0.0, 8)
    check("fires on spoofed-source flood", (row or {}).get("score", 0) > 0.8)

    print("scan")
    check("quiet on narrow-cover traffic",
          scan_detector.on_event({"n_packets": 200, "n_dst_ports": 6,
                                  "duration_s": 2.0}) is None)
    row = scan_detector.on_event({"n_packets": 4000, "n_dst_ports": 3900,
                                  "duration_s": 2.0})
    check("fires on port fan-out", (row or {}).get("score", 0) > 0.5,
          f"score={ (row or {}).get('score') }")

    print("beacon")
    b = BeaconDetector()
    for i in range(120):
        b.on_event({"t": t0 + i * 1.0 + rng.uniform(-0.4, 0.4), "src": "10.0.0.9"})
    check("quiet on jittery cadence", b.flush_window(t0 + 130, 0) is None)
    b.reset()
    for i in range(240):
        b.on_event({"t": t0 + i * 0.5 + rng.uniform(-0.02, 0.02), "src": "10.0.0.9"})
    row = b.flush_window(t0 + 140, 1) or [{}]
    check("fires on metronome beacon", row[0].get("score", 0) > 0.8)

    print("exfil")
    e = ExfilDetector()
    for i in range(80):
        e.on_event({"t": t0 + i * 0.05, "src": "10.0.0.3", "size": 250})
    e.flush_window(t0 + 3, 0)
    for i in range(1500):
        e.on_event({"t": t0 + 3 + i * 0.002, "src": "10.0.0.3", "size": 1000})
    row = e.flush_window(t0 + 6, 1) or [{}]
    check("fires on byte-volume asymmetry", row[0].get("score", 0) > 0.6)

    print("dns_dga")
    d = DGADetector()
    for i in range(30):
        d.on_event({"t": t0 + i * 0.05, "src": "10.0.0.4",
                    "payload": dns_query(rng.choice(["www.api.com", "mail.org",
                                                     "login.net", "cdn.com"]))})
    check("quiet on dictionary DNS", (d.flush_window(t0 + 2, 0) or [{}])[0]
          .get("score", 0) < 0.4)
    # busy REAL production DNS (the window caught live at the 30-min mark):
    # 52 queries over ~3 s, 16% long names — high entropy, high rate, but NOT
    # a tunnel cluster; must stay quiet
    for i in range(52):
        # exactly ONE of the six forms is a long FQDN (~16% of the cluster)
        lbl = rng.choice(["ec2-52-52-166-141.eu-west-1.compute",  # >40 chars
                          "d3ag4hukkh62yn", "e16390.g.akamaiedge",
                          "lb-xy-17.example", "srv-pod-04",
                          "cdn-1611659974.edgecast"])
        d.on_event({"t": t0 + 8 + i * 0.06, "src": "52.52.166.141",
                    "payload": dns_query(lbl + ".amazonaws.com")})
    check("quiet on busy production DNS (16% long names)",
          (d.flush_window(t0 + 12, 1) or [{}])[0].get("score", 0) < 0.4)
    for i in range(60):
        # a ciphered DGA/tunnel cluster: long random labels push every FQDN
        # past LONG_QNAME, saturating long_frac — the ON gate for this detector
        lbl = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                      for _ in range(31))
        d.on_event({"t": t0 + 3 + i * 0.02, "src": "10.0.0.4",
                    "payload": dns_query(lbl + ".zzyxb.com")})
    row = d.flush_window(t0 + 5, 2) or [{}]
    check("fires on DGA qnames", row[0].get("score", 0) > 0.5)
    check("parse_dns_query accepts DNS bytes", parse_dns_query(dns_query("x.com")) is not None)
    check("parse_dns_query rejects junk", parse_dns_query(b"\xff\xff\xff") is None)

    print("tls (prototype)")
    t = TLSPrototype()
    t.on_event({"tap": True, "proto": 6, "dst_port": 443, "payload": tls_hello()})
    rows = t.flush_window(0.0, 0)
    check("clienthello parsed", parse_client_hello(tls_hello()) is not None)
    check("never alerts solo (score 0 policy)",
          all(r.get("score", 0) == 0 for r in rows))

    print("coordinator")
    c = DetectorCoordinator()
    seq = [[math.log1p(60), math.log1p(1e6), 2.0, 0.3]] * 50
    c2 = DetectorCoordinator()
    for i in range(300):
        c2.feed({"t": t0 + i * 0.5, "window_id": 0, "src": "10.0.0.7",
                 "proto": 17, "size": 60, "payload": b"x" * 60, "tap": False})
    rows = c2.flush(t0 + 160, 0)
    check("beacon alone escalates through coordinator",
          any(r["threat_class"] == "beacon" and r["score"] > 0.6 for r in rows))
    _ = seq, c

    print()
    if FAILURES:
        print(f"✘ {len(FAILURES)} FAILURES: {FAILURES}")
        sys.exit(1)
    print("✔ all detector gates green")


if __name__ == "__main__":
    main()