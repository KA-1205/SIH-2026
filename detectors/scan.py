"""Recon / port-scan detector.

A host that fans out SYN probes (or UDP/GRE probes) over a large spread of
distinct destination ports is either scanning for reachable services or probing
for filtering rules — the behaviour both firewalls and SIEM analysts treat as
pre-attack reconnaissance.

Evidence is estimated from window aggregates the live extractor already tracks
(n_packets, n_dst_ports, rate).  Unlike the volumetric detector this is usable
on the relay-visible stream: the UDP relay collapses source IPs onto the relay
address, but a spread of DESTINATION ports survives the rebuild, so a SYN-less
UDP scan still reads as scan behaviour on the loop side.

Thresholds (per 2-s window, single relay source):
  cover           = distinct ports / packets          per-port spread
  ports_per_s     = distinct ports per second
  pkts_per_port   = packets per distinct port         low == probe-per-port
"""
from __future__ import annotations

import math

SCAN_COVER_MIN = 0.5        # > 50% of packets hit a distinct port
SCAN_PORTS_PER_S = 80.0     # >= 2,400 distinct ports over 30 s
PKTS_PER_PORT_MAX = 3.0     # fewer than this packets per probed port
MIN_PORTS = 24
SECS = 2.0


def _est(ev: dict) -> dict | None:
    n = float(ev.get("n_packets") or 0)
    if n < 1:
        return None
    ports = float(ev.get("n_dst_ports") or 0)
    dur = max(float(ev.get("duration_s") or SECS), SECS)
    cover = min(1.0, ports / n)
    ports_s = ports / dur
    pkts_per_port = n / max(ports, 1.0)
    return {"cover": cover, "ports_s": ports_s, "pkts_per_port": pkts_per_port,
            "n": n, "ports": ports}


def on_event(ev: dict) -> None:
    est = _est(ev)
    if est is None:
        return None
    cover_ok = est["cover"] >= SCAN_COVER_MIN or est["ports"] >= MIN_PORTS
    rate_ok = est["ports_s"] >= SCAN_PORTS_PER_S
    per_port_ok = est["pkts_per_port"] <= PKTS_PER_PORT_MAX
    if not (cover_ok and rate_ok and per_port_ok):
        return None
    score = 0.45 * min(1.0, cover_ok * est["cover"] / SCAN_COVER_MIN)
    score += 0.35 * min(1.0, est["ports_s"] / (2 * SCAN_PORTS_PER_S))
    score += 0.20 * min(1.0, PKTS_PER_PORT_MAX / max(est["pkts_per_port"], 0.1))
    score = min(1.0, score)
    if score <= 0:
        return None
    why = (f"port-scan shape: {int(est['ports'])} distinct ports of {int(est['n'])} "
           f"pkts ({est['cover']:.0%} cover, {est['ports_s']:.0f}/s, "
           f"{est['pkts_per_port']:.1f} pkts/port)")
    return {"detector": "scan", "threat_class": "scan_recon", "score": score,
            "confidence": score, "features": {"n_packets": est["n"],
                                              "n_dst_ports": est["ports"],
                                              "cover": round(est["cover"], 3),
                                              "ports_per_s": round(est["ports_s"], 1),
                                              "pkts_per_port": round(est["pkts_per_port"], 2)},
            "why": why}


if __name__ == "__main__":
    import random
    rng = random.Random(7)
    benign = on_event({"n_packets": 200, "n_dst_ports": 6,
                       "duration_s": 2.0, "src": "10.1.1.2"})
    print("benign-web   :", None if benign is None else benign["score"])
    scan = on_event({"n_packets": 4000, "n_dst_ports": 3900,
                     "duration_s": 2.0, "src": "10.1.1.9"})
    print("hscan-udp    :", None if scan is None else round(scan["score"], 3),
          "—", scan["why"][:70] if scan else "")
    syn = on_event({"n_packets": 1500, "n_dst_ports": 1200,
                    "duration_s": 2.0, "src": "10.1.1.9"})
    print("syn-fanout   :", None if syn is None else round(syn["score"], 3))