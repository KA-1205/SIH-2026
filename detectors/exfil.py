#!/usr/bin/env python3
"""SIH26145 — Data-exfiltration detector (outbound byte-volume asymmetry).

Tracks each source's observed egress rate and compares the CURRENT window rate
to that source's own slow-moving baseline. A machine that suddenly pushes
megabytes outward while its baseline is kilobytes is the textbook exfil shape.

IMPORTANT (honest framing): the baseline is derived from this source's own
recent history, and in a demo the "benign" baseline is our own telemetry. The
wavefront's `why` field says so. It is a strong RELATIVE signal, not an
absolute characterization of exfiltration.
"""
from __future__ import annotations

from detectors.common import sigmoid, clip

NAME = "exfil"
THREAT_CLASS = "exfiltration"

ALPHA = 0.10                  # EMA smoothing per window
# fire only when the rate is genuinely large AND many multiples of baseline
MIN_RATE_BPS = 50000          # 50 KB/s sustained
RATE_RATIO = 3.0              # current/baseline must clear this
MIN_BYTES = 200_000           # total moved in the window
SCORE_SCALE = 4.0             # ratio normalized at ~4x above threshold


class ExfilDetector:
    def __init__(self) -> None:
        self._baseline: dict[str, float] = {}
        self._cur: dict[str, dict] = {}

    def on_event(self, ev: dict) -> None:
        src = ev.get("src", "")
        if ev.get("tap") and ev.get("proto") == 6:
            return  # TCP egress on the tap is raw-capture territory; skip
        self._cur.setdefault(src, {"bytes": 0, "t0": ev.get("t", 0.0),
                                   "tl": ev.get("t", 0.0)})
        c = self._cur[src]
        c["bytes"] += ev.get("size", 0)
        c["tl"] = ev.get("t", c["tl"])

    def flush_window(self, t: float, window_id: int) -> dict | None:
        rows = []
        # The tap thread feeds on_event() while we flush from the window thread
        # — iterate over a snapshot so a mid-window new source can't raise.
        for src, c in list(self._cur.items()):
            dur = max(0.5, c["tl"] - c["t0"])
            rate = c["bytes"] / dur
            old = self._baseline.get(src, 0.0)
            score = 0.0
            features = {
                "window_bytes": c["bytes"],
                "rate_bps": round(rate, 1),
                "baseline_bps": round(old, 1),
                "ratio_vs_baseline": round(rate / old, 2) if old > 0 else None,
            }
            why = None
            if rate >= MIN_RATE_BPS and c["bytes"] >= MIN_BYTES and old > 0 \
                    and rate / old >= RATE_RATIO:
                score = clip(sigmoid((rate / old - RATE_RATIO) / SCORE_SCALE))
                why = (f"egress rate {rate / 1024:.0f} KB/s is "
                       f"{rate / old:.1f}x this source's own baseline "
                       f"({old / 1024:.0f} KB/s) — byte-volume asymmetry")
            # keep the EMA even when quiet, so a sudden spike is a real jump
            self._baseline[src] = (1 - ALPHA) * old + ALPHA * rate
            if score > 0:
                rows.append({"detector": NAME, "threat_class": THREAT_CLASS,
                             "score": round(score, 3),
                             "confidence": round(score, 3),
                             "features": features, "why": why})
        self._cur = {}
        return rows or None

    def reset(self) -> None:
        self._baseline.clear()
        self._cur.clear()


if __name__ == "__main__":
    import time
    d = ExfilDetector()
    t = time.time()
    # benign: steady 5 KB/s
    for i in range(60):
        d.on_event({"t": t + i * 0.05, "src": "10.0.0.3", "size": 250})
    print("benign window:", d.flush_window(t + 3, 0))
    for i in range(60):
        d.on_event({"t": t + i * 0.05, "src": "10.0.0.3", "size": 250})
    print("benign window2:", d.flush_window(t + 6, 1))
    # exfil: 2 MB in the same 3s
    for i in range(2000):
        d.on_event({"t": t + 6 + i * 0.0015, "src": "10.0.0.3", "size": 1000})
    print("exfil window:", d.flush_window(t + 9, 2))