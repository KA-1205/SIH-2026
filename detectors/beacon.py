#!/usr/bin/env python3
"""SIH26145 — C2 beaconing detector (inter-arrival regularity).

Bots phone home on a fixed rhythm. Real hosts have jittery cadences; a channel
whose inter-packet timing is TOO regular is the behavioural tell of a beacon,
visible even inside encrypted traffic, without decryption.

Implementation notes (read out loud when asked):
  * We measure the coefficient of variation (std/mean) of observed inter-
    arrival times. cv near zero == metronome == beacon signature.
  * "Near real-time" is a real constraint: a beacon with period > the window
    needs a long history buffer before it is detectable. We keep a rolling
    buffer of the last ~6 minutes so sub-minute and minute-scale beacons are
    caught while the window stays 3 s. Long-period beacons are the product
    trade-off we state honestly, not hide.
"""
from __future__ import annotations

from collections import deque
from statistics import mean, pstdev

from detectors.common import clip

NAME = "beacon"
THREAT_CLASS = "beacon"

MIN_SAMPLES = 40          # need enough IATs before the rhythm claim
BUFFER_MS = 6 * 60 * 1000 # rolling history window (6 min) per source
# cv must be this small *and* the mean in plausible beacon range
CV_FLOOR = 0.10
MEAN_LO_MS, MEAN_HI_MS = 60.0, 5000.0
CV_SCALE = 0.05


class BeaconDetector:
    def __init__(self) -> None:
        self._last: dict[str, deque[tuple[float, float]]] = {}

    def on_event(self, ev: dict) -> None:
        src = ev.get("src", "")
        t = ev.get("t", 0.0)
        self._last.setdefault(src, deque()).append((t, t))

    def _prune(self, src: str, now_ms: float) -> deque[tuple[float, float]]:
        buf = self._last.get(src)
        if buf is None:
            return deque()
        while buf and buf[0][0] * 1000 < now_ms - BUFFER_MS:
            buf.popleft()
        # keep only arrival times, already in insertion order
        return buf

    def flush_window(self, t: float, window_id: int) -> dict | None:
        now_ms = t * 1000
        rows = []
        for src in list(self._last):
            buf = self._prune(src, now_ms)
            if len(buf) < MIN_SAMPLES:
                continue
            # snapshot AFTER pruning: the tap thread appends concurrently, and
            # deque.append/popleft are thread-safe but ITERATION is not — this
            # was the RuntimeError that killed the 30-min soak mid-run
            ts = [e[0] for e in list(buf)]
            iats = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            iats = [d * 1e3 for d in iats if d > 0]
            if len(iats) < MIN_SAMPLES:
                continue
            mn, sd = mean(iats), pstdev(iats)
            if mn <= 0 or not (MEAN_LO_MS <= mn <= MEAN_HI_MS):
                continue
            cv = sd / mn
            if cv > CV_FLOOR:
                continue
            score = clip((CV_FLOOR - cv) / CV_SCALE)
            rows.append({
                "detector": NAME, "threat_class": THREAT_CLASS,
                "score": round(score, 3), "confidence": round(score, 3),
                "src": src,
                "features": {"period_ms": round(mn, 1),
                             "cv_iat": round(cv, 4),
                             "n_iat_samples": len(iats),
                             "history_s": round(BUFFER_MS / 1000),
                             "src": src},
                "why": f"phone-home rhythm every {mn:.0f} ms with cv={cv:.3f} "
                       "— a metronome, not a human or a machine with load",
            })
        return rows or None

    def reset(self) -> None:
        self._last.clear()


if __name__ == "__main__":
    import random
    t0 = 1_000_000.0
    d = BeaconDetector()
    # benign-ish: human/telemetry jitter
    rng = random.Random(3)
    for i in range(200):
        d.on_event({"t": t0 + i * 1.0 + rng.uniform(-0.4, 0.4), "src": "10.0.0.9"})
    print("jittery:", d.flush_window(t0 + 250, 0))
    d.reset()
    # beacon: exactly every 0.5 s with tight jitter
    for i in range(400):
        d.on_event({"t": t0 + 300 + i * 0.5 + rng.uniform(-0.02, 0.02),
                    "src": "10.0.0.9"})
    print("beacon:", d.flush_window(t0 + 550, 1))