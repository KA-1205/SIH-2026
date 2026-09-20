#!/usr/bin/env python3
"""Driver for bench_throughput.sh — feeds realistic windows to /score.

Mode paced (default): fixed 25/s for `duration` seconds, measures achieved rate.
Mode burst: saturates a single connection with N requests back-to-back and
reports the scorer's capacity (no client-side pacing).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request

mode = sys.argv[1]
api = sys.argv[2]

cols = json.load(open("models/artifacts/feature_columns.json"))
feat = dict.fromkeys(cols, 0.0)
feat.update({"n_packets": 60, "bytes_total": 6e4, "rate_pkts_per_s": 600,
             "rate_bytes_per_s": 6e5, "duration_s": 0.1})


def one(k: int) -> None:
    body = json.dumps({"features": feat, "flow_id": f"bench-{k}",
                       "win_pkts": 60, "win_bytes": 60000}).encode()
    req = urllib.request.Request(api + "/score", data=body,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


if mode == "burst":
    n = int(sys.argv[3] if len(sys.argv) > 3 else 1000)
    t0 = time.time()
    for k in range(1, n + 1):
        one(k)
    el = time.time() - t0
    print(f"[bench] burst mode: {n} windows in {el:.2f}s -> {n / el:,.0f} "
          f"windows/s scorer capacity = {n / el * 60 * 8 / 1e6:,.1f} Mbit/s "
          f"equivalent (60 pkts x 1000 B per window)")
else:
    dur = float(mode)
    k = 0
    t0 = time.time()
    while time.time() - t0 < dur:
        k += 1
        one(k)
        time.sleep(0.04)
    el = time.time() - t0
    print(f"[bench] paced: {k} windows in {el:.1f}s -> {k / el:,.1f} windows/s "
          f"= {k / el * 60 * 8 / 1e6:,.3f} Mbit/s equivalent "
          f"(60 pkts x 1000 B per window)")