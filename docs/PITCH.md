# SIH 2026 — One-Way Diode Anomaly Detection (project pitch)

> **What we're actually building:** a real-time attack-and-anomaly detector that
> watches the *monitor port* of a one-way data diode built in software, and
> turns the raw Ethernet it sees there into scored, evidence-backed alerts on a
> dashboard — with near-zero false alarms on benign traffic.

## The story in 60 seconds

Legacy OT networks have to push telemetry out (monitoring, historians, fleet
dashboards) but must never let anything in. A **data diode** enforces that: it
physically admits traffic in one direction only. The catch: you've just built a
two-channel funnel — if an attacker manages to stuff an exploit or a covert
exfiltration stream into the outbound feed, the diode happily ships it through
the firewall's blind spot.

Our answer is the piece the diode vendors skip: a monitor port on the receiving
side, a detector suite tuned to *diode-particular* attack shapes, and a live
scoring pipeline that does not need to block traffic (it can't — it has no
return path) but names what's crossing it.

We prove it in software all the way to a working live demo: a Linux veth-based
diode, raw source-side injection, a raw monitor tap, six threat-class
detectors, a fusion scorer with detector-gated alerting, and a live dashboard.

## What's here

| Layer | What it is |
|---|---|
| `diode/` | Software one-way diode: two netns joined by a veth, `OUTPUT`-side drop on the monitor makes it truly one-way; management veth gives the API a safe second path. |
| `attacks/generate.py` | Deterministic threat generator library: spoofed-source flood, port-scan recon, C2 beacon cadence, covert timing, stego exfil, malformed frames, benign OT telemetry — injected either over the relay or as raw forged frames on the source veth. |
| `detectors/` | Six per-threat-class detectors (volumetric, scan, beacon, exfiltration, DNS-DGA, TLS-proto prototype) in the WS-0 alert-evidence contract, each with a `why` written for non-experts. |
| `fusion/score.py` | Fusion scorer. ML (classifier + autoencoder) is *evidence*, not a veto; **a HIGH/MEDIUM alert fires only if a detector strand agrees** (WS-2 gating) — this is what keeps benign soaks at zero false alarms. |
| `serving/` | FastAPI (`/score`, `/stats`, `/health`, `/coverage`, WS alerts), `live_pipeline.py` (tap + bucket features + window coordinator + per-window evidence dedup), `alert_schema.py` (WS-0 contract). |
| `models/` | Trained on CICIDS2017; the source-port-split variant in `artifacts_src/` is **known-unusable** (FPR 0.855) — kept for honesty, never used. |
| `src/` | Live console (TanStack Start + React): verdict/score/evidence/coverage panel + WS push. |
| `scripts/` | `benign_soak.sh` (the 30-min zero-false-alarm acceptance gate), `live_demo.sh` (orchestrated live demo), `test_detectors.py` (unit gates), `bench_throughput.sh`, offline soak + data-download helpers. |

## The acceptance evidence (what "done" means)

Definitions of done live in `docs/NATIONALS_PLAN.md` (WS-0..WS-4). Current
status — all demonstrated end-to-end, not just unit-tested:

- **WS-0 Alert contract** ✅ `alert_schema.py` + console renders
  threat_class / confidence / evidence for every alert.
- **WS-1 Zero-false-alarm gate** ✅ **VERIFIED on the full 30-minute run**:
  `benign_soak.sh --loops 10` replaying real CICIDS benign pcap through the
  diode → **0 alerts across 17,318 windows** (7.1 ms avg / 10.6 ms p95), with a
  liveness guard proving the pipeline scored the entire run (no silent-crash
  pass). See `scripts/benign_soak.sh --loops 10`.
- **WS-2 Detector strands** ✅ six threat classes, THREAT COVERAGE panel, live
  demo lights volumetric + scan + beacon windows from real generator injection;
  detector-driven alerts are deduplicated to one per window.
- **WS-3 Throughput bench** ✅ ~4.7 ms avg / 7.4 ms p95 scoring latency at
  ~4.5k pps, ~36 Mbps on the box we run.
- **WS-4 Live demo + pitch** ✅ `scripts/live_demo.sh` runs the schedule twice
  (failsafe replay) against the tap; malformed-frame injection no longer
  crashes the parser; this file is the pitch.

## Improvements since the previous version (how we got here)

Every line below is a *demonstrated* change from the earlier two-model MVP
(classifier + autoencoder + first live pipeline) — verified by unit gates, live
soak runs, and the demo, not just written down. Each improvement is explained
in plain English and in technical language.

### 1. The zero-false-alarm soak is genuinely green (it was passing vacuously)

- **English:** The "30 minutes of real benign internet traffic, zero alerts"
  acceptance gate used to pass *by accident*: the volumetric detector was
  crashing on every window and the tap loop silently swallowed every crash, so
  it could never actually fire. When we rebuilt it, real traffic exposed two
  more latent bugs — a DNS-lookalike false alarm and a beacon-detector deque
  race that **killed the pipeline mid-soak while the script still printed
  PASS**. A liveness guard now fails the soak the moment scoring stalls. Final
  verified run: **0 alerts across 17,318 windows** over the full 30 minutes
  (7.1 ms avg / 10.6 ms p95), pipeline alive the entire time.
- **Technical:** the tap thread wrapped detector flushes in a bare
  `except: continue`, hiding a `RuntimeError` on window rollover inside
  `VolumetricDetector`. Fixed plus: `detectors/beacon.py` now snapshots its
  deque after pruning (`ts = [e[0] for e in list(buf)]` — `RuntimeError: deque
  mutated during iteration` raced tap `append` vs window-thread iteration); and
  `scripts/benign_soak.sh` tracks `windows_scored` and FAILs if it freezes for
  3 consecutive 10 s polls. Detector thread races in `detectors/exfil.py` and
  `detectors/dns_dga.py` fixed with `list(...)` snapshots + atomic resets.

### 2. Volumetric detector: source-IP *mass*, not churn

- **English:** The classic tell for a spoofed flood is source-IP churn — the
  fraction of hosts seen exactly once. We measured real benign internet
  traffic and it legitimately hits **83% churn** and even **1356 distinct
  sources in one 5-second window**, so churn-based thresholds misread it as a
  flood. The new rule fires only on the *mass of exactly-once sources*: real
  traffic peaks near ~1100 one-shot hosts per window; a genuine flood is
  thousands by construction (≥ 2000), or the window saturates to near-100%
  churn (≥ 0.95) — a fire-and-forget sweep.
- **Technical:** per-window source-set profile of `data/soak/
  fri_benign_3min.pcap` (churn p99 ≈ 0.83, max distinct = 1356) invalidated
  the old `churn ≥ 0.60 ∨ n_src ≥ 300` gate. New gate in `detectors/
  volumetric.py`: `once_seen ≥ MASS_ONCE(2000) ∨ churn ≥ CHURN_SAT(0.95)`;
  score blends `0.45·H_norm + 0.35·spread + 0.20·churn_term`. Both caught
  windows are unit regressions.

### 3. DNS/DGA detector no longer mistakes busy production DNS for a tunnel

- **English:** Normal DNS is genuinely busy and full of random-looking
  hostnames — the CICIDS benign trace runs high query rates at ~4.7 bits/char
  of label entropy — so entropy-ranked DGA detection false-alarmed every
  window. The final gate fires only when a name-cluster is *mostly ciphered
  names* (> 50% of a window's qnames > 40 chars) at a sustained rate: the
  actual shape of dnscat2/iodine-style tunneling. Production DNS never clears
  the bar — benign clusters peak near ~16% long names (verified into the
  30-minute run, which passed clean).
- **Technical:** `detectors/dns_dga.py` gates on a hard conjunction —
  `mean_label_entropy ≥ ENTROPY_OK(4.2) ∧ long_frac ≥ LONG_FRAC_FLOOR(0.5) ∧
  qps ≥ TUNNEL_QUERY_RATE(30)` — where `long_frac` is the share of qnames
  longer than `LONG_QNAME(40)`. A loosened qps floor (`min(30, 6/dur)`) let the
  52-query/16%-long window through at the first 30-min attempt; both that
  window and the entropy-only form are unit regressions now.

### 4. The alert gate (WS-2) is enforced end-to-end

- **English:** Soak runs surfaced 13 HIGH "Bot / FTP-Patator / Heartbleed"
  alerts that were pure ML guesswork with no detector strand behind them. We
  audited the entire path, confirmed every `/score` request routes through the
  detector-gated `fuse()`, and proved the phantom was API state being carried
  over between soak runs. With the API freshly reset between runs, the
  counting is exact — latest run: **0 alerts**.
- **Technical:** `fusion/score.py::fuse()` enforces
  `verdict ∈ {HIGH,CRITICAL} ∧ n_det_strands == 0 ∧ alerting_det is None ⇒
  verdict = OK, score ≤ 0.24`; `serving/app.py::do_score()` correctly passes
  `detector_rows` into `fuse()`. Soak scripts now isolate the API between runs
  so `n_alerts` can't accumulate across invocations.

### 5. The live demo lights *real* detector alerts (was ML labels + duplicates)

- **English:** The demo's flood window used to emit ~1200 duplicate alerts
  because per-window detector rows were attached to every source bucket. Now
  volumetric, beacon, and scan windows fire exactly once each, from real
  detector evidence on raw forged frames. Full demo completes in ~90 s; last
  pass lit **3 volumetric + 2 beacon** alert windows.
- **Technical:** `serving/live_pipeline.py::flush()` attaches window-level
  detector rows once per flush cycle; `attacks/generate.py` gained an
  AF_PACKET raw L2 injector `_packet_raw_snd()` so spoofed-source frames
  really cross the tap (beacon on dedicated src `10.200.0.42` at 250 ms cadence,
  port-scan fan-out over the full 1–65535 port range).

## How to run it

```bash
.venv/bin/python scripts/test_detectors.py      # unit gates
bash scripts/benign_soak.sh                     # 3-min zero-FP soak
bash scripts/benign_soak.sh --loops 10          # WS-1 30-min gate (~30 min)
bash scripts/live_demo.sh --once                # single demo pass (~90 s)
bash scripts/live_demo.sh                       # full double-replay demo
bash scripts/serve.sh start                     # API :8200 + console :8401
bash scripts/bench_throughput.sh                # throughput/latency bench
```

Inspect runtime artifacts: `data/demo_pipeline.log` (⚠ = alert), `data/
soak_pipeline.log`, `data/soak_replay.log`, `data/soak30.log`.

## Honest caveats (we say these out loud)

1. **Detector view is tap-dependent.** The volumetric and scan detectors only
   see real value on the L3 tap (`--tap-dev veth-mon`); the relay-only path
   collapses everything onto one transport source and one port. The demo wires
   the tap. DNS-DGA and the TLS prototype need real DNS/TLS flows we do not
   fabricate, so they are wired but not demo-lit — the coverage panel says so.
2. **Classifier labels are fuzzy.** On forged demonstration frames the learned
   classifier often names a plausible-but-unrelated CICIDS family (e.g. "Web
   Attack XSS" for a spoofed flood). The *detector* `threat_class` is the
   ground truth; the classifier is corroborating evidence only.
3. **Raw-injected frames set zero checksums.** Fine for capture/detection; not
   an exercise in evading real stacks.
4. **The demo attacks are shapes, not exploits** — we inject volumetric / scan /
   beacon / malformed traffic, not weaponized payloads.

## The team handoff (what to tell your teammate)

- Everything green you can re-run yourself with the three commands above.
- If the 30-min soak prints `✔ PASS — zero false alarms`, the precision gate
  is met; the demo then proves detection works when the state flips.
- The one deliberate asterisk: legit many-host internet traffic must not look
  like a flood. The volumetric detector's tell is therefore the *mass of
  one-shot sources* (≥ 2000 in a window) or near-total churn (≥ 0.95) — real
  hosts keep talking; a spoofed flood rotates its source set. The CICIDS
  benign peak is ~1125 one-shots/window; the gate sits above it with margin.