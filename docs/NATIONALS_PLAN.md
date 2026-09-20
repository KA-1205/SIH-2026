# SIH 2026 Nationals — Improvement Plan (12–24h Sprint)

> **SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (NTRO)**
> This is the plan for the NATIONAL round. It was stress-tested by a 5-advisor + 5-reviewer "council"
> (anonymized, adversarial, peer-reviewed). The plan below incorporates that verdict.
> Companion: `PROGRESS.md` (build log / source of truth), `docs/DECISIONS.md` (design rationale).

---

## 1. Where we are (read this in 30 seconds)

We already have a **complete, working, defensible system**:

```
software data diode (netns + iptables + one-way UDP relay, PROVEN zero reverse packets)
  → forward-only feature extractor (flow + source-bucket + sequence views; no bwd_* features exist)
  → hybrid ML detection (XGBoost, 15 CICIDS2017 classes + LSTM-Autoencoder for novel threats)
  → evidence fusion → FastAPI (~4ms/window) → live tactical dashboard
```

- 24 attack slices replayed through the real diode at **99.9% delivery**
- Macro-F1 **0.46**, binary ROC-AUC **0.91**; LSTM-AE two-sided AUC **0.80**
- Diode leak proof verified (`data/diode/proof/result.txt`, shown on the dashboard)
- Pretrained models committed (`models.tar.gz`, `models/artifacts/`)

**What is still weak for a national round:**

1. **False alarms:** at 95% attack recall we fire **53% false positives** — half our alerts are noise. A live audience watches alerts fire on benign traffic and stops trusting the whole system.
2. **Coverage:** 3 of the 6 threat classes named in the problem statement have **no dedicated detector yet** — DGA/DNS tunnelling, malware inside encrypted traffic (JA3/JA4), and botnet command-and-control beaconing.
3. **No measured throughput:** the problem demands a demonstrated throughput number (flows/s or Mbps). We have not printed one.
4. **No scripted demo or failsafe:** live generators can die mid-demo and the whole pitch goes with them.

---

## 2. The ONE Idea (what actually wins the round)

> **Don't chase six classes. Win on one provable, low-noise, explainable pipeline — demonstrated live, honestly.**

A national judge watches a ~10-minute demo. What convinces them is not "we detect more classes", it is:

- **The alert stream is clean** when traffic is benign (precision first),
- **Each alert shows its evidence** — click a spike and see *why* (entropy jump, beacon periodogram, byte-asymmetry chart),
- **Threats materialize live, on command**, while alerts stream to the dashboard on cue,
- **The diode's "cannot call back" property is proven live** — the literal NTRO mandate.

Everything else (docs, coverage matrix, extra detectors) is nice-to-have that must not eat demo time.

---

## 3. The Plan in Plain English (for the team)

Think of the diode as a one-way airlock: traffic flows **out of** the private network through a pipe that is physically incapable of sending anything back. We watch that pipe and flag six kinds of bad behavior the agency cares about.

### Our fixes, one line each:

| Fix | What it is | Plain-English analogy |
|---|---|---|
| **1. Precision push** | Add per-threat severity thresholds + demand *multiple* confirming signals before an alert fires; prove it with 30 min of pure benign traffic showing ZERO alarms. | A fire alarm that only rings on smoke **+ heat** together, not when the toaster gets warm. |
| **2. Volumetric flood detector** | Measure source-IP *entropy* per time bucket — detect a flood that fakes a million different senders. | Someone impersonating a whole crowd: the sudden "everyone at once, all different" pattern is the tell. |
| **3. Exfiltration detector** | Track outbound-vs-baseline byte volume per host. | A sensor that normally sends 50 bytes/sec suddenly pushing 500 KB out. |
| **4. Scan / recon detector** | Already good — reuse it; it stays. Fan-out to many ports = infiltrator door-testing. | |
| **5. C2 beacon detector** | Find bots that "phone home" on a regular rhythm (e.g. exactly every 47 s). | A worker tapping his watch at the same second, every single hour. |
| **6. DGA / DNS-tunnel detector** | Flag domain names that look machine-generated and DNS queries that smuggle data in packet sizes/entropy. | A spy writing a drop of ink into each of 10,000 balloons so no single one looks odd. Gated behind real prerequisites — timeboxed. |
| **7. TLS malware detector (JA3/JA4)** | Fingerprint the TLS handshake of encrypted traffic — catch malware borrowing the browser's TLS "typing style" — without ever decrypting anything. | Reading someone's handwriting on the envelope, never opening the letter. **ONLY if our tap actually sees handshakes — we audit this first.** |
| **8. Measured throughput** | Run one PCAP replay, print **flows/s + Mbps** on screen. | |
| **9. Live demo + failsafe** | Script all threats to fire live, in sequence, with a pre-recorded PCAP replay as warm backup if the live generators die. Rehearse the one-way probe. | A concert with a backing track: if the band fails, the show still goes on. |
| **10. Honest framing** | Label each detector's validation source on-screen ("simulated", "public dataset"). Script answers to hard questions. | Never claim something we can't prove in front of SIGINT people. |

### The alert we emit (the contract — this is the FIRST build task):

```json
{
  "timestamp":  1720000000000,          // epoch ms, capture-side clock
  "flow_id":    "10.0.2.7:51324 -> 8.8.8.8:53/UDP",
  "threat_class":"dns_tunneling",        // one of the 6 named classes (+anomaly)
  "verdict":     "HIGH",
  "threat_score": 0.87,
  "confidence":  0.91,                   // calibrated: "91% of alerts like this were real"
  "detector":    "dns_dga",
  "evidence": [{ "feature": "domain_entropy", "value": 4.2, "why": "entropy >> benign DNS" }],
  "latency_ms":  4.3
}
```

That exact record is the problem statement's own schema (timestamp, flow id, threat class, confidence, evidence). Everything — detectors, dashboard, demo — writes to it.

---

## 4. Engineering plan (workstreams, ordered to de-risk the demo)

### WS-0 — Freeze the alert schema + emit one compliant record  (~45 min) 🥇 FIRST
- Define the alert record exactly as in §3 (single source of truth in code, e.g. `serving/alert_schema.py`).
- Make the **existing** XGBoost + LSTM-AE path emit one compliant record end-to-end (add `threat_class`, `confidence`, structured `evidence[]`).
- `confidence` = a probability we can calibrate later; for now map scores via the fusion bands.

### WS-1 — Precision push (replaces the old "calibration" idea)  (~2–3 h)
- **Evidence gating in `fusion/score.py`:** per-threat-class thresholds; require a minimum evidence chain (classifier signal AND/OR sequence anomaly AND detector signal) before `verdict != OK`. This is the real FPR lever.
- **Benign-soak acceptance test:** `scripts/benign_soak.sh` — 30 min of benign traffic through the full pipeline; gate = **0 alerts, 0 API errors, stable latency**.
- Optional: isotonic calibration is a *communication* tool, not an FPR tool — use it only to make `confidence` mean what it says. Never to claim a lower false-alarm rate.

### WS-2 — Detectors, deterministic-first  (~6–8 h)
Order by robustness (pure feature logic, no training data needed first):
1. `detectors/volumetric.py` — source-IP entropy per bucket + reflection ratios (catches spoofed-source floods). Feature logic only.
2. `detectors/exfil.py` — outbound byte asymmetry vs per-host baseline. Feature logic only; **flag weak self-baseline** on screen.
3. `detectors/scan.py` (reuse existing bucket view) — port-spread fan-out.
4. `detectors/beacon.py` — FFT / inter-arrival regularity on a history buffer; honest long-history latency (that is the real product tradeoff — say it out loud).
5. `detectors/dns_dga.py` — domain entropy + n-gram + query-length/record-type features. Needs a DNS payload path + canonical DGA generator; **timeboxed to 90 min**, else fall back to entropy/n-gram on available DNS captures.
6. `detectors/tls.py` — JA3/JA3S (JA4). **AUDIT MIRROR DIRECTION FIRST.** If we never see ClientHello, downgrade TLS to explicit "prototype" and do not claim it.

All detectors output into the alert-schema record with their evidence slots. Add a `THREAT COVERAGE` panel to the dashboard mapping the 6 classes → detected/handled/prototype.

### WS-3 — Measured throughput + latency  (~1–2 h, run early)
- One script: replay X flows → print **flows/s** and **Mbps** through the real diode relay + pipeline; print **end-to-end alert latency** (ingest→extract→score→alert record, ms).
- Add a live **Mbps / flows/s** counter to the dashboard.

### WS-4 — Demo & pitch  (last ~4 h)
- 6-threat live schedule (benign soak → each threat on command → benign soak) via `scripts/live_demo.sh`.
- **Failsafe:** staged pre-recorded PCAP replay = warm spare (a demo never dies).
- **Return-path probe** segment: probe the monitor side for replies → nothing returns. Re-run `diode/verify_diode.sh` the morning of the demo.
- **Screen recording** + `docs/PITCH.md` (~10-min spoken script, judge-safe language, no insider jargon).

### Hour budget (nominal 24 h)

| H | Work |
|---|---|
| 0–1 | WS-0 schema freeze + one compliant record |
| 1–3 | WS-1 gating + benign soak |
| 3–8 | WS-2 volumetric → exfil → scan → beacon (JA3/JA4 + DGA gated/framed) |
| 8–11 | WS-2 remainder + WS-3 throughput/latency measured |
| 11–14 | detectors wired to live path + dashboard coverage panel (parallel agents) |
| 14–20 | WS-4 demo orchestration + failsafe + rehearsal + recording |
| 20–24 | PITCH.md, screen-record final, last-minute fixes |

**Rule:** if time runs out, drop a detector — **never** the alert pipeline, the gating, or the demo rehearsal.

---

## 5. The Pitch (for the hackathon)

### What it is (opening, 30 s)
"A passive AI observatory that sits behind a **one-way data diode** and watches traffic that the network can physically never pull back. It reads only what flows outward — never decrypts, never touches the source — and turns a raw byte stream into a structured, evidence-backed threat alert in milliseconds."

### How it improves (compared to our selection round / to typical entries)
1. **Precision over coverage:** half our alerts used to be false alarms; now the system sits through 30 minutes of normal traffic with **zero alarms**, and still catches every staged threat.
2. **Six named threat classes covered** — the exact classes your problem statement lists (volumetric, beaconing, DGA/DNS-tunnelling, encrypted-traffic malware, scanning, exfiltration) — each with its own detector and its own evidence chain.
3. **Proven, not asserted:** real numbers on the dashboard — flows/s, Mbps, ms per window.

### The WOW factor — what separates us from ~500 other teams
1. **Live attack orchestration.** We don't replay footage — we *fire attacks on command* during the demo, and the dashboard streams alerts on cue. Almost nobody else can do that.
2. **Proof of the one-way property, live.** We probe the monitor side and demonstrate *nothing comes back*. That's the literal heart of the NTRO problem — we show it, not just claim it.
3. **Every alert opens its evidence.** Not a black-box score: a click opens the actual feature that fired (entropy spike, beacon periodogram peak, byte-asymmetry chart). This is explainable AI in front of analysts whose entire job is trust.
4. **The "leave it running" flex.** We let the borderline-loader run against untouched benign traffic for 30 minutes and show a quiet board — unstaged proof beats any static slide.

### Anticipated judge questions (and our honest answers)
- **"Your attacks are self-generated — that's circular."**
  We evaluate on CICIDS2017 real labeled attacks through the same unidirectional extractor, and our generators rebuild *canonical public implementations* of real malware families (e.g. `baderj/domain_generation_algorithms`). Every detector labels its validation source on-screen: `simulated` vs `public-dataset`.
- **"JA3/JA4 needs the ClientHello — will your tap even see it?"**
  We audited mirror direction first; if handshakes are not visible we present TLS-malware as a prototype and lean on entropy/sequence analysis for that channel instead. We never over-claim.
- **"Software diode isn't the NTRO hardware diode."**
  Correct — we state that the diode is a faithful software emulation (proven zero-leak), and the extractor + detector + alert pipeline is the part that ports to the hardware tap. We measure and publish the relay's real numbers rather than hiding behind emulation.
- **"One-way means no NTP — do your timestamps drift?"**
  We timestamp at the capture point, on the host clock, and log ordering/delivery deltas; timestamps stay internally consistent.
- **"How fast is it?"**
  Live counter: X flows/s, Y Mbps, Z ms per window >10× inside your requirement.

---

## 6. Known risks & fail-safes

| Risk | Mitigation |
|---|---|
| Live generator dies / conference Wi-Fi fails | Pre-recorded PCAP replay as warm spare — demo never dies |
| FPR stays high under gating | Benign-soak gate is a hard Go/No-Go for the demo |
| RAM (5.8 GB) flow-state growth | Flow-state eviction/reaping; bounded deques everywhere |
| JA3/JA4 invisible (egress-only mirror) | Audit direction first; degrade to prototype + honest framing |
| One-way box clock drift | Capture-time timestamp + ordering delta logging |
| Detector slips schedule | Drop the detector, never the pipeline/gating/rehearsal |

---

## 7. Definitions of done (acceptance per workstream)

- **WS-0:** `POST /score` returns the compliant record; dashboard renders `threat_class` + `confidence` + `evidence[]`.
- **WS-1:** `scripts/benign_soak.sh` passes 30 min with **0 alerts**; gating threshold table in `fusion/score.py`.
- **WS-2:** each detector returns a record through the schema; THREAT COVERAGE panel shows 6/6 states.
- **WS-3:** `scripts/bench_throughput.sh` prints flows/s, Mbps, ms/window & end-to-end latency; counter on dashboard.
- **WS-4:** `scripts/live_demo.sh` runs the full 6-threat schedule twice; failsafe replay tested; screen recording saved; `docs/PITCH.md` written.