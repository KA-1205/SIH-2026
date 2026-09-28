#!/usr/bin/env python3
"""SIH26145 — FastAPI inference service.

Endpoints:
  GET  /health          model/artifact status
  POST /score           full-pipeline scoring of ONE window
                        {features: {...}, sequence?: [[...], ...]}
                        -> threat score + verdict + reasons (+ latency)
  POST /score_batch     list version
  GET  /recent_alerts   last N alert rows for the dashboard (poll)
  WS   /ws/alerts       live push channel (dashboard subscribes)

Latency is measured per request and averaged in /health — the number goes on a
slide ("low-latency detection in a constrained one-way environment").

Run: .venv/bin/uvicorn serving.app:app --host 127.0.0.1 --port 8200
"""
import asyncio
import json
import math
import os
import re
import time
from collections import Counter, deque
from pathlib import Path

# MUST be set before torch/xgboost are imported (they read it at import time).
#
# Starlette runs sync endpoints on a worker thread. libgomp creates a fresh
# OpenMP thread team for each foreign calling thread and, with the default active
# wait policy, that team spin-waits: the identical LSTM forward pass measured
# 0.26 ms on the main thread and 323 ms on a worker thread, so every /score
# request appeared to cost ~600 ms while the detector itself needed ~2 ms.
# Single-row inference wants one thread anyway, and pinning it makes the worker
# thread exactly as fast as the main thread.
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OMP_WAIT_POLICY", "passive")
os.environ.setdefault("MKL_NUM_THREADS", "1")

from fastapi import FastAPI, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field

ART = Path("models/artifacts")
sys_path = str(Path(__file__).resolve().parents[1])

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SIH26145 diode-IDS", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
_state: dict = {"xgb": None, "columns": None, "classes": None, "ae": None,
                "ae_cfg": None, "dev": "cpu", "lat_ms": deque(maxlen=200),
                "top_features": [], "n_scored": 0, "n_alerts": 0,
                "by_verdict": Counter(), "by_family": Counter(),
                "by_class": Counter(),
                "throughput": {"pkts": 0, "bytes": 0, "pkts_s": 0.0,
                               "mbps": 0.0, "t0": None, "twin": None,
                               "win_pkts": 0, "win_bytes": 0},
                "started": time.time()}
_alerts: deque = deque(maxlen=200)
_recent: deque = deque(maxlen=240)      # every scored window, for the trend chart
_ws_clients: set = set()
_demo_lock = asyncio.Lock()


class ScoreReq(BaseModel):
    features: dict = Field(default_factory=dict)
    sequence: list[list[float]] | None = None
    flow_id: str = ""
    detectors: list[dict] = Field(default_factory=list)
    win_pkts: float = 0
    win_bytes: float = 0


@app.on_event("startup")
async def load_models() -> None:
    import asyncio
    import joblib
    import sys
    # _broadcast runs on Starlette's sync worker threads, which have no event
    # loop of their own; hold the serving loop so it can post back to it.
    _state["loop"] = asyncio.get_running_loop()
    sys.path.insert(0, sys_path)
    if (ART / "xgb_model.joblib").exists():
        _state["xgb"] = joblib.load(ART / "xgb_model.joblib")
        # Single-row inference: an 8-thread pool costs more in fan-out/join than
        # the trees themselves, and it competes with the capture processes.
        try:
            _state["xgb"].set_params(n_jobs=1)
        except Exception:                      # noqa: BLE001
            pass
        _state["columns"] = json.loads((ART / "feature_columns.json").read_text())
        _state["classes"] = json.loads((ART / "label_classes.json").read_text())
        # Attribution names are read ONCE here. Reading them per /score request
        # (as an earlier revision did) put a synchronous file read on the hot
        # path that the latency figure is meant to measure.
        met = ART / "classical_metrics.json"
        if met.exists():
            feats = json.loads(met.read_text()).get("shap_top_features", [])
            _state["top_features"] = [f for f in feats
                                      if not str(f).startswith("(shap skipped")]
    cfg_f = ART / "lstm_ae_config.json"
    if cfg_f.exists() and (ART / "lstm_ae.pt").exists():
        import torch
        from models.lstm_ae import LSTMAE
        torch.set_num_threads(1)               # same rationale as xgb n_jobs=1
        cfg = json.loads(cfg_f.read_text())
        m = LSTMAE(feat_dim=cfg["feat_dim"])
        # weights_only=True: the checkpoint is a plain state_dict, so there is no
        # reason to let pickle execute arbitrary code while loading it.
        m.load_state_dict(torch.load(ART / "lstm_ae.pt", map_location="cpu",
                                     weights_only=True))
        m.eval()
        _state["ae"], _state["ae_cfg"] = m, cfg
        _state["dev"] = "cuda" if torch.cuda.is_available() else "cpu"
        # cache normalisation vectors as arrays so ae_error() does no per-request
        # list->ndarray conversion
        import numpy as np
        _state["ae_mu"] = np.asarray(cfg["mu"], dtype=np.float32)
        _state["ae_sd"] = np.asarray(cfg["sd"], dtype=np.float32)

    # read fusion weights once now, off the request path
    from fusion.score import load_config
    load_config(refresh=True)
    _warmup()


def _warmup() -> None:
    """Run one throwaway inference so the first real request is not the one that
    pays for XGBoost's thread-pool construction and torch's lazy init.

    Without this the first few /score calls measured hundreds of ms while steady
    state was ~4ms, which made the reported p95 meaningless.
    """
    try:
        if _state["columns"]:
            classify({c: 0.0 for c in _state["columns"]})
        if _state["ae"] is not None:
            ae_error([[0.0] * _state["ae_cfg"]["feat_dim"]]
                     * _state["ae_cfg"]["seq_len"])
    except Exception as e:                     # noqa: BLE001
        print(f"[warmup] skipped: {e}")
    _state["lat_ms"].clear()
    _state["n_scored"] = 0


def ae_error(seq) -> float | None:
    """Reconstruction error for one [T,F] sequence window."""
    if _state["ae"] is None or not seq:
        return None
    import numpy as np
    import torch
    cfg = _state["ae_cfg"]
    x = np.asarray(seq, dtype=np.float32)[-cfg["seq_len"]:]
    if x.shape[0] < cfg["seq_len"]:
        pad = np.tile(x[:1], (cfg["seq_len"] - x.shape[0], 1))
        x = np.vstack([pad, x])
    xn = (x - _state["ae_mu"]) / _state["ae_sd"]
    t = torch.tensor(xn[None], dtype=torch.float32)
    with torch.no_grad():
        r = _state["ae"](t)
    return float(((r - t) ** 2).mean())


def classify(features: dict) -> dict:
    if _state["xgb"] is None:
        return {"p_attack": 0.0, "pred_label": "", "top_attack": "",
                "class_probs": {}, "top_features": []}
    import numpy as np
    import pandas as pd
    row = {c: (float(features[c]) if c in features and features[c] is not None
               else float("nan"))
           for c in _state["columns"]}
    proba = _state["xgb"].predict_proba(pd.DataFrame([row]))[0]
    classes = _state["classes"]
    bi = classes.index("BENIGN")
    # P(any attack) = 1 - P(benign). Dividing by len(classes) here (as an earlier
    # revision did) capped the attainable score at 1/n_classes, so a 100%-certain
    # attack could never clear the fusion CRITICAL band.
    p_attack = float(1.0 - proba[bi])
    # Best non-benign hypothesis: what the window looks like IF it is an attack.
    # Reported separately so a benign verdict is never mislabelled with an attack
    # name, while an attack verdict still names the most likely family.
    att_order = [i for i in np.argsort(proba)[::-1] if i != bi]
    return {
        "p_attack": p_attack,
        "pred_label": classes[int(np.argmax(proba))],
        "top_attack": classes[att_order[0]] if att_order else "",
        "class_probs": {c: round(float(p), 4) for c, p in zip(classes, proba)},
        "top_features": _state["top_features"],
    }


def do_score(req: ScoreReq) -> dict:
    t0 = time.perf_counter()
    from fusion.score import fuse                      # repo-root import
    from serving.alert_schema import build_alert, classify_family
    c = classify(req.features)
    err = ae_error(req.sequence) if req.sequence else None
    out = fuse(c["p_attack"], err, c["top_attack"], c["top_features"],
               detector_rows=req.detectors)
    out["predicted_label"] = c["pred_label"] or "n/a"
    out["attack_family"] = c["top_attack"]
    out["threat_class"] = out.get("detected_class") or classify_family(c["top_attack"])
    out["class_probs"] = c["class_probs"]
    out["ae_error"] = round(err, 5) if err is not None else None
    out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    out["confidence"] = round(min(1.0, max(out["threat_score"],
                                           c["p_attack"], err or 0.0)), 3)
    evidence = [{"feature": "reason", "value": None, "why": r}
                for r in out.get("reasons", [])]
    for r in (req.detectors or []):
        if (r.get("score") or 0) <= 0:
            continue
        evidence.append({"feature": f"detector:{r.get('threat_class')}",
                         "value": r.get("score"),
                         "why": r.get("why") or "detector evidence"})
    if err is not None:
        evidence.append({"feature": "ae_recon_error", "value": out["ae_error"],
                         "why": "sequence deviation from benign baseline"})
    out["evidence"] = evidence
    latency = out.pop("latency_ms")
    score = out.pop("threat_score")
    verdict = out.pop("verdict")
    thr_cls = out.pop("threat_class")
    conf = out.pop("confidence")
    evidence = out.pop("evidence")
    out = build_alert(flow_id=req.flow_id, threat_class=thr_cls, verdict=verdict,
                      threat_score=score, confidence=conf, latency_ms=latency,
                      evidence=evidence, **out)
    _state["lat_ms"].append(latency)
    _state["n_scored"] += 1
    _update_throughput(req)
    _recent.append({"ts": time.time(), "threat_score": score, "verdict": verdict})
    return out


def _update_throughput(req: ScoreReq) -> None:
    """Tracks the packet/byte counts the extractor reports per window and keeps
    a decayed pkts/s + Mbit/s figure on /stats (no per-window ring buffer)."""
    pkts = max(0, int(req.win_pkts or 0))
    nbytes = max(0, int(req.win_bytes or 0))
    if not pkts:
        return
    th = _state["throughput"]
    now = time.time()
    th["pkts"] += pkts
    th["bytes"] += nbytes
    if th["t0"] is None:
        th["t0"] = now
        th["twin"] = now
        th["win_pkts"] = pkts
        th["win_bytes"] = nbytes
        return
    dt = now - th["twin"]
    if dt >= 1.0:
        alpha = 1.0 - math.exp(-dt / 5.0)       # 5 s decay constant
        inst_pkts = th["win_pkts"] / max(dt, 1e-6)
        inst_mbps = (th["win_bytes"] * 8) / max(dt, 1e-6) / 1e6
        th["pkts_s"] = th["pkts_s"] * (1 - alpha) + inst_pkts * alpha
        th["mbps"] = th["mbps"] * (1 - alpha) + inst_mbps * alpha
        th["twin"] = now
        th["win_pkts"] = pkts
        th["win_bytes"] = nbytes
    else:
        th["win_pkts"] += pkts
        th["win_bytes"] += nbytes


@app.post("/score")
def score(req: ScoreReq) -> dict:
    out = do_score(req)
    row = {"ts": time.time(), **out}
    _state["by_verdict"][out["verdict"]] += 1
    if out["verdict"] != "OK":
        _state["n_alerts"] += 1
        _state["by_family"][out.get("attack_family") or "unknown"] += 1
        _state["by_class"][out.get("threat_class") or "anomaly"] += 1
        _alerts.append(row)
    _broadcast(row)                # dashboard plots benign windows too
    return out


@app.post("/score_batch")
def score_batch(reqs: list[ScoreReq]) -> list[dict]:
    return [do_score(r) for r in reqs]


@app.post("/demo/reset")
async def reset_demo(request: Request) -> dict[str, str]:

    _state["n_scored"] = 0
    _state["n_alerts"] = 0
    _state["by_verdict"].clear()
    _state["by_family"].clear()
    _state["by_class"].clear()
    _state["lat_ms"].clear()
    _state["throughput"].update({
        "pkts": 0,
        "bytes": 0,
        "pkts_s": 0.0,
        "mbps": 0.0,
        "t0": None,
        "twin": None,
        "win_pkts": 0,
        "win_bytes": 0,
    })
    _alerts.clear()
    _recent.clear()
    _broadcast({"type": "reset"})
    return {"status": "reset"}


@app.post("/demo/run")
async def run_demo(request: Request) -> dict[str, str]:
    if _demo_lock.locked():
        raise HTTPException(status_code=409, detail="A simulation is already running")

    async with _demo_lock:
        import os, sys
        port = os.environ.get("PORT", "8200")
        api_url = f"http://127.0.0.1:{port}"
        
        try:
            process = await asyncio.create_subprocess_exec(
                ".venv/bin/python" if os.path.exists(".venv/bin/python") else "python",
                "scripts/drive_demo.py",
                "--api", api_url,
                cwd=sys_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"Unable to start drive_demo: {exc}") from exc

        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=90)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise HTTPException(status_code=504, detail="drive_demo timed out") from exc

        if process.returncode != 0:
            raise HTTPException(status_code=500, detail=f"drive_demo failed:\n{output.decode(errors='replace')}")

    return {"status": "complete"}


@app.get("/recent_alerts")
def recent(n: int = 25) -> list[dict]:
    return list(_alerts)[-n:]


@app.get("/trend")
def trend(n: int = 120) -> list[dict]:
    """Every scored window (benign included) for the score timeline."""
    return list(_recent)[-n:]


@app.get("/stats")
def stats() -> dict:
    """Verdict / attack-family tallies since start, for the summary tiles.

    Counts come from running totals, not from len(_alerts): that deque is a
    capped tail (200) and would silently stop counting during a long demo.
    """
    th = _state["throughput"]
    return {"windows_scored": _state["n_scored"],
            "alerts": _state["n_alerts"],
            "by_verdict": dict(_state["by_verdict"]),
            "by_family": dict(_state["by_family"]),
            "throughput": {"pkts_total": th["pkts"], "bytes_total": th["bytes"],
                           "pkts_s": round(th["pkts_s"], 1),
                           "mbps": round(th["mbps"], 3)},
            "latency_ms": {"avg": round(sum(_state["lat_ms"]) / len(_state["lat_ms"]), 3)
                           if _state["lat_ms"] else None,
                           "p95": round(sorted(_state["lat_ms"])
                                        [int(len(_state["lat_ms"]) * 0.95)], 3)
                           if _state["lat_ms"] else None}}


from detectors import COVERAGE as DETECTOR_COVERAGE


@app.get("/coverage")
def coverage() -> dict:
    """THREAT COVERAGE matrix for the dashboard: the six problem-statement
    classes, which detector handles each (production/prototype), and how many
    alerts of each class have fired this run."""
    by_class = dict(_state["by_class"])
    return {"classes": DETECTOR_COVERAGE, "alerts_by_class": by_class}


@app.get("/meta")
def meta() -> dict:
    """Static model + diode provenance the dashboard displays as evidence."""
    def _j(name: str) -> dict:
        f = ART / name
        return json.loads(f.read_text()) if f.exists() else {}

    clf, ae = _j("classical_metrics.json"), _j("ae_metrics.json")
    proof = Path("data/diode/proof/result.txt")
    # diode/verify_diode.sh writes e.g.
    #   forward frames received on monitor : 5 / 5 (135 bytes)
    #   bytes leaked monitor -> source     : 0 (PASS)
    # so parse the leak counter rather than string-matching prose.
    diode: dict = {"proof_present": proof.exists(), "zero_reverse_packets": None,
                   "leaked_bytes": None, "forward_delivery": None}
    if proof.exists():
        for line in proof.read_text().splitlines():
            low = line.lower()
            if "leaked" in low:
                m = re.search(r":\s*(\d+)", line)
                if m:
                    diode["leaked_bytes"] = int(m.group(1))
                    diode["zero_reverse_packets"] = int(m.group(1)) == 0
            elif "forward frames" in low:
                m = re.search(r"(\d+)\s*/\s*(\d+)", line)
                if m:
                    diode["forward_delivery"] = f"{m.group(1)}/{m.group(2)}"
        diode["checked_at"] = proof.read_text().splitlines()[0].split()[-1]
    return {
        "classes": _state["classes"] or [],
        "n_features": len(_state["columns"] or []),
        "classifier_metrics": {k: clf.get(k) for k in
                               ("macro_f1", "accuracy", "n_rows", "n_train", "n_test")},
        "per_class": clf.get("per_class", {}),
        "fpr_at_recall95": clf.get("fpr_at_recall0.95", {}),
        "autoencoder_metrics": ae,
        "top_features": _state["top_features"],
        "diode": diode,
    }


@app.get("/")
def root() -> dict:
    return {"status": "ok", "message": "SIH-2026 API is running", "docs": "/docs"}

@app.get("/health")
def health() -> dict:
    lat = sorted(_state["lat_ms"])
    return {
        "classifier": _state["xgb"] is not None,
        "autoencoder": _state["ae"] is not None,
        "device": _state["dev"],
        "windows_scored": _state["n_scored"],
        "uptime_s": round(time.time() - _state["started"], 1),
        "ws_clients": len(_ws_clients),
        "avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
        "p95_latency_ms": round(lat[min(int(len(lat) * 0.95), len(lat) - 1)], 2)
                          if lat else None,
    }


async def _ws_loop(ws: WebSocket):
    try:
        while True:
            await ws.receive_text()            # keepalive pings from dashboard
    except Exception:                          # noqa: BLE001
        pass
    finally:
        _ws_clients.discard(ws)


def _broadcast(row: dict) -> None:
    """Push one scored window to every dashboard socket.

    /score is a sync endpoint, so Starlette runs it in a worker thread where
    there is no running event loop -- the previous asyncio.get_event_loop()
    .create_task() call therefore raised on every alert and no client ever
    received anything. We keep a reference to the serving loop and hand the
    coroutine back to it thread-safely instead.
    """
    loop = _state.get("loop")
    if loop is None or not _ws_clients:
        return
    import asyncio
    for ws in list(_ws_clients):
        try:
            asyncio.run_coroutine_threadsafe(ws.send_json(row), loop)
        except Exception:                      # noqa: BLE001
            _ws_clients.discard(ws)


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    _ws_clients.add(ws)
    await _ws_loop(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8200)
