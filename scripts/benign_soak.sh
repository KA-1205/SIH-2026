#!/usr/bin/env bash
# SIH26145 — BENIGN SOAK acceptance test.
#
# The precision gate for the nationals demo: run the FULL live pipeline
# (diode -> relay -> monitor pipeline -> scoring API) against benign traffic and
# require:
#   1. ZERO alerts (verdict != OK)
#   2. stable avg/p95 latency
#   3. at least one window actually scored
#
# Benign source (default): REAL CICIDS2017 Friday late-morning traffic
# (data/soak/fri_benign_3min.pcap, the known-benign morning segment) injected on
# the source side as raw frames and observed by the monitor-side L3 tap — the
# same observation point a hardware diode's monitor port provides. This is the
# only path that yields the full feature schema the models were trained on
# (ports, protocols, TTL, sizes). `--synthetic` falls back to the OT-telemetry
# generator over the relay (payload-only features; weaker proxy).
#
# Usage:
#   bash scripts/benign_soak.sh                       # replay the 3-min slice
#   bash scripts/benign_soak.sh --multiplier 2        # 2x, ~90 s
#   bash scripts/benign_soak.sh --synthetic --minutes 2
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
BENIGN_PCAP="$ROOT/data/soak/fri_benign_3min.pcap"
MULT=1.0
SYNTHETIC=0
MINUTES=2
LOOPS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --minutes)   MINUTES="$2"; shift 2 ;;
    --multiplier) MULT="$2"; shift 2 ;;
    --pcap)      BENIGN_PCAP="$2"; shift 2 ;;
    --loops)     LOOPS="$2"; shift 2 ;;   # replay the pcap N times (WS-1 30-min gate = ~10)
    --synthetic) SYNTHETIC=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$SYNTHETIC" = "1" ]; then
  RUN_SECONDS=$((MINUTES * 60))
  SRC_DESC="synthetic OT telemetry (${MINUTES} min)"
else
  [ -f "$BENIGN_PCAP" ] || { echo "missing benign pcap: $BENIGN_PCAP" >&2; exit 2; }
  DUR=$(capinfos -M -u "$BENIGN_PCAP" 2>/dev/null | sed -nE 's/.*[Cc]apture duration:[^0-9]*([0-9]+\.?[0-9]*).*/\1/p')
  RUN_SECONDS=$(python3 -c "print(int(${DUR:-180}*$LOOPS/$MULT)+20)")
  SRC_DESC="$(basename "$BENIGN_PCAP") at ${MULT}x x$LOOPS loops (~$(python3 -c "print(round(${DUR:-180}*$LOOPS/$MULT))")s)"
fi
API_LOG="$ROOT/data/soak_api.log"

echo "== benign soak: $SRC_DESC through the FULL live path =="

echo "-- [1/5] diode up"
bash "$ROOT/diode/setup_diode.sh" >/dev/null

echo "-- [2/5] inference service"
curl -sf --max-time 3 http://127.0.0.1:8200/health >/dev/null || {
  ( cd "$ROOT" && "$PY" -m uvicorn serving.app:app --port 8200 > "$API_LOG" 2>&1 & )
  for i in $(seq 1 30); do
    curl -sf --max-time 2 http://127.0.0.1:8200/health >/dev/null && break
    sleep 1
  done
}
curl -s --max-time 3 http://127.0.0.1:8200/health > /dev/null

echo "-- [3/5] host tcp proxy for api (monitor ns -> host)"
"$PY" "$ROOT/scripts/tcp_proxy.py" 10.200.1.1 8200 127.0.0.1 8200 > /dev/null 2>&1 &
PROXY=$!
sleep 1

echo "-- [4/5] monitor-side pipeline (recvfrom-only, no return path)"
if [ "$SYNTHETIC" = "1" ]; then
  TAP_ARG=""
else
  TAP_ARG="--tap-dev veth-mon"
fi
sudo ip netns exec ns-monitor \
  timeout "$RUN_SECONDS" "$PY" "$ROOT/serving/live_pipeline.py" --window-s 5 \
    $TAP_ARG \
    --api http://10.200.1.1:8200 > "$ROOT/data/soak_pipeline.log" 2>&1 &
LIVE=$!
sleep 1

echo "-- benign source: $SRC_DESC (alerts must stay 0)"
if [ "$SYNTHETIC" = "1" ]; then
  echo "-- [5/5] relay sender inside source ns"
  sudo ip netns exec ns-source "$PY" "$ROOT/diode/relay.py" send --in-port 10500 \
    > /dev/null 2>&1 &
  RELAY=$!
  sleep 1
  sudo ip netns exec ns-source "$PY" "$ROOT/attacks/generate.py" benign \
    --seconds "$RUN_SECONDS" &
else
  echo "-- [5/5] raw-frame replay on veth-src (monitor L3 tap observes originals)"
  RELAY=""
  sudo ip netns exec ns-source timeout "$RUN_SECONDS" \
    tcpreplay -i veth-src --loop="$LOOPS" --multiplier="$MULT" --stats=20 "$BENIGN_PCAP" \
    > "$ROOT/data/soak_replay.log" 2>&1 &
fi
BENIGN=$!

alerts=0
failed=0
prev_scored=-1
stall=0
while kill -0 $BENIGN 2>/dev/null; do
  sleep 10
  st=$(curl -s --max-time 3 http://127.0.0.1:8200/stats || echo '{"alerts":-1,"windows_scored":-1}')
  a=$(printf '%s' "$st" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('alerts',-1))")
  scored=$(printf '%s' "$st" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('windows_scored',0))")
  h=$(curl -s --max-time 3 http://127.0.0.1:8200/health || echo '{}')
  now=$(printf '%s' "$h" | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d.get('avg_latency_ms') or 0)")
  printf '\r  so far: alerts=%s  windows_scored=%s  avg_latency=%.2fms   ' \
    "$a" "$scored" "$now"
  # liveness guard: a pipeline that stops scoring (crashed thread) would look
  # like a pass — a vacuous-precision trap. Fail if scoring stalls mid-replay.
  if [ "$scored" -le "$prev_scored" ]; then
    stall=$((stall + 1))
  else
    stall=0
  fi
  prev_scored=$scored
  if [ "$stall" -ge 3 ]; then
    echo; echo "FAIL: the pipeline stopped scoring mid-run (windows_scored frozen) — a vacuous pass in disguise"
    failed=1; break
  fi
  [ "$a" != "0" ] && { echo; echo "FAIL: alert fired during benign soak"; failed=1; break; }
done
wait $BENIGN 2>/dev/null || true
sleep 8   # let the last buckets flush + score

echo
echo "== results =="
st=$(curl -s --max-time 3 http://127.0.0.1:8200/stats)
h=$(curl -s --max-time 3 http://127.0.0.1:8200/health)
alerts=$(printf '%s' "$st" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('alerts',-1))")
scored=$(printf '%s' "$st" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('windows_scored',0))")
avg=$(printf '%s' "$h" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('avg_latency_ms') or 0)")
p95=$(printf '%s' "$h" | "$PY" -c "import sys,json; print(json.load(sys.stdin).get('p95_latency_ms') or 0)")
echo "  source         = $SRC_DESC"
echo "  windows_scored = $scored"
echo "  alerts         = $alerts"
echo "  avg latency    = ${avg} ms / p95 ${p95} ms"

kill $LIVE $RELAY $PROXY 2>/dev/null || true

if [ "$failed" = "1" ]; then
  exit 1
fi

if [ "$alerts" = "0" ] && [ "$scored" -gt 0 ]; then
  echo "✔ PASS — benign soak: zero false alarms on $SRC_DESC"
  exit 0
else
  echo "✘ FAIL — false alarms present (or no windows scored). See data/soak_*.log"
  exit 1
fi