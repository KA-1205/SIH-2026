#!/usr/bin/env bash
# SIH26145 — start/stop the inference API and the operator console (frontend).
#
# The console is the TanStack Start app at the repo root. It is served either
# from the production build (.output/server/index.mjs, via node) or from the
# Vite dev server (npm run dev). Both talk to the FastAPI inference service on
# :8200 through VITE_API_BASE_URL (default http://127.0.0.1:8200).
#
# pkill -f <pattern> is deliberately NOT used here: the pattern matches the
# invoking shell's own command line, so it kills its own parent. PIDs are
# tracked in data/run/ instead.
#
# Usage: bash scripts/serve.sh start|stop|restart|status [dev|prod]
#   start        auto: production build if present, else dev server
#   start dev    force the Vite dev server (hot reload, port 8080)
#   start prod   force the production build (node, port 8401)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
RUN="$ROOT/data/run"
API_PORT=8200
DASH_PORT=8401
DEV_PORT=8080
mkdir -p "$RUN" "$ROOT/data"

_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

# The console build is only runnable with plain node when nitro used the
# node-server preset. Lovable's own deploy uses the cloudflare preset, so we
# detect rather than assume.
_build_is_node() {
  [ -f "$ROOT/.output/server/index.mjs" ] &&
    grep -q '"preset": *"node-server"' "$ROOT/.output/nitro.json" 2>/dev/null
}

_stop_one() {
  local pidf="$1" name="$2"
  if _alive "$pidf"; then
    local pid; pid="$(cat "$pidf")"
    # Kill the whole process group: the console may be an npm/vite tree whose
    # children outlive the parent if only the leader is signalled.
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    kill -9 -- "-$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null
    echo "  stopped $name (pid $pid)"
  else
    echo "  $name not running"
  fi
  rm -f "$pidf"
}

# Safety net: npm/vite can leave detached children holding the port even after
# the tracked PID is gone. Reap whatever still listens on the given port.
_free_port() {
  local port="$1" name="$2"
  if command -v fuser >/dev/null 2>&1; then
    if fuser -s "${port}/tcp" 2>/dev/null; then
      fuser -k "${port}/tcp" >/dev/null 2>&1
      sleep 0.5
      fuser -k -9 "${port}/tcp" >/dev/null 2>&1
      echo "  freed port $port ($name)"
    fi
  fi
}

start() {
  local mode="${1:-auto}"
  cd "$ROOT" || return 1
  if _alive "$RUN/api.pid"; then
    echo "  api already running (pid $(cat "$RUN/api.pid"))"
  else
    # Launch directly (no subshell) so $! is the real server PID, and setsid
    # detaches it into its own session so it survives this script exiting.
    setsid "$PY" -m uvicorn serving.app:app \
      --host 127.0.0.1 --port "$API_PORT" --log-level warning \
      > "$ROOT/data/api.log" 2>&1 &
    echo $! > "$RUN/api.pid"
    echo "  api    -> http://127.0.0.1:$API_PORT  (log data/api.log)"
  fi

  if _alive "$RUN/dash.pid"; then
    echo "  console already running (pid $(cat "$RUN/dash.pid"))"
  else
    # Resolve the serving mode: explicit dev/prod, else prefer a runnable build.
    if [ "$mode" = "auto" ]; then
      if _build_is_node; then mode="prod"; else mode="dev"; fi
    fi
    if [ "$mode" = "prod" ] && ! _build_is_node; then
      echo "  console: no node-server build found — run 'make frontend-build' first" >&2
      return 1
    fi
    if [ "$mode" = "prod" ]; then
      PORT="$DASH_PORT" HOST=127.0.0.1 setsid node .output/server/index.mjs \
        > "$ROOT/data/dash.log" 2>&1 &
      echo $! > "$RUN/dash.pid"
      echo "  console-> http://127.0.0.1:$DASH_PORT  (production build, log data/dash.log)"
    else
      setsid npm run dev -- --port "$DEV_PORT" --host 127.0.0.1 \
        > "$ROOT/data/dash.log" 2>&1 &
      echo $! > "$RUN/dash.pid"
      echo "  console-> http://127.0.0.1:$DEV_PORT  (vite dev server, log data/dash.log)"
    fi
  fi

  # Models load on first import, which can take a while on a cold start.
  for _ in $(seq 1 120); do
    curl -sf --max-time 2 "http://127.0.0.1:$API_PORT/health" >/dev/null && break
    sleep 0.5
  done
  status
}

stop() {
  _stop_one "$RUN/api.pid" api
  _stop_one "$RUN/dash.pid" console
  _free_port "$API_PORT" api
  _free_port "$DASH_PORT" console
  _free_port "$DEV_PORT" console
}

status() {
  local h
  h=$(curl -sf --max-time 3 "http://127.0.0.1:$API_PORT/health" || echo "")
  if [ -n "$h" ]; then echo "  health: $h"; else echo "  health: API NOT RESPONDING"; fi
  if _alive "$RUN/dash.pid"; then
    echo "  console: running (pid $(cat "$RUN/dash.pid"))"
  else
    echo "  console: not running"
  fi
}

case "${1:-start}" in
  start)   start "${2:-auto}" ;;
  stop)    stop ;;
  restart) stop; sleep 1; start "${2:-auto}" ;;
  status)  status ;;
  *) echo "usage: $0 start|stop|restart|status [dev|prod]"; exit 2 ;;
esac
