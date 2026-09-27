# Operator console (frontend)

The console is a **TanStack Start** app (React 19 + TypeScript + Tailwind CSS v4
+ shadcn/ui + recharts) that reads live telemetry from the existing FastAPI
inference service. It replaced the earlier static `dashboard/` page; the backend,
APIs, models and data pipeline are unchanged.

## Stack

| Piece | Choice |
|---|---|
| Framework | TanStack Start (Vite 8) |
| UI | React 19, Tailwind CSS v4, shadcn/ui |
| Data | `@tanstack/react-query` + native `fetch` |
| Charts | recharts |
| Routing | `@tanstack/react-router` (file-based, `src/routes/`) |

## Layout

```
src/
  lib/api.ts        typed fetch client + API_BASE / WS_URL
  lib/queries.ts    react-query option factories (polling intervals live here)
  lib/system.ts     derives component status levels from /health, /stats, /meta
  hooks/useAlertStream.ts   WS /ws/alerts merged with polled /recent_alerts
  routes/           one file per page (index, events, analysis, network,
                    models, system, about) + __root.tsx app shell
  components/       shared UI (header, panels, charts, ui/* primitives)
  styles.css        all motion (CSS animations, disabled under
                    prefers-reduced-motion)
```

## Backend contract

All backend access goes through `src/lib/api.ts`; no component fetches directly,
so the API base and polling intervals stay in one place.

| Endpoint | Used for |
|---|---|
| `GET /health` | API status pill, uptime, device, windows scored |
| `GET /stats` | traffic summary counters, latency |
| `GET /trend` | fused-score time series |
| `GET /recent_alerts` | backfill for the live feed |
| `GET /coverage` | threat-class coverage matrix |
| `GET /meta` | model provenance, feature/class counts, diode proof |
| `WS /ws/alerts` | live scored windows (source of truth; polling is backfill) |

Rules the console follows:

- **No fabricated metrics.** Missing backend fields render `not reported` or an
  `Unavailable` / `Pending` state — never a made-up number.
- **Unknown ≠ healthy.** Component status is derived only from real responses;
  anything unrecognised renders `UNKNOWN`.
- **Motion is CSS-only** and disabled under `prefers-reduced-motion`.

## Configuration

The API base comes from `VITE_API_BASE_URL` (default `http://127.0.0.1:8200`).
Copy `.env.example` to `.env` to point the console at a different host. The
backend already allows cross-origin requests, so no proxy is required.

## Develop / build / run

```bash
npm install          # once
npm run dev          # dev server on :8080 (hot reload)
npm run build        # production build -> .output/
npm run lint         # eslint + prettier

make serve           # API :8200 + console (prod build if present, else dev)
make serve-dev       # API :8200 + console dev server :8080
make stop            # stop both
```

`scripts/serve.sh` starts the API and the console together and tracks their PIDs
in `data/run/`. In production mode it runs the built server with
`node .output/server/index.mjs` on `:8401`; in dev mode it runs `npm run dev` on
`:8080`. `scripts/shoot_dashboard.py` renders the console headlessly and
screenshots it at several widths for a quick visual check.
