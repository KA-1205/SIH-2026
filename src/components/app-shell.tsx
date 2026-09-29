import { Link } from "@tanstack/react-router";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";

import { API_BASE, type Health } from "@/lib/api";
import { healthQuery } from "@/lib/queries";
import { fmtUptime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SimulationButton } from "./simulation-button";
import { StatusDot, statusLabel, type StatusLevel } from "./primitives";

const NAV = [
  { to: "/", label: "Overview", accent: "var(--accent-overview)" },
  { to: "/events", label: "Live Traffic", accent: "var(--accent-events)" },
  { to: "/analysis", label: "Threat Detection", accent: "var(--accent-analysis)" },
  { to: "/network", label: "Traffic Analytics", accent: "var(--accent-network)" },
  { to: "/models", label: "Detection Models", accent: "var(--accent-models)" },
  { to: "/system", label: "System Health", accent: "var(--accent-system)" },
  { to: "/about", label: "About", accent: "var(--accent-about)" },
] as const;
function StartupLoader({ health }: { health: UseQueryResult<Health, Error> }) {
  const isBooting = health.isPending || health.isError;
  const retryCount = health.failureCount > 0 ? health.failureCount : 0;

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <div className="w-full max-w-2xl rounded-2xl border border-border bg-surface p-6 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] sm:p-8">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-primary/40 bg-primary/10 text-lg font-semibold text-primary">
            SS
          </div>
          <div>
            <p className="tech text-[0.6875rem] uppercase tracking-[0.2em] text-muted-foreground">
              SIH 2026 demo
            </p>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Sanchar Saṅgaṇaka</h1>
          </div>
        </div>

        <div className="space-y-4 border-l border-border pl-4">
          <p className="tech text-[0.6875rem] uppercase tracking-[0.2em] text-muted-foreground">
            Team HarTimeError
          </p>
          <p className="tech text-[0.75rem] text-muted-foreground">PS 26145</p>
          <p className="text-sm text-muted-foreground">
            AI-based detection of cyber threats in unidirectional IP traffic.
          </p>
        </div>

        <div className="mt-8 rounded-xl border border-border bg-background/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span
                className="inline-block h-3 w-3 animate-pulse rounded-full bg-primary"
                aria-hidden
              />
              <span className="tech text-[0.75rem] uppercase tracking-[0.14em] text-muted-foreground">
                {isBooting ? "Booting pipeline" : "Ready"}
              </span>
            </div>
            <span className="tech text-[0.6875rem] text-muted-foreground">{API_BASE}</span>
          </div>

          <div className="mt-4 flex items-center gap-3">
            <div
              className="h-10 w-10 rounded-full border border-primary/40 border-t-primary animate-spin"
              aria-hidden
            />
            <div>
              <p className="text-lg font-medium">Demo loading…</p>
              <p className="tech text-[0.75rem] text-muted-foreground">
                {retryCount > 0
                  ? `Retrying backend startup (${retryCount} attempts so far)...`
                  : "Warming the live inference service…"}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const health = useQuery(healthQuery);
  const [showStartupScreen, setShowStartupScreen] = useState(true);

  useEffect(() => {
    if (!health.isSuccess) {
      setShowStartupScreen(true);
      return;
    }

    const timer = globalThis.setTimeout(() => {
      setShowStartupScreen(false);
    }, 4000);

    return () => globalThis.clearTimeout(timer);
  }, [health.isSuccess]);

  const level: StatusLevel = health.isError ? "offline" : health.data ? "healthy" : "unknown";

  if (health.isPending || health.isError || showStartupScreen) {
    return <StartupLoader health={health} />;
  }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur-[2px]">
        <div className="mx-auto flex w-full max-w-[1920px] flex-wrap items-center justify-between gap-x-8 gap-y-2 px-4 py-2.5 lg:px-6">
          <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5">
            <span className="text-[0.9375rem] font-semibold tracking-tight">Sanchar Saṅgaṇaka</span>
            <span className="hidden h-3 w-px bg-border-strong sm:inline-block" aria-hidden />
            <span className="text-[0.8125rem] text-muted-foreground">
              SIH26145 · Unidirectional Threat Detection
            </span>
          </div>

          <div className="flex min-w-0 flex-col items-end gap-1.5">
            <div className="flex flex-wrap items-center justify-end gap-4">
              <div className="flex items-center gap-2">
                <StatusDot level={level} pulse />
                <span
                  className={cn(
                    "tech text-[0.6875rem] tracking-wider",
                    level === "healthy" && "text-healthy",
                    level === "offline" && "text-critical",
                    level === "unknown" && "text-muted-foreground",
                  )}
                >
                  API {statusLabel[level]}
                </span>
              </div>
              <span className="tech hidden text-muted-foreground sm:inline">{API_BASE}</span>
              {health.data ? (
                <span className="tech hidden text-muted-foreground lg:inline">
                  up {fmtUptime(health.data.uptime_s)}
                </span>
              ) : null}
            </div>
          </div>
        </div>

        <nav className="mx-auto flex w-full max-w-[1920px] flex-wrap gap-0 px-2 sm:px-4 lg:px-6">
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              activeOptions={{ exact: item.to === "/" }}
              style={{ ["--nav-accent" as string]: item.accent }}
              className="-mb-px border-b-2 border-transparent px-2 py-2 text-[0.8125rem] whitespace-nowrap sm:px-3 text-muted-foreground transition-colors hover:text-foreground"
              activeProps={{
                className: "[border-bottom-color:var(--nav-accent)] [color:var(--nav-accent)]",
              }}
            >
              {item.label}
            </Link>
          ))}
          <div className="-mb-px ml-auto flex shrink-0 items-center border-b-2 border-transparent px-2">
            <SimulationButton />
          </div>
        </nav>
      </header>

      <main className="mx-auto w-full max-w-[1920px] min-w-0 flex-1 px-4 py-5 lg:px-6">
        {children}
      </main>

      <footer className="border-t border-border">
        <p className="tech mx-auto w-full max-w-[1920px] px-4 py-2.5 text-[0.6875rem] text-muted-foreground lg:px-6">
          All figures read live from the FastAPI inference service. Nothing on this console is
          simulated.
        </p>
      </footer>
    </div>
  );
}
