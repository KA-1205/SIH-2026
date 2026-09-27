import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { API_BASE } from "@/lib/api";
import { healthQuery } from "@/lib/queries";
import { fmtUptime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatusDot, statusLabel, type StatusLevel } from "./primitives";

const NAV = [
  { to: "/", label: "Overview" },
  { to: "/events", label: "Live Traffic" },
  { to: "/analysis", label: "Threat Detection" },
  { to: "/network", label: "Traffic Analytics" },
  { to: "/models", label: "Detection Models" },
  { to: "/system", label: "System Health" },
  { to: "/about", label: "About" },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const health = useQuery(healthQuery);
  const level: StatusLevel = health.isError ? "offline" : health.data ? "healthy" : "unknown";

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur-[2px]">
        <div className="flex flex-wrap items-center justify-between gap-x-8 gap-y-2 px-4 py-2.5 lg:px-6">
          <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5">
            <span className="text-[0.9375rem] font-semibold tracking-tight">Sanchar Saṅgaṇaka</span>
            <span className="hidden h-3 w-px bg-border-strong sm:inline-block" aria-hidden />
            <span className="text-[0.8125rem] text-muted-foreground">
              SIH26145 · Unidirectional Threat Detection
            </span>
          </div>

          <div className="flex items-center gap-4">
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

        <nav className="flex flex-wrap gap-0 px-2 sm:px-4 lg:px-6">
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              activeOptions={{ exact: item.to === "/" }}
              className="-mb-px border-b-2 border-transparent px-2 py-2 text-[0.8125rem] whitespace-nowrap sm:px-3 text-muted-foreground transition-colors hover:text-foreground"
              activeProps={{ className: "border-primary text-foreground" }}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </header>

      <main className="min-w-0 flex-1 px-4 py-5 lg:px-6">{children}</main>

      <footer className="border-t border-border px-4 py-2.5 lg:px-6">
        <p className="tech text-[0.6875rem] text-muted-foreground">
          All figures read live from the FastAPI inference service. Nothing on this console is
          simulated.
        </p>
      </footer>
    </div>
  );
}
