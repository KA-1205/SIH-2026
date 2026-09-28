import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/utils";

/* ── layout panels ──────────────────────────────────────────────────── */

export function Panel({
  title,
  right,
  children,
  className,
  bodyClassName,
}: {
  title?: string | undefined;
  right?: ReactNode | undefined;
  children: ReactNode;
  className?: string | undefined;
  bodyClassName?: string | undefined;
}) {
  return (
    <section className={cn("flex min-w-0 flex-col border border-border bg-surface", className)}>
      {title ? (
        <header className="flex h-9 shrink-0 items-center justify-between gap-3 border-b border-border px-3">
          <h2 className="label-xs text-foreground/80">{title}</h2>
          {right}
        </header>
      ) : null}
      <div className={cn("min-w-0 flex-1 p-3", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  description,
  right,
}: {
  title: string;
  description: string;
  right?: ReactNode | undefined;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 border-b border-border pb-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
      </div>
      {right}
    </div>
  );
}

/* ── status ─────────────────────────────────────────────────────────── */

export type StatusLevel = "healthy" | "warning" | "offline" | "unknown";

const statusDot: Record<StatusLevel, string> = {
  healthy: "bg-healthy",
  warning: "bg-suspicious",
  offline: "bg-critical",
  unknown: "bg-idle",
};

const statusText: Record<StatusLevel, string> = {
  healthy: "text-healthy",
  warning: "text-suspicious",
  offline: "text-critical",
  unknown: "text-muted-foreground",
};

export const statusLabel: Record<StatusLevel, string> = {
  healthy: "HEALTHY",
  warning: "WARNING",
  offline: "OFFLINE",
  unknown: "UNKNOWN",
};

export function StatusDot({
  level,
  pulse = false,
  className,
}: {
  level: StatusLevel;
  pulse?: boolean | undefined;
  className?: string | undefined;
}) {
  return (
    <span
      className={cn(
        "inline-block size-[7px] rounded-full",
        statusDot[level],
        pulse && level === "warning" && "pulse-dot",
        className,
      )}
    />
  );
}

export function StatusLine({
  label,
  level,
  detail,
}: {
  label: string;
  level: StatusLevel;
  detail?: string | undefined;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 py-2 last:border-0">
      <div className="flex shrink-0 items-center gap-2">
        <StatusDot level={level} pulse />
        <span className="text-sm">{label}</span>
      </div>
      <div className="flex min-w-0 items-baseline gap-3 text-right">
        {detail ? (
          <span className="tech min-w-0 truncate text-muted-foreground" title={detail}>
            {detail}
          </span>
        ) : null}
        <span className={cn("tech text-[0.6875rem] tracking-wider", statusText[level])}>
          {statusLabel[level]}
        </span>
      </div>
    </div>
  );
}

/* ── metrics ────────────────────────────────────────────────────────── */

export function Metric({
  label,
  value,
  unit,
  hint,
  tone,
  size = "md",
}: {
  label: string;
  value: ReactNode;
  unit?: string | undefined;
  hint?: string | undefined;
  tone?: string | undefined;
  size?: "sm" | "md" | "lg" | undefined;
}) {
  return (
    <div className="min-w-0">
      <div className="label-xs">{label}</div>
      <div
        className={cn(
          "metric mt-1 flex items-baseline gap-1 truncate",
          size === "lg" && "text-3xl",
          size === "md" && "text-xl",
          size === "sm" && "text-base",
          tone,
        )}
      >
        {value}
        {unit ? (
          <span className="text-[0.6875rem] font-normal text-muted-foreground">{unit}</span>
        ) : null}
      </div>
      {hint ? <div className="mt-0.5 text-[0.6875rem] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

/** Counts up/down to the target so live score changes read as movement. */
export function AnimatedNumber({
  value,
  digits = 3,
  className,
}: {
  value: number | null | undefined;
  digits?: number | undefined;
  className?: string | undefined;
}) {
  const [shown, setShown] = useState(value ?? 0);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    if (value === null || value === undefined) return;
    const from = shown;
    const to = value;
    if (Math.abs(to - from) < 10 ** -(digits + 1)) {
      setShown(to);
      return;
    }
    const start = performance.now();
    const duration = 420;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - t) ** 3;
      setShown(from + (to - from) * eased);
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, digits]);

  if (value === null || value === undefined) return <span className={className}>—</span>;
  return <span className={className}>{shown.toFixed(digits)}</span>;
}

/* ── honest empty / error states ────────────────────────────────────── */

export function Unavailable({
  what,
  reason,
  className,
  onRetry,
}: {
  what: string;
  reason?: string | undefined;
  className?: string | undefined;
  onRetry?: (() => void) | undefined;
}) {
  return (
    <div className={cn("flex h-full min-h-24 flex-col justify-center gap-1 px-1 py-6", className)}>
      <p className="tech text-muted-foreground">{what} unavailable</p>
      {reason ? (
        <p className="max-w-md text-[0.6875rem] leading-relaxed text-muted-foreground/80">
          {reason}
        </p>
      ) : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="tech mt-1 w-fit border border-border px-2 py-1 text-[0.6875rem] text-foreground transition-colors hover:bg-surface-raised"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function Pending({ what }: { what: string }) {
  return (
    <div className="flex h-full min-h-24 items-center px-1 py-6">
      <p className="tech text-muted-foreground">Awaiting {what}…</p>
    </div>
  );
}

/** Thin inline bar used for score components and distributions. */
export function Bar({
  value,
  max = 1,
  tone = "bg-primary",
  className,
}: {
  value: number;
  max?: number | undefined;
  tone?: string | undefined;
  className?: string | undefined;
}) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className={cn("h-[3px] w-full bg-surface-raised", className)}>
      <div
        className={cn("h-full transition-[width] duration-500 ease-out", tone)}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
