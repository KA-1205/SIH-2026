import { cn } from "@/lib/utils";
import type { StatusLevel } from "./primitives";

export type Stage = {
  id: string;
  label: string;
  detail: string;
  level: StatusLevel;
};

export type PipelineActivity = "idle" | "flowing" | "busy";

const strokeFor: Record<StatusLevel, string> = {
  healthy: "var(--healthy)",
  warning: "var(--suspicious)",
  offline: "var(--critical)",
  unknown: "var(--idle)",
};

/**
 * Data-flow visualisation of the real pipeline. Link animation reflects
 * measured activity: stopped when the downstream stage is offline/unknown,
 * continuous when healthy, faster while windows are actively being scored.
 */
export function PipelineFlow({
  stages,
  activity,
  className,
}: {
  stages: Stage[];
  activity: PipelineActivity;
  className?: string | undefined;
}) {
  const byId = (id: string) => stages.find((s) => s.id === id);
  const diode = byId("diode");
  const extract = byId("extraction");
  const xgb = byId("classifier");
  const ae = byId("autoencoder");
  const fusion = byId("fusion");
  const score = byId("score");

  const dashClass = (target?: Stage) => {
    if (!target || target.level === "offline" || target.level === "unknown")
      return "flow-dash-stopped";
    if (activity === "idle") return "flow-dash-stopped";
    return activity === "busy" ? "flow-dash-fast" : "flow-dash";
  };

  const box = (
    x: number,
    y: number,
    w: number,
    stage: Stage | undefined,
    align: "start" | "middle" = "start",
  ) =>
    stage ? (
      <g key={stage.id}>
        <rect
          x={x}
          y={y}
          width={w}
          height={46}
          fill="var(--surface-raised)"
          stroke={stage.level === "offline" ? "var(--critical)" : "var(--border-strong)"}
        />
        <circle cx={x + 10} cy={y + 15} r={3.5} fill={strokeFor[stage.level]} />
        <text
          x={align === "middle" ? x + w / 2 : x + 20}
          y={y + 19}
          textAnchor={align === "middle" ? "middle" : "start"}
          fill="var(--foreground)"
          fontSize="10.5"
          letterSpacing="0.07em"
          fontFamily="var(--font-sans)"
          fontWeight="500"
        >
          {stage.label}
        </text>
        <text
          x={align === "middle" ? x + w / 2 : x + 20}
          y={y + 34}
          textAnchor={align === "middle" ? "middle" : "start"}
          fill="var(--muted-foreground)"
          fontSize="10"
          fontFamily="var(--font-mono)"
        >
          {stage.detail}
        </text>
      </g>
    ) : null;

  const link = (d: string, target?: Stage) => (
    <path
      d={d}
      fill="none"
      stroke="var(--border-strong)"
      strokeWidth="1"
      className={cn(dashClass(target))}
      style={{ stroke: "var(--primary)" }}
    />
  );

  return (
    <>
      <ol className={cn("space-y-1.5 sm:hidden", className)} aria-label="Detection pipeline stages">
        {stages.map((st, idx) => (
          <li
            key={st.id}
            className="flex min-w-0 items-center gap-2 border border-border bg-surface-raised px-2 py-1.5"
          >
            <span className="tech w-4 shrink-0 text-muted-foreground">{idx + 1}</span>
            <span
              className="inline-block size-[7px] shrink-0 rounded-full"
              style={{ background: strokeFor[st.level] }}
            />
            <span className="tech shrink-0 text-[0.6875rem]">{st.label}</span>
            <span
              className="tech ml-auto min-w-0 truncate text-[0.6875rem] text-muted-foreground"
              title={st.detail}
            >
              {st.detail}
            </span>
          </li>
        ))}
      </ol>
      <svg
        viewBox="0 0 980 150"
        className={cn("hidden h-auto w-full sm:block", className)}
        role="img"
        aria-label="Detection pipeline status"
      >
        {/* base rails (static) */}
        <path
          d="M160 75 H198 M394 75 H414 M414 43 V107 M414 43 H434 M414 107 H434 M598 43 H618 M598 107 H618 M618 43 V107 M618 75 H638 M750 75 H810"
          stroke="var(--border)"
          strokeWidth="1"
          fill="none"
        />
        {link("M160 75 H198", extract)}
        {link("M394 75 H414 V43 H434", xgb)}
        {link("M394 75 H414 V107 H434", ae)}
        {link("M598 43 H618 V75 H638", fusion)}
        {link("M598 107 H618 V75 H638", fusion)}
        {link("M750 75 H810", score)}

        <text
          x={420}
          y={79}
          fill="var(--muted-foreground)"
          fontSize="11"
          fontFamily="var(--font-mono)"
        >
          +
        </text>

        {box(10, 52, 150, diode)}
        {box(198, 52, 196, extract)}
        {box(434, 20, 164, xgb)}
        {box(434, 84, 164, ae)}
        {box(638, 52, 112, fusion)}
        {box(810, 52, 144, score)}
      </svg>
    </>
  );
}
