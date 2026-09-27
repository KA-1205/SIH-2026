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
          d="M158 75 H196 M330 75 H360 M360 43 V52 M360 107 V98 M360 43 H392 M360 107 H392 M556 43 H592 M556 107 H592 M592 43 V70 M592 107 V80 M592 75 H628 M762 75 H798"
          stroke="var(--border)"
          strokeWidth="1"
          fill="none"
        />
        {link("M158 75 H196", extract)}
        {link("M330 75 H360 V43 H392", xgb)}
        {link("M330 75 H360 V107 H392", ae)}
        {link("M556 43 H592 V75 H628", fusion)}
        {link("M556 107 H592 V75 H628", fusion)}
        {link("M762 75 H798", score)}

        <text
          x={366}
          y={79}
          fill="var(--muted-foreground)"
          fontSize="11"
          fontFamily="var(--font-mono)"
        >
          +
        </text>

        {box(8, 52, 150, diode)}
        {box(196, 52, 134, extract)}
        {box(392, 20, 164, xgb)}
        {box(392, 84, 164, ae)}
        {box(628, 52, 134, fusion)}
        {box(798, 52, 174, score)}
      </svg>
    </>
  );
}
