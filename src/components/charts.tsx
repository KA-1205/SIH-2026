import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { TrendPoint } from "@/lib/api";
import { fmtTime } from "@/lib/format";

const axis = {
  stroke: "var(--border-strong)",
  tick: {
    fill: "var(--muted-foreground)",
    fontSize: 10,
    fontFamily: "var(--font-mono)",
  },
} as const;

const tooltipStyle = {
  contentStyle: {
    background: "var(--surface-raised)",
    border: "1px solid var(--border-strong)",
    borderRadius: 2,
    fontSize: 11,
    fontFamily: "var(--font-mono)",
    padding: "6px 8px",
  },
  labelStyle: { color: "var(--muted-foreground)", fontSize: 10 },
  itemStyle: { color: "var(--foreground)" },
} as const;

/** Threat score per scored window, with the real fusion verdict bands. */
export function ThreatTrendChart({
  data,
  height = 180,
}: {
  data: TrendPoint[];
  height?: number | undefined;
}) {
  const rows = data.map((d) => ({ ...d, label: fmtTime(d.ts) }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={rows} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
        <defs>
          <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.28} />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="label" {...axis} minTickGap={48} />
        <YAxis domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} {...axis} width={44} />
        <ReferenceLine y={0.25} stroke="var(--suspicious)" strokeDasharray="3 3" />
        <ReferenceLine y={0.5} stroke="var(--critical)" strokeDasharray="3 3" />
        <Tooltip {...tooltipStyle} />
        <Area
          type="monotone"
          dataKey="threat_score"
          name="fused score"
          stroke="var(--primary)"
          strokeWidth={1.4}
          fill="url(#scoreFill)"
          isAnimationActive={false}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeriesLine({
  data,
  dataKey,
  name,
  color = "var(--informational)",
  height = 160,
  domain,
}: {
  data: Array<Record<string, number | string>>;
  dataKey: string;
  name: string;
  color?: string | undefined;
  height?: number | undefined;
  domain?: [number, number | "auto"] | undefined;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="label" {...axis} minTickGap={48} />
        <YAxis {...axis} width={44} domain={domain ?? ["auto", "auto"]} />
        <Tooltip {...tooltipStyle} />
        <Line
          type="monotone"
          dataKey={dataKey}
          name={name}
          stroke={color}
          strokeWidth={1.4}
          dot={false}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function CategoryBars({
  data,
  height = 180,
  color = "var(--primary)",
  colors,
}: {
  data: Array<{ label: string; value: number }>;
  height?: number | undefined;
  color?: string | undefined;
  colors?: string[] | undefined;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="label" {...axis} interval={0} />
        <YAxis {...axis} width={44} allowDecimals={false} />
        <Tooltip {...tooltipStyle} cursor={{ fill: "var(--surface-raised)" }} />
        <Bar dataKey="value" name="windows" fill={color} isAnimationActive={false}>
          {colors ? data.map((_, i) => <Cell key={i} fill={colors[i % colors.length]} />) : null}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
