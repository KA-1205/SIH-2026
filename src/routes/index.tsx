import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import type { Alert } from "@/lib/api";
import {
  coverageQuery,
  healthQuery,
  metaQuery,
  recentAlertsQuery,
  statsQuery,
  trendQuery,
} from "@/lib/queries";
import { useAlertStream } from "@/hooks/useAlertStream";
import {
  alertKey,
  alertSeconds,
  fmtInt,
  fmtScore,
  fmtTime,
  threatClassLabel,
  verdictBg,
  verdictColor,
} from "@/lib/format";
import { activityOf, buildStages, streamLevel } from "@/lib/system";
import { ThreatTrendChart } from "@/components/charts";
import { EventTable } from "@/components/event-table";
import { EventInspector } from "@/components/event-inspector";
import { PipelineFlow } from "@/components/pipeline-flow";
import {
  AnimatedNumber,
  Bar,
  Metric,
  PageHeader,
  Panel,
  Pending,
  StatusDot,
  Unavailable,
} from "@/components/primitives";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "Overview — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "System health, diode status, traffic activity, model status, current fused threat level and recent detections for the unidirectional-traffic IDS.",
      },
      { property: "og:title", content: "Overview — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content: "Live diode status, pipeline health, fused threat score and recent detections.",
      },
    ],
  }),
  component: Overview,
});

function Overview() {
  const health = useQuery(healthQuery);
  const stats = useQuery(statsQuery);
  const trend = useQuery(trendQuery);
  const recent = useQuery(recentAlertsQuery);
  const meta = useQuery(metaQuery);
  const coverage = useQuery(coverageQuery);
  const stream = useAlertStream();
  const [selected, setSelected] = useState<Alert | null>(null);

  const inputs = {
    health: health.data,
    healthError: health.isError,
    stats: stats.data,
    meta: meta.data,
    streamState: stream.state,
    lastEventAt: stream.lastAt,
  };
  const stages = buildStages(inputs);
  const activity = activityOf(inputs);

  const feed = useMemo(() => stream.merge(recent.data), [stream.rows, recent.data]);
  const latest: Alert | null = feed[0] ?? null;
  const trendRows = trend.data ?? [];

  const verdictCounts = stats.data?.by_verdict ?? {};
  const alertsByClass = coverage.data?.alerts_by_class ?? {};
  const topClasses = Object.entries(alertsByClass)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const noBackend = health.isError;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Network Threat Monitoring"
        description="Monitor pipeline health, forward traffic activity, detection signals and the current threat level."
      />
      {noBackend ? (
        <div className="border-l-2 border-critical bg-surface px-4 py-3">
          <p className="text-sm">
            <span className="text-critical">Inference service unreachable.</span> Start it with{" "}
            <span className="tech">uvicorn serving.app:app --port 8200</span> and set{" "}
            <span className="tech">VITE_API_BASE_URL</span> if it is not on 127.0.0.1:8200. No
            values are shown until it responds.
          </p>
        </div>
      ) : null}

      {/* row 1: threat assessment + traffic summary */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <Panel title="Current threat assessment" bodyClassName="p-0">
          {latest ? (
            <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,180px)_1fr]">
              <div className="border-border p-4 sm:border-r">
                <div className="label-xs">Fused score</div>
                <div
                  className={cn("metric mt-1 text-4xl leading-none", verdictColor[latest.verdict])}
                >
                  <AnimatedNumber value={latest.threat_score} />
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <span className={cn("size-[7px] rounded-full", verdictBg[latest.verdict])} />
                  <span
                    className={cn(
                      "tech text-[0.6875rem] tracking-wider",
                      verdictColor[latest.verdict],
                    )}
                  >
                    {latest.verdict}
                  </span>
                </div>
                <p className="mt-2 text-[0.8125rem] text-muted-foreground">
                  {threatClassLabel[latest.threat_class] ?? latest.threat_class}
                </p>
                <p className="tech mt-2 text-[0.6875rem] text-muted-foreground">
                  window {fmtTime(alertSeconds(latest))}
                </p>
              </div>
              <div className="space-y-3 p-4">
                <SignalRow
                  label="XGBoost / RF term"
                  value={latest.components?.classifier}
                  detail={
                    latest.predicted_label && latest.predicted_label !== "n/a"
                      ? latest.predicted_label
                      : undefined
                  }
                  tone="bg-informational"
                />
                <SignalRow
                  label="LSTM-AE term"
                  value={latest.components?.autoencoder}
                  detail={
                    latest.ae_error === null || latest.ae_error === undefined
                      ? "no sequence"
                      : `recon ${fmtScore(latest.ae_error, 4)}`
                  }
                  tone="bg-suspicious"
                />
                <SignalRow
                  label="Detector term"
                  value={latest.components?.detectors}
                  detail={latest.detector}
                  tone="bg-primary"
                />
                <div className="flex items-baseline justify-between gap-4 border-t border-border pt-2">
                  <span className="label-xs">Confidence</span>
                  <span className="tech">{fmtScore(latest.confidence)}</span>
                </div>
              </div>
            </div>
          ) : noBackend ? (
            <Unavailable
              what="Threat assessment"
              reason="The service has not returned any scored window."
              className="px-4"
            />
          ) : (
            <Pending what="the first scored window" />
          )}
        </Panel>

        <Panel title="Traffic summary" bodyClassName="p-0">
          {stats.data ? (
            <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-3">
              {[
                {
                  label: "Windows scored",
                  value: fmtInt(stats.data.windows_scored),
                },
                { label: "Alerts raised", value: fmtInt(stats.data.alerts) },
                {
                  label: "Suspicious (MEDIUM)",
                  value: fmtInt(verdictCounts["MEDIUM"] ?? 0),
                },
                { label: "Confirmed (HIGH)", value: fmtInt(verdictCounts["HIGH"] ?? 0) },
                {
                  label: "Packets / s",
                  value: stats.data.throughput.pkts_s.toFixed(1),
                },
                {
                  label: "Avg latency",
                  value:
                    stats.data.latency_ms.avg === null ? "—" : stats.data.latency_ms.avg.toFixed(2),
                  unit: "ms",
                  hint:
                    stats.data.latency_ms.p95 === null
                      ? undefined
                      : `p95 ${stats.data.latency_ms.p95.toFixed(2)} ms`,
                },
              ].map((m) => (
                <div key={m.label} className="p-3">
                  <Metric label={m.label} value={m.value} unit={m.unit} hint={m.hint} size="md" />
                </div>
              ))}
            </div>
          ) : noBackend ? (
            <Unavailable what="Traffic counters" className="px-4" />
          ) : (
            <Pending what="traffic counters" />
          )}
        </Panel>
      </div>

      {/* row 2: pipeline */}
      <Panel
        title="Detection pipeline"
        right={
          <div className="flex items-center gap-2">
            <StatusDot level={streamLevel(inputs)} pulse />
            <span className="tech text-[0.6875rem] text-muted-foreground">
              {stream.state === "live"
                ? activity === "busy"
                  ? "streaming · scoring"
                  : "streaming · idle"
                : stream.state === "connecting"
                  ? "connecting to /ws/alerts"
                  : "live stream offline"}
            </span>
          </div>
        }
      >
        <PipelineFlow stages={stages} activity={activity} />
      </Panel>

      {/* row 3: trend + threat classes */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel
          title="Fused threat score / scored window"
          right={
            <span className="tech text-[0.6875rem] text-muted-foreground">
              bands 0.25 MEDIUM · 0.50 HIGH
            </span>
          }
        >
          {trendRows.length ? (
            <ThreatTrendChart data={trendRows} height={200} />
          ) : noBackend ? (
            <Unavailable what="Score trend" />
          ) : (
            <Pending what="scored windows" />
          )}
        </Panel>

        <Panel title="Alerts by threat class">
          {topClasses.length ? (
            <div className="space-y-3">
              {topClasses.map(([cls, n]) => (
                <div key={cls}>
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="text-sm">{threatClassLabel[cls] ?? cls}</span>
                    <span className="tech">{n}</span>
                  </div>
                  <Bar value={n} max={topClasses[0]?.[1] ?? 1} className="mt-1.5" />
                </div>
              ))}
            </div>
          ) : coverage.isError ? (
            <Unavailable what="Coverage tallies" />
          ) : (
            <Pending what="the first alert" />
          )}
        </Panel>
      </div>

      {/* row 4: recent detections */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,340px)]">
        <Panel
          title="Recent detections"
          bodyClassName="p-0"
          right={
            <span className="tech text-[0.6875rem] text-muted-foreground">
              {feed.length} windows buffered
            </span>
          }
        >
          {feed.length ? (
            <div className="max-h-[420px] overflow-auto">
              <EventTable
                rows={feed.slice(0, 40)}
                selectedKey={selected ? alertKey(selected) : null}
                onSelect={setSelected}
                newestKey={feed[0] ? alertKey(feed[0]) : null}
              />
            </div>
          ) : noBackend ? (
            <Unavailable what="Detections" className="px-4" />
          ) : (
            <Pending what="live windows" />
          )}
        </Panel>
        <div className="min-h-[320px]">
          <EventInspector alert={selected} onClose={() => setSelected(null)} />
        </div>
      </div>
    </div>
  );
}

function SignalRow({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: number | undefined;
  detail?: string | undefined;
  tone: string;
}) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="label-xs">{label}</span>
        <span className="tech">{value === undefined ? "not reported" : fmtScore(value)}</span>
      </div>
      <Bar value={value ?? 0} tone={tone} className="mt-1.5" />
      {detail ? <p className="tech mt-1 text-[0.6875rem] text-muted-foreground">{detail}</p> : null}
    </div>
  );
}
