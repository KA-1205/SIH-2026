import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { API_BASE, WS_URL } from "@/lib/api";
import { healthQuery, metaQuery, statsQuery } from "@/lib/queries";
import { useAlertStream } from "@/hooks/useAlertStream";
import { fmtInt, fmtUptime } from "@/lib/format";
import {
  Metric,
  PageHeader,
  Panel,
  Pending,
  StatusLine,
  Unavailable,
  type StatusLevel,
} from "@/components/primitives";
import { PipelineFlow } from "@/components/pipeline-flow";
import {
  activityOf,
  apiLevel,
  buildStages,
  diodeLevel,
  extractionLevel,
  streamLevel,
} from "@/lib/system";

export const Route = createFileRoute("/system")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "System Health — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "Component health for the Sanchar Saṅgaṇaka pipeline: API, data diode, feature extraction, model inference and the live alert stream, with uptime and latency.",
      },
      { property: "og:title", content: "System Health — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content:
          "API, diode, extraction, inference and live-stream status with measured latency and uptime.",
      },
    ],
  }),
  component: SystemHealth,
});

function SystemHealth() {
  const health = useQuery(healthQuery);
  const stats = useQuery(statsQuery);
  const meta = useQuery(metaQuery);
  const stream = useAlertStream();

  const inputs = {
    health: health.data,
    healthError: health.isError,
    stats: stats.data,
    meta: meta.data,
    streamState: stream.state,
    lastEventAt: stream.lastAt,
  };

  const inferenceLevel: StatusLevel = health.isError
    ? "offline"
    : health.data
      ? health.data.classifier && health.data.autoencoder
        ? "healthy"
        : health.data.classifier || health.data.autoencoder
          ? "warning"
          : "offline"
      : "unknown";

  return (
    <div className="space-y-4">
      <PageHeader
        title="System Health"
        description="Monitor the operational state of the API, data diode, feature extraction, model inference and live stream."
        right={
          health.data ? (
            <div className="flex gap-6">
              <Metric label="Uptime" value={fmtUptime(health.data.uptime_s)} size="sm" />
              <Metric label="WS clients" value={health.data.ws_clients} size="sm" />
            </div>
          ) : undefined
        }
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel title="Components">
          <div className="-mt-1">
            <StatusLine label="Inference API" level={apiLevel(inputs)} detail={API_BASE} />
            <StatusLine
              label="Data diode"
              level={diodeLevel(meta.data)}
              detail={
                meta.data?.diode?.leaked_bytes === null || meta.data?.diode === undefined
                  ? undefined
                  : `${meta.data.diode.leaked_bytes} B reverse`
              }
            />
            <StatusLine
              label="Feature extraction"
              level={extractionLevel(inputs)}
              detail={health.data ? `${fmtInt(health.data.windows_scored)} windows` : undefined}
            />
            <StatusLine
              label="Model inference"
              level={inferenceLevel}
              detail={
                health.data
                  ? `${health.data.classifier ? "clf" : "no clf"} · ${
                      health.data.autoencoder ? "ae" : "no ae"
                    } · ${health.data.device}`
                  : undefined
              }
            />
            <StatusLine label="Live stream" level={streamLevel(inputs)} detail={WS_URL} />
          </div>
        </Panel>

        <Panel title="Measured latency & counters" bodyClassName="p-0">
          {health.data ? (
            <div className="grid grid-cols-2 divide-x divide-y divide-border">
              <div className="p-3">
                <Metric
                  label="Avg score latency"
                  value={
                    health.data.avg_latency_ms === null
                      ? "—"
                      : health.data.avg_latency_ms.toFixed(2)
                  }
                  unit="ms"
                  hint="rolling window of 200 requests"
                />
              </div>
              <div className="p-3">
                <Metric
                  label="p95 score latency"
                  value={
                    health.data.p95_latency_ms === null
                      ? "—"
                      : health.data.p95_latency_ms.toFixed(2)
                  }
                  unit="ms"
                />
              </div>
              <div className="p-3">
                <Metric label="Windows scored" value={fmtInt(health.data.windows_scored)} />
              </div>
              <div className="p-3">
                <Metric
                  label="Alerts raised"
                  value={stats.data ? fmtInt(stats.data.alerts) : "—"}
                />
              </div>
            </div>
          ) : health.isError ? (
            <Unavailable
              what="Latency counters"
              reason="/health did not respond, so no measured latency exists to show."
              className="px-4"
            />
          ) : (
            <Pending what="/health" />
          )}
        </Panel>
      </div>

      <Panel title="Pipeline stage status">
        <PipelineFlow stages={buildStages(inputs)} activity={activityOf(inputs)} />
      </Panel>
    </div>
  );
}
