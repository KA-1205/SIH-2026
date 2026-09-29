import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

import { coverageQuery, metaQuery, recentAlertsQuery, statsQuery, trendQuery } from "@/lib/queries";
import { useAlertStream } from "@/hooks/useAlertStream";
import { VERDICT_BAR_COLOR, alertSeconds, fmtScore, fmtTime, threatClassLabel } from "@/lib/format";
import { CategoryBars, SeriesLine, ThreatTrendChart } from "@/components/charts";
import { Bar, Metric, PageHeader, Panel, Pending, Unavailable } from "@/components/primitives";

export const Route = createFileRoute("/analysis")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "Threat Detection — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "Threat score over time, verdict distribution, attack-family tallies, classifier confidence, LSTM reconstruction error and per-window detection latency.",
      },
      { property: "og:title", content: "Threat Detection — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content:
          "Score timeline, verdict distribution, reconstruction error and detection latency from the live pipeline.",
      },
    ],
  }),
  component: Analysis,
});

function Analysis() {
  const trend = useQuery(trendQuery);
  const stats = useQuery(statsQuery);
  const recent = useQuery(recentAlertsQuery);
  const coverage = useQuery(coverageQuery);
  const meta = useQuery(metaQuery);
  const stream = useAlertStream();

  const feed = useMemo(() => stream.merge(recent.data), [stream.rows, recent.data]);
  const trendRows = trend.data ?? [];

  /** Windows per 10 s bucket, derived from the real /trend timestamps. */
  const eventsOverTime = useMemo(() => {
    if (!trendRows.length) return [];
    const bucket = new Map<number, number>();
    for (const p of trendRows) {
      const k = Math.floor(p.ts / 10) * 10;
      bucket.set(k, (bucket.get(k) ?? 0) + 1);
    }
    return Array.from(bucket.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([ts, n]) => ({ label: fmtTime(ts), value: n }));
  }, [trendRows]);

  const chronological = useMemo(
    () =>
      [...feed]
        .sort((a, b) => alertSeconds(a) - alertSeconds(b))
        .map((a) => ({
          label: fmtTime(alertSeconds(a)),
          recon: a.ae_error ?? 0,
          latency: a.latency_ms ?? 0,
          confidence: a.confidence,
          classifier: a.components?.classifier ?? 0,
        })),
    [feed],
  );

  const hasRecon = feed.some((a) => a.ae_error !== null && a.ae_error !== undefined);
  const hasLatency = feed.some((a) => a.latency_ms !== null && a.latency_ms !== undefined);

  const verdictDist = useMemo(() => {
    const v = stats.data?.by_verdict;
    if (!v) return [];
    return ["OK", "MEDIUM", "HIGH", "CRITICAL"]
      .filter((k) => v[k] !== undefined)
      .map((k) => ({ label: k, value: v[k] ?? 0 }));
  }, [stats.data]);

  const families = useMemo(() => {
    const f = stats.data?.by_family;
    if (!f) return [];
    return Object.entries(f)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [stats.data]);

  const classAlerts = Object.entries(coverage.data?.alerts_by_class ?? {}).filter(([, n]) => n > 0);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Threat Detection"
        description="Known and novel threats detected from forward-only network traffic: RF / XGBoost for known attack types, the LSTM autoencoder for unseen patterns, combined by alert fusion."
        right={
          stats.data ? (
            <div className="flex gap-6">
              <Metric
                label="Windows scored"
                value={stats.data.windows_scored.toLocaleString("en-US")}
                size="sm"
              />
              <Metric label="Alerts" value={stats.data.alerts.toLocaleString("en-US")} size="sm" />
              <Metric
                label="p95 latency"
                value={
                  stats.data.latency_ms.p95 === null ? "—" : stats.data.latency_ms.p95.toFixed(2)
                }
                unit="ms"
                size="sm"
              />
            </div>
          ) : undefined
        }
      />

      <Panel title="Fused threat score over time">
        {trendRows.length ? (
          <ThreatTrendChart data={trendRows} height={220} />
        ) : trend.isError ? (
          <Unavailable what="Score timeline" reason="/trend did not respond." />
        ) : (
          <Pending what="scored windows" />
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Windows per 10 s">
          {eventsOverTime.length ? (
            <CategoryBars data={eventsOverTime} height={170} color="var(--informational)" />
          ) : (
            <Pending what="scored windows" />
          )}
        </Panel>

        <Panel title="Verdict distribution">
          {verdictDist.length ? (
            <CategoryBars
              data={verdictDist}
              height={170}
              colors={verdictDist.map((d) => VERDICT_BAR_COLOR[d.label] ?? "var(--idle)")}
            />
          ) : stats.isError ? (
            <Unavailable what="Verdict tallies" reason="/stats did not respond." />
          ) : (
            <Pending what="verdict tallies" />
          )}
        </Panel>

        <Panel title="LSTM-AE reconstruction error per window">
          {hasRecon ? (
            <SeriesLine
              data={chronological}
              dataKey="recon"
              name="recon error"
              color="var(--suspicious)"
              height={170}
            />
          ) : (
            <Unavailable
              what="Reconstruction error"
              reason="No scored window carried a sequence, so the autoencoder reported no error."
            />
          )}
        </Panel>

        <Panel title="Classifier term & calibrated confidence">
          {chronological.length ? (
            <SeriesLine
              data={chronological}
              dataKey="confidence"
              name="confidence"
              color="var(--primary)"
              height={170}
              domain={[0, 1]}
            />
          ) : (
            <Pending what="scored windows" />
          )}
        </Panel>

        <Panel title="Detection latency per window">
          {hasLatency ? (
            <SeriesLine
              data={chronological}
              dataKey="latency"
              name="latency ms"
              color="var(--informational)"
              height={170}
            />
          ) : (
            <Unavailable what="Latency series" reason="No window reported latency_ms." />
          )}
        </Panel>

        <Panel title="Attack families & threat classes">
          {families.length || classAlerts.length ? (
            <div className="space-y-4">
              {families.length ? (
                <div className="space-y-2">
                  <p className="label-xs">Classifier families (/stats)</p>
                  {families.map(([name, n]) => (
                    <div key={name}>
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="text-sm">{name}</span>
                        <span className="tech">{n}</span>
                      </div>
                      <Bar value={n} max={families[0]?.[1] ?? 1} className="mt-1" />
                    </div>
                  ))}
                </div>
              ) : null}
              {classAlerts.length ? (
                <div className="space-y-2 border-t border-border pt-3">
                  <p className="label-xs">Named threat classes (/coverage)</p>
                  {classAlerts.map(([cls, n]) => (
                    <div key={cls} className="flex items-baseline justify-between gap-3 py-0.5">
                      <span className="text-sm">{threatClassLabel[cls] ?? cls}</span>
                      <span className="tech">{n}</span>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          ) : (
            <Pending what="the first alert" />
          )}
        </Panel>
      </div>

      <Panel title="Offline evaluation metrics (/meta)">
        {meta.data ? (
          <div className="grid gap-x-8 gap-y-3 sm:grid-cols-3 lg:grid-cols-5">
            <Metric
              label="Macro F1"
              value={fmtScore(meta.data.classifier_metrics.macro_f1, 4)}
              size="md"
            />
            <Metric
              label="Accuracy"
              value={fmtScore(meta.data.classifier_metrics.accuracy, 4)}
              size="md"
            />
            <Metric
              label="Rows"
              value={
                meta.data.classifier_metrics.n_rows === null
                  ? "—"
                  : meta.data.classifier_metrics.n_rows.toLocaleString("en-US")
              }
              size="md"
            />
            <Metric
              label="Train / test"
              value={`${meta.data.classifier_metrics.n_train ?? "—"} / ${
                meta.data.classifier_metrics.n_test ?? "—"
              }`}
              size="sm"
            />
            <Metric label="Features" value={meta.data.n_features} size="md" />
          </div>
        ) : meta.isError ? (
          <Unavailable what="Evaluation metrics" reason="/meta did not respond." />
        ) : (
          <Pending what="model metadata" />
        )}
      </Panel>
    </div>
  );
}
