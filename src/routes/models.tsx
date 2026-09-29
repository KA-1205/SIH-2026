import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { healthQuery, metaQuery } from "@/lib/queries";
import { fmtInt, fmtScore } from "@/lib/format";
import {
  Bar,
  Metric,
  PageHeader,
  Panel,
  Pending,
  StatusDot,
  Unavailable,
  statusLabel,
  type StatusLevel,
} from "@/components/primitives";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/models")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "Detection Models — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "Loaded detection models: XGBoost/RF known-threat classifier and the LSTM autoencoder for novel threats, with artifact status, metrics and top attribution features.",
      },
      { property: "og:title", content: "Detection Models — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content:
          "Artifact status and reported metrics for the known-threat classifier and the LSTM autoencoder.",
      },
    ],
  }),
  component: Models,
});

function Models() {
  const health = useQuery(healthQuery);
  const meta = useQuery(metaQuery);

  const clfLevel: StatusLevel = health.isError
    ? "offline"
    : health.data
      ? health.data.classifier
        ? "healthy"
        : "offline"
      : "unknown";
  const aeLevel: StatusLevel = health.isError
    ? "offline"
    : health.data
      ? health.data.autoencoder
        ? "healthy"
        : "offline"
      : "unknown";

  const perClass = meta.data?.per_class ?? {};
  const perClassRows = Object.entries(perClass);
  const fpr = meta.data?.fpr_at_recall95 ?? {};
  const aeMetrics = Object.entries(meta.data?.autoencoder_metrics ?? {});

  return (
    <div className="space-y-4">
      <PageHeader
        title="Detection Models"
        description="Inspect the status and reported metrics of the known-threat classifier and the novel-threat autoencoder."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Known-threat model — XGBoost / RF" right={<ModelBadge level={clfLevel} />}>
          {meta.data ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
                <Metric
                  label="Macro F1"
                  value={fmtScore(meta.data.classifier_metrics.macro_f1, 4)}
                />
                <Metric
                  label="Accuracy"
                  value={fmtScore(meta.data.classifier_metrics.accuracy, 4)}
                />
                <Metric label="Features" value={meta.data.n_features} />
                <Metric label="Classes" value={meta.data.classes.length} />
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-border pt-3 sm:grid-cols-3">
                <Metric
                  label="Rows"
                  value={fmtInt(meta.data.classifier_metrics.n_rows)}
                  size="sm"
                />
                <Metric
                  label="Train"
                  value={fmtInt(meta.data.classifier_metrics.n_train)}
                  size="sm"
                />
                <Metric
                  label="Test"
                  value={fmtInt(meta.data.classifier_metrics.n_test)}
                  size="sm"
                />
              </div>
              {meta.data.top_features.length ? (
                <div className="border-t border-border pt-3">
                  <p className="label-xs mb-2">SHAP top attribution features</p>
                  <ul className="flex flex-wrap gap-x-4 gap-y-1">
                    {meta.data.top_features.map((f) => (
                      <li key={f} className="tech text-muted-foreground">
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="tech border-t border-border pt-3 text-muted-foreground">
                  No SHAP attribution written by the training run
                </p>
              )}
            </div>
          ) : meta.isError ? (
            <Unavailable what="Classifier metadata" reason="/meta did not respond." />
          ) : (
            <Pending what="model metadata" />
          )}
        </Panel>

        <Panel title="Novel-threat model — LSTM autoencoder" right={<ModelBadge level={aeLevel} />}>
          {meta.data ? (
            aeMetrics.length ? (
              <dl className="divide-y divide-border/60">
                {aeMetrics.map(([k, v]) => (
                  <div key={k} className="flex items-baseline justify-between gap-4 py-1.5">
                    <dt className="label-xs">{k.replace(/_/g, " ")}</dt>
                    <dd className="tech">
                      {typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(5)) : String(v)}
                    </dd>
                  </div>
                ))}
                {health.data ? (
                  <div className="flex items-baseline justify-between gap-4 py-1.5">
                    <dt className="label-xs">inference device</dt>
                    <dd className="tech">{health.data.device}</dd>
                  </div>
                ) : null}
              </dl>
            ) : (
              <Unavailable
                what="Autoencoder metrics"
                reason="models/artifacts/ae_metrics.json has not been written by a training run."
              />
            )
          ) : meta.isError ? (
            <Unavailable what="Autoencoder metadata" reason="/meta did not respond." />
          ) : (
            <Pending what="model metadata" />
          )}
        </Panel>
      </div>

      <Panel title="Per-class classifier performance" bodyClassName="p-0">
        {perClassRows.length ? (
          <div className="overflow-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>
                  {["Class", "Precision", "Recall", "F1", "Support", "FPR @ recall 0.95"].map(
                    (h, i) => (
                      <th
                        key={h}
                        className={cn(
                          "label-xs border-b border-border px-3 py-2 text-left font-medium whitespace-nowrap",
                          i > 0 && "text-right",
                        )}
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {perClassRows.map(([label, m]) => (
                  <tr key={label} className="border-b border-border/50 hover:bg-surface-raised/60">
                    <td className="px-3 py-1.5 whitespace-nowrap">{label}</td>
                    <td className="tech px-3 py-1.5 text-right">{fmtScore(m["precision"], 4)}</td>
                    <td className="tech px-3 py-1.5 text-right">{fmtScore(m["recall"], 4)}</td>
                    <td className="tech px-3 py-1.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Bar
                          value={m["f1-score"] ?? m["f1"] ?? 0}
                          className="w-16"
                          tone="bg-primary"
                        />
                        {fmtScore(m["f1-score"] ?? m["f1"], 4)}
                      </div>
                    </td>
                    <td className="tech px-3 py-1.5 text-right text-muted-foreground">
                      {m["support"] === undefined ? "—" : fmtInt(m["support"])}
                    </td>
                    <td className="tech px-3 py-1.5 text-right text-muted-foreground">
                      {fpr[label] === undefined ? "—" : fmtScore(fpr[label], 5)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : meta.isError ? (
          <Unavailable what="Per-class metrics" reason="/meta did not respond." className="px-4" />
        ) : (
          <Unavailable
            what="Per-class metrics"
            reason="classical_metrics.json reported no per-class block."
            className="px-4"
          />
        )}
      </Panel>

      {meta.data?.classes?.length ? (
        <Panel title="Label space">
          <ul className="flex flex-wrap gap-x-4 gap-y-1">
            {meta.data.classes.map((c) => (
              <li key={c} className="tech text-muted-foreground">
                {c}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  );
}

function ModelBadge({ level }: { level: StatusLevel }) {
  return (
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
        {level === "healthy" ? "LOADED" : statusLabel[level]}
      </span>
    </div>
  );
}
