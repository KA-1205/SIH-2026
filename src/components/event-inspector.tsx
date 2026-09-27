import { X } from "lucide-react";

import type { Alert } from "@/lib/api";
import {
  alertSeconds,
  fmtClock,
  fmtScore,
  parseFlow,
  threatClassLabel,
  verdictBg,
  verdictColor,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import { Bar } from "./primitives";

function Row({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-border/50 py-1.5 last:border-0">
      <span className="label-xs shrink-0">{k}</span>
      <span className={cn("min-w-0 truncate text-right", mono ? "tech" : "text-sm")}>{v}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-t border-border px-4 py-3">
      <h3 className="label-xs mb-2 text-foreground/80">{title}</h3>
      {children}
    </div>
  );
}

/**
 * Inspection panel. Every field comes from the /score alert record; nothing is
 * inferred. Fields the backend did not send render as "not reported".
 */
export function EventInspector({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  if (!alert) {
    return (
      <div className="flex h-full items-center justify-center border border-border bg-surface p-6">
        <p className="max-w-52 text-center text-sm text-muted-foreground">
          Select an event to inspect its features, model outputs and fusion evidence.
        </p>
      </div>
    );
  }

  const flow = parseFlow(alert.flow_id);
  const comp = alert.components;
  const probs = alert.class_probs
    ? Object.entries(alert.class_probs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
    : [];

  return (
    <aside
      key={`${alert.timestamp}-${alert.flow_id}`}
      className="panel-slide flex h-full min-h-0 flex-col overflow-y-auto border border-border bg-surface"
    >
      <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-border bg-surface px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn("size-[7px] rounded-full", verdictBg[alert.verdict])} />
            <span className={cn("tech tracking-wider", verdictColor[alert.verdict])}>
              {alert.verdict}
            </span>
            <span className="text-sm text-muted-foreground">
              {threatClassLabel[alert.threat_class] ?? alert.threat_class}
            </span>
          </div>
          <p className="tech mt-1 truncate text-muted-foreground">{alert.flow_id}</p>
        </div>
        <button
          onClick={onClose}
          className="text-muted-foreground transition-colors hover:text-foreground"
          aria-label="Close inspector"
        >
          <X className="size-4" />
        </button>
      </header>

      <div className="px-4 py-3">
        <div className="flex items-end justify-between gap-6">
          <div>
            <div className="label-xs">Fused threat score</div>
            <div className="metric mt-1 text-3xl">{fmtScore(alert.threat_score)}</div>
          </div>
          <div className="text-right">
            <div className="label-xs">Confidence</div>
            <div className="metric mt-1 text-xl">{fmtScore(alert.confidence)}</div>
          </div>
        </div>
        <Bar
          value={alert.threat_score}
          tone={alert.verdict === "OK" ? "bg-healthy" : verdictBg[alert.verdict]}
          className="mt-3"
        />
      </div>

      <Section title="Event metadata">
        <Row k="Timestamp" v={fmtClock(alertSeconds(alert))} />
        <Row
          k="Source"
          v={flow.src ? `${flow.src}${flow.srcPort ? `:${flow.srcPort}` : ""}` : "not reported"}
        />
        <Row
          k="Destination"
          v={flow.dst ? `${flow.dst}${flow.dstPort ? `:${flow.dstPort}` : ""}` : "not reported"}
        />
        <Row k="Protocol" v={flow.proto ?? "not reported"} />
        <Row k="Threat class" v={alert.threat_class} />
        <Row k="Detector" v={alert.detector} />
        <Row
          k="Latency"
          v={alert.latency_ms === null ? "not reported" : `${alert.latency_ms.toFixed(2)} ms`}
        />
      </Section>

      <Section title="Model outputs">
        <Row
          k="XGBoost / RF label"
          v={
            alert.predicted_label && alert.predicted_label !== "n/a"
              ? alert.predicted_label
              : "not reported"
          }
          mono={false}
        />
        <Row k="Best attack family" v={alert.attack_family || "not reported"} mono={false} />
        <Row
          k="LSTM-AE recon error"
          v={
            alert.ae_error === null || alert.ae_error === undefined
              ? "not reported"
              : fmtScore(alert.ae_error, 5)
          }
        />
        {comp ? (
          <>
            <Row k="Classifier term" v={fmtScore(comp.classifier)} />
            <Row k="Autoencoder term" v={fmtScore(comp.autoencoder)} />
            <Row k="Detector term" v={fmtScore(comp.detectors)} />
          </>
        ) : (
          <Row k="Score components" v="not reported" />
        )}
      </Section>

      {probs.length ? (
        <Section title="Classifier class probabilities">
          <div className="space-y-1.5">
            {probs.map(([label, p]) => (
              <div key={label}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="truncate text-sm">{label}</span>
                  <span className="tech text-muted-foreground">{p.toFixed(4)}</span>
                </div>
                <Bar
                  value={p}
                  tone={label === "BENIGN" ? "bg-healthy" : "bg-informational"}
                  className="mt-1"
                />
              </div>
            ))}
          </div>
        </Section>
      ) : null}

      <Section title="Evidence">
        {alert.evidence?.length ? (
          <ul className="space-y-2">
            {alert.evidence.map((e, i) => (
              <li key={i} className="border-l border-border-strong pl-2.5">
                <div className="flex items-baseline justify-between gap-3">
                  <span className="tech text-primary">{e.feature}</span>
                  {e.value !== null && e.value !== undefined ? (
                    <span className="tech text-muted-foreground">{e.value}</span>
                  ) : null}
                </div>
                <p className="mt-0.5 text-[0.8125rem] leading-relaxed text-muted-foreground">
                  {e.why}
                </p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="tech text-muted-foreground">No evidence rows reported</p>
        )}
      </Section>

      {alert.reasons?.length ? (
        <Section title="Fusion reasons">
          <ul className="space-y-1.5">
            {alert.reasons.map((r, i) => (
              <li key={i} className="text-[0.8125rem] leading-relaxed text-muted-foreground">
                {r}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
    </aside>
  );
}
