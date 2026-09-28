import type { Health, Meta, Stats } from "./api";
import type { StatusLevel } from "@/components/primitives";
import type { PipelineActivity, Stage } from "@/components/pipeline-flow";

export type Inputs = {
  health: Health | undefined;
  healthError: boolean;
  stats: Stats | undefined;
  meta: Meta | undefined;
  streamState: "connecting" | "live" | "offline";
  /** epoch ms of the last window received over the WebSocket */
  lastEventAt: number | null;
};

export function apiLevel(i: Inputs): StatusLevel {
  if (i.healthError) return "offline";
  if (!i.health) return "unknown";
  return "healthy";
}

export function diodeLevel(meta: Meta | undefined): StatusLevel {
  if (!meta) return "unknown";
  const d = meta.diode;
  if (!d?.proof_present) return "unknown";
  if (d.zero_reverse_packets === false) return "offline";
  if (d.zero_reverse_packets === true) return "healthy";
  return "warning";
}

export function streamLevel(i: Inputs): StatusLevel {
  if (i.streamState === "live") return "healthy";
  if (i.streamState === "connecting") return "warning";
  return "offline";
}

/** "Traffic is arriving" == a window was scored in the last 15 s. */
export function extractionLevel(i: Inputs): StatusLevel {
  if (i.healthError) return "offline";
  if (i.lastEventAt && Date.now() - i.lastEventAt < 15_000) return "healthy";
  if ((i.health?.windows_scored ?? 0) > 0) return "warning";
  return "unknown";
}

export function activityOf(i: Inputs): PipelineActivity {
  if (!i.lastEventAt) return "idle";
  const age = Date.now() - i.lastEventAt;
  if (age < 2500) return "busy";
  if (age < 20_000) return "flowing";
  return "idle";
}

export function buildStages(i: Inputs): Stage[] {
  const h = i.health;
  const diode = diodeLevel(i.meta);
  const extraction = extractionLevel(i);
  const clf: StatusLevel = i.healthError
    ? "offline"
    : h
      ? h.classifier
        ? "healthy"
        : "offline"
      : "unknown";
  const ae: StatusLevel = i.healthError
    ? "offline"
    : h
      ? h.autoencoder
        ? "healthy"
        : "offline"
      : "unknown";
  const fusion: StatusLevel =
    clf === "healthy" || ae === "healthy" ? "healthy" : i.healthError ? "offline" : "unknown";
  const scored = h?.windows_scored ?? 0;

  return [
    {
      id: "diode",
      label: "DATA DIODE",
      detail:
        i.meta?.diode?.proof_present && i.meta.diode.forward_delivery
          ? `fwd ${i.meta.diode.forward_delivery} · leak ${i.meta.diode.leaked_bytes ?? "?"}B`
          : diode === "unknown"
            ? "no proof artifact"
            : "proof present",
      level: diode,
    },
    {
      id: "extraction",
      label: "FEATURE EXTRACTION",
      detail: i.meta ? `${i.meta.n_features} features` : "—",
      level: extraction,
    },
    {
      id: "classifier",
      label: "XGBOOST / RF",
      detail: h
        ? h.classifier
          ? `${i.meta?.classes?.length ?? 0} classes`
          : "artifact missing"
        : "—",
      level: clf,
    },
    {
      id: "autoencoder",
      label: "LSTM AUTOENCODER",
      detail: h ? (h.autoencoder ? `device ${h.device}` : "artifact missing") : "—",
      level: ae,
    },
    {
      id: "fusion",
      label: "FUSION",
      detail: i.stats ? `${i.stats.alerts} alerts` : "—",
      level: fusion,
    },
    {
      id: "score",
      label: "THREAT SCORE",
      detail: scored ? `${scored.toLocaleString("en-US")} windows` : "no windows yet",
      level: scored > 0 ? "healthy" : i.healthError ? "offline" : "unknown",
    },
  ];
}
