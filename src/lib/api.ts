/**
 * API client for the SIH26145 FastAPI inference service (serving/app.py).
 *
 * Real endpoints only:
 *   GET  /health         model/artifact status + latency
 *   GET  /stats          verdict / family tallies, throughput, latency
 *   GET  /trend?n=       every scored window (benign included)
 *   GET  /recent_alerts?n=
 *   GET  /coverage       threat-class coverage matrix
 *   GET  /meta           model metrics + diode provenance
 *   WS   /ws/alerts      live push of every scored window
 */

export const API_BASE = (
  (import.meta.env["VITE_API_BASE_URL"] as string | undefined) ?? "http://127.0.0.1:8200"
).replace(/\/$/, "");

export const WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws/alerts`;

export type Verdict = "OK" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Evidence = {
  feature: string;
  value: number | null;
  why: string;
};

/** One scored window, as assembled by serving/alert_schema.build_alert. */
export type Alert = {
  /** epoch seconds, added by /score, /recent_alerts and the WS push */
  ts?: number;
  /** epoch milliseconds, from the alert contract */
  timestamp: number;
  flow_id: string;
  threat_class: string;
  verdict: Verdict;
  threat_score: number;
  confidence: number;
  detector: string;
  evidence: Evidence[];
  latency_ms: number | null;
  reasons?: string[];
  components?: {
    classifier: number;
    autoencoder: number;
    detectors: number;
  };
  predicted_label?: string;
  attack_family?: string;
  detected_class?: string;
  class_probs?: Record<string, number>;
  ae_error?: number | null;
};

export type Health = {
  classifier: boolean;
  autoencoder: boolean;
  device: string;
  windows_scored: number;
  uptime_s: number;
  ws_clients: number;
  avg_latency_ms: number | null;
  p95_latency_ms: number | null;
};

export type Stats = {
  windows_scored: number;
  alerts: number;
  by_verdict: Record<string, number>;
  by_family: Record<string, number>;
  throughput: {
    pkts_total: number;
    bytes_total: number;
    pkts_s: number;
    mbps: number;
  };
  latency_ms: { avg: number | null; p95: number | null };
};

export type TrendPoint = { ts: number; threat_score: number; verdict: Verdict };

export type Coverage = {
  /** detector name -> [threat_class, "production" | "prototype"] */
  classes: Record<string, [string, string]>;
  alerts_by_class: Record<string, number>;
};

export type SimulationResult = { status: "complete" };

export type Meta = {
  classes: string[];
  n_features: number;
  classifier_metrics: {
    macro_f1: number | null;
    accuracy: number | null;
    n_rows: number | null;
    n_train: number | null;
    n_test: number | null;
  };
  per_class: Record<string, Record<string, number>>;
  fpr_at_recall95: Record<string, number>;
  autoencoder_metrics: Record<string, number | string>;
  top_features: string[];
  diode: {
    proof_present: boolean;
    zero_reverse_packets: boolean | null;
    leaked_bytes: number | null;
    forward_delivery: string | null;
    checked_at?: string;
  };
};

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const init: RequestInit = { headers: { accept: "application/json" } };
  if (signal) init.signal = signal;
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function post<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { accept: "application/json" },
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { detail?: unknown } | null;
    throw new Error(
      typeof body?.detail === "string" ? body.detail : `${path} → HTTP ${res.status}`,
    );
  }
  return (await res.json()) as T;
}

export const api = {
  health: (signal?: AbortSignal) => get<Health>("/health", signal),
  stats: (signal?: AbortSignal) => get<Stats>("/stats", signal),
  trend: (n = 120, signal?: AbortSignal) => get<TrendPoint[]>(`/trend?n=${n}`, signal),
  recentAlerts: (n = 50, signal?: AbortSignal) => get<Alert[]>(`/recent_alerts?n=${n}`, signal),
  coverage: (signal?: AbortSignal) => get<Coverage>("/coverage", signal),
  meta: (signal?: AbortSignal) => get<Meta>("/meta", signal),
  runSimulation: () => post<SimulationResult>("/demo/run"),
};
