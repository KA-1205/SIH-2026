import type { Alert, Verdict } from "./api";

/** flow_id contract: "10.0.2.7:51324 -> 8.8.8.8:53/UDP" (may be freeform). */
export type Flow = {
  src: string | null;
  srcPort: string | null;
  dst: string | null;
  dstPort: string | null;
  proto: string | null;
  raw: string;
};

export function parseFlow(flowId: string): Flow {
  const raw = flowId ?? "";
  const empty: Flow = {
    src: null,
    srcPort: null,
    dst: null,
    dstPort: null,
    proto: null,
    raw,
  };
  const m = raw.match(/^\s*(\S+?)(?::(\d+))?\s*->\s*(\S+?)(?::(\d+))?(?:\/(\w+))?\s*$/);
  if (!m) return empty;
  return {
    src: m[1] ?? null,
    srcPort: m[2] ?? null,
    dst: m[3] ?? null,
    dstPort: m[4] ?? null,
    proto: m[5] ? m[5].toUpperCase() : null,
    raw,
  };
}

export function alertSeconds(a: Alert): number {
  return a.ts ?? a.timestamp / 1000;
}

export function alertKey(a: Alert): string {
  return `${a.timestamp}-${a.flow_id}-${a.threat_score}`;
}

export function fmtTime(seconds: number): string {
  const d = new Date(seconds * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

export function fmtClock(seconds: number): string {
  const d = new Date(seconds * 1000);
  return `${d.toLocaleTimeString("en-GB", { hour12: false })}.${String(
    d.getMilliseconds(),
  ).padStart(3, "0")}`;
}

export function fmtScore(n: number | null | undefined, digits = 3): string {
  return n === null || n === undefined ? "—" : n.toFixed(digits);
}

export function fmtInt(n: number | null | undefined): string {
  return n === null || n === undefined ? "—" : n.toLocaleString("en-US");
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtUptime(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}

/** Fusion verdict bands: >= 0.50 HIGH, >= 0.25 MEDIUM, else OK. */
export const verdictColor: Record<Verdict | string, string> = {
  OK: "text-healthy",
  MEDIUM: "text-suspicious",
  HIGH: "text-critical",
  CRITICAL: "text-critical",
};

export const verdictBg: Record<Verdict | string, string> = {
  OK: "bg-healthy",
  MEDIUM: "bg-suspicious",
  HIGH: "bg-critical",
  CRITICAL: "bg-critical",
};

export const threatClassLabel: Record<string, string> = {
  volumetric: "Volumetric / DDoS",
  beacon: "C2 beaconing",
  dns_tunneling: "DNS tunnelling / DGA",
  tls_malware: "Encrypted-session malware",
  scan_recon: "Recon / port scan",
  exfiltration: "Data exfiltration",
  anomaly: "General anomaly",
};
