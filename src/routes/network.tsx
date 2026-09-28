import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

import { coverageQuery, metaQuery, recentAlertsQuery, statsQuery } from "@/lib/queries";
import { useAlertStream } from "@/hooks/useAlertStream";
import { fmtBytes, fmtInt, fmtScore, parseFlow, threatClassLabel } from "@/lib/format";
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
import { diodeLevel } from "@/lib/system";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/network")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "Traffic Analytics — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "Forward-only traffic telemetry: diode leak proof, packet and byte throughput, and the source/destination endpoints seen in scored windows.",
      },
      { property: "og:title", content: "Traffic Analytics — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content: "Diode proof, throughput and the endpoints observed on the monitor-side stream.",
      },
    ],
  }),
  component: Network,
});

function Network() {
  const stats = useQuery(statsQuery);
  const meta = useQuery(metaQuery);
  const recent = useQuery(recentAlertsQuery);
  const coverage = useQuery(coverageQuery);
  const stream = useAlertStream();

  const feed = useMemo(() => stream.merge(recent.data), [stream.rows, recent.data]);

  const endpoints = useMemo(() => {
    const map = new Map<
      string,
      { windows: number; maxScore: number; classes: Set<string>; protos: Set<string> }
    >();
    for (const a of feed) {
      const f = parseFlow(a.flow_id);
      const key = f.src ?? a.flow_id;
      const e = map.get(key) ?? {
        windows: 0,
        maxScore: 0,
        classes: new Set<string>(),
        protos: new Set<string>(),
      };
      e.windows += 1;
      e.maxScore = Math.max(e.maxScore, a.threat_score);
      if (a.threat_class) e.classes.add(a.threat_class);
      if (f.proto) e.protos.add(f.proto);
      map.set(key, e);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].maxScore - a[1].maxScore || b[1].windows - a[1].windows)
      .slice(0, 12);
  }, [feed]);

  const ports = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of feed) {
      const f = parseFlow(a.flow_id);
      if (!f.dstPort) continue;
      const key = `${f.dstPort}${f.proto ? `/${f.proto}` : ""}`;
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [feed]);

  const dLevel = diodeLevel(meta.data);
  const th = stats.data?.throughput;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Traffic Analytics"
        description="Review forward-only traffic crossing the data diode: throughput, endpoints and ports seen in scored windows."
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1fr)]">
        <Panel title="Data diode verification">
          {meta.data ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3 pb-1">
                <div className="flex items-center gap-2">
                  <StatusDot level={dLevel} pulse />
                  <span className="text-sm">One-way enforcement</span>
                </div>
                <span
                  className={cn(
                    "tech text-[0.6875rem] tracking-wider",
                    dLevel === "healthy" && "text-healthy",
                    dLevel === "offline" && "text-critical",
                    dLevel === "warning" && "text-suspicious",
                    dLevel === "unknown" && "text-muted-foreground",
                  )}
                >
                  {statusLabel[dLevel]}
                </span>
              </div>
              <dl className="divide-y divide-border/60">
                <Field
                  k="Proof artifact"
                  v={meta.data.diode.proof_present ? "present" : "not generated"}
                />
                <Field
                  k="Reverse bytes leaked"
                  v={
                    meta.data.diode.leaked_bytes === null
                      ? "not reported"
                      : `${meta.data.diode.leaked_bytes} B`
                  }
                />
                <Field
                  k="Forward delivery"
                  v={meta.data.diode.forward_delivery ?? "not reported"}
                />
                <Field k="Checked at" v={meta.data.diode.checked_at ?? "not reported"} />
              </dl>
              {!meta.data.diode.proof_present ? (
                <p className="text-[0.8125rem] leading-relaxed text-muted-foreground">
                  Run <span className="tech">diode/verify_diode.sh</span> to produce the proof file
                  the service reads.
                </p>
              ) : null}
            </div>
          ) : meta.isError ? (
            <Unavailable what="Diode proof" reason="/meta did not respond." />
          ) : (
            <Pending what="diode provenance" />
          )}
        </Panel>

        <Panel title="Forward traffic throughput" bodyClassName="p-0">
          {th ? (
            <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-4">
              <div className="p-3">
                <Metric label="Packets / s" value={th.pkts_s.toFixed(1)} />
              </div>
              <div className="p-3">
                <Metric label="Throughput" value={th.mbps.toFixed(3)} unit="Mbit/s" />
              </div>
              <div className="p-3">
                <Metric label="Packets total" value={fmtInt(th.pkts_total)} />
              </div>
              <div className="p-3">
                <Metric label="Bytes total" value={fmtBytes(th.bytes_total)} />
              </div>
            </div>
          ) : stats.isError ? (
            <Unavailable what="Throughput" reason="/stats did not respond." className="px-4" />
          ) : (
            <Pending what="throughput counters" />
          )}
          {th && th.pkts_total === 0 ? (
            <p className="px-3 py-2 text-[0.8125rem] text-muted-foreground">
              The extractor has not reported packet counts for any window yet (
              <span className="tech">win_pkts</span> is zero).
            </p>
          ) : null}
        </Panel>

        <Panel title="Detector coverage">
          {coverage.data ? (
            <ul className="divide-y divide-border/60">
              {Object.entries(coverage.data.classes).map(([detector, [cls, status]]) => {
                const level: StatusLevel = status === "production" ? "healthy" : "warning";
                return (
                  <li key={detector} className="flex items-baseline justify-between gap-3 py-1.5">
                    <div className="min-w-0">
                      <div className="tech truncate">{detector}</div>
                      <div className="text-[0.6875rem] text-muted-foreground">
                        {threatClassLabel[cls] ?? cls}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="tech text-[0.6875rem] text-muted-foreground">
                        {coverage.data.alerts_by_class[cls] ?? 0}
                      </span>
                      <StatusDot level={level} />
                      <span className="tech text-[0.6875rem] tracking-wider text-muted-foreground">
                        {status.toUpperCase()}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : coverage.isError ? (
            <Unavailable what="Coverage matrix" reason="/coverage did not respond." />
          ) : (
            <Pending what="coverage matrix" />
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Panel title="Endpoints seen in scored windows" bodyClassName="overflow-auto p-0">
          {endpoints.length ? (
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>
                  {["Source", "Windows", "Protocols", "Threat classes", "Max fused"].map((h, i) => (
                    <th
                      key={h}
                      className={cn(
                        "label-xs border-b border-border px-3 py-2 text-left font-medium",
                        (i === 1 || i === 4) && "text-right",
                      )}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {endpoints.map(([src, e]) => (
                  <tr key={src} className="border-b border-border/50 hover:bg-surface-raised/60">
                    <td className="tech px-3 py-1.5">{src}</td>
                    <td className="tech px-3 py-1.5 text-right text-muted-foreground">
                      {e.windows}
                    </td>
                    <td className="tech px-3 py-1.5 text-muted-foreground">
                      {e.protos.size ? Array.from(e.protos).join(" ") : "—"}
                    </td>
                    <td className="px-3 py-1.5 text-[0.8125rem] text-muted-foreground">
                      {Array.from(e.classes)
                        .map((c) => threatClassLabel[c] ?? c)
                        .join(", ")}
                    </td>
                    <td className="tech px-3 py-1.5 text-right">{fmtScore(e.maxScore)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Pending what="scored windows" />
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="Destination ports">
            {ports.length ? (
              <div className="space-y-2">
                {ports.map(([p, n]) => (
                  <div key={p}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="tech">{p}</span>
                      <span className="tech text-muted-foreground">{n}</span>
                    </div>
                    <Bar value={n} max={ports[0]?.[1] ?? 1} className="mt-1" />
                  </div>
                ))}
              </div>
            ) : (
              <Unavailable
                what="Port breakdown"
                reason="Scored windows carried no destination port in flow_id."
              />
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <dt className="label-xs">{k}</dt>
      <dd className="tech">{v}</dd>
    </div>
  );
}
