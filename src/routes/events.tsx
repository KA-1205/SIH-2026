import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Search } from "lucide-react";

import type { Alert, Verdict } from "@/lib/api";
import { recentAlertsQuery } from "@/lib/queries";
import { useAlertStream } from "@/hooks/useAlertStream";
import { alertKey, threatClassLabel } from "@/lib/format";
import { EventTable, useTableSort } from "@/components/event-table";
import { EventInspector } from "@/components/event-inspector";
import { PageHeader, Panel, Pending, StatusDot, Unavailable } from "@/components/primitives";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/events")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { title: "Live Traffic — Sanchar Saṅgaṇaka" },
      {
        name: "description",
        content:
          "Dense live table of every scored traffic window: flow, protocol, classifier label, LSTM reconstruction error, fused score and verdict, with a full inspection panel.",
      },
      { property: "og:title", content: "Live Traffic — Sanchar Saṅgaṇaka" },
      {
        property: "og:description",
        content: "Every scored window from the diode pipeline, searchable and inspectable.",
      },
    ],
  }),
  component: LiveEvents,
});

const VERDICTS: Array<Verdict | "ALL"> = ["ALL", "OK", "MEDIUM", "HIGH"];

function LiveEvents() {
  const recent = useQuery(recentAlertsQuery);
  const stream = useAlertStream();
  const { sortKey, setSortKey } = useTableSort("time");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [query, setQuery] = useState("");
  const [verdict, setVerdict] = useState<Verdict | "ALL">("ALL");
  const [threatClass, setThreatClass] = useState<string>("ALL");

  const feed = useMemo(() => stream.merge(recent.data), [stream.rows, recent.data]);

  const classes = useMemo(
    () => Array.from(new Set(feed.map((r) => r.threat_class))).sort(),
    [feed],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return feed.filter((r) => {
      if (verdict !== "ALL" && r.verdict !== verdict) return false;
      if (threatClass !== "ALL" && r.threat_class !== threatClass) return false;
      if (!q) return true;
      return (
        r.flow_id.toLowerCase().includes(q) ||
        r.threat_class.toLowerCase().includes(q) ||
        (r.detector ?? "").toLowerCase().includes(q) ||
        (r.predicted_label ?? "").toLowerCase().includes(q) ||
        (r.attack_family ?? "").toLowerCase().includes(q)
      );
    });
  }, [feed, query, verdict, threatClass]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Live Traffic"
        description="Review and investigate every traffic window as the detection pipeline scores it."
        right={
          <div className="flex items-center gap-2">
            <StatusDot
              level={
                stream.state === "live"
                  ? "healthy"
                  : stream.state === "connecting"
                    ? "warning"
                    : "offline"
              }
              pulse
            />
            <span className="tech text-[0.6875rem] text-muted-foreground">
              {stream.state === "live"
                ? `live · ${feed.length} buffered`
                : stream.state === "connecting"
                  ? "connecting"
                  : "stream offline"}
            </span>
          </div>
        }
      />

      <div className="space-y-4 xl:flex xl:h-[calc(100dvh-330px)] xl:min-h-0 xl:flex-col xl:space-y-0 xl:gap-4">
        <Panel
          bodyClassName="flex min-h-0 flex-1 flex-col overflow-hidden p-0"
          title="Scored windows"
          className="min-h-0 xl:flex-1"
          right={
            <span className="tech text-[0.6875rem] text-muted-foreground">
              {filtered.length} / {feed.length} shown
            </span>
          }
        >
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2">
            <div className="flex min-w-48 flex-1 items-center gap-2 border border-border bg-background px-2 py-1">
              <Search className="size-3.5 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="filter by IP, port, class, detector, family"
                className="tech w-full bg-transparent py-0.5 outline-none placeholder:text-muted-foreground/70"
              />
            </div>

            <div className="flex items-center border border-border">
              {VERDICTS.map((v) => (
                <button
                  key={v}
                  onClick={() => setVerdict(v)}
                  className={cn(
                    "tech border-r border-border px-2 py-1 text-[0.6875rem] tracking-wider last:border-0 transition-colors",
                    verdict === v
                      ? "bg-surface-raised text-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {v}
                </button>
              ))}
            </div>

            <select
              value={threatClass}
              onChange={(e) => setThreatClass(e.target.value)}
              className="tech border border-border bg-background px-2 py-1 outline-none"
            >
              <option value="ALL">all threat classes</option>
              {classes.map((c) => (
                <option key={c} value={c}>
                  {threatClassLabel[c] ?? c}
                </option>
              ))}
            </select>
          </div>

          {filtered.length ? (
            <div className="min-h-0 flex-1 overflow-auto">
              <EventTable
                rows={filtered}
                selectedKey={selected ? alertKey(selected) : null}
                onSelect={setSelected}
                sortKey={sortKey}
                onSortChange={setSortKey}
                newestKey={feed[0] ? alertKey(feed[0]) : null}
              />
            </div>
          ) : recent.isError && stream.state === "offline" ? (
            <Unavailable
              what="Event feed"
              reason="Unable to load live events: neither /recent_alerts nor /ws/alerts responded. The rest of the console remains usable."
              onRetry={() => void recent.refetch()}
              className="px-4"
            />
          ) : feed.length ? (
            <div className="px-4 py-8">
              <p className="tech text-muted-foreground">No window matches the filter</p>
            </div>
          ) : (
            <Pending what="scored windows" />
          )}
        </Panel>

        <Panel
          title="General anomaly"
          bodyClassName="min-h-0 flex-1 overflow-hidden p-0"
          className="min-h-0 xl:flex-1"
        >
          <EventInspector
            alert={selected}
            onClose={() => setSelected(null)}
            columns
            framed={false}
          />
        </Panel>
      </div>
    </div>
  );
}
