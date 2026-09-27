import { useMemo, useState } from "react";

import type { Alert } from "@/lib/api";
import { alertKey, alertSeconds, fmtClock, fmtScore, parseFlow, verdictColor } from "@/lib/format";
import { cn } from "@/lib/utils";

export type SortKey = "time" | "score" | "confidence" | "latency";

export function EventTable({
  rows,
  selectedKey,
  onSelect,
  sortKey = "time",
  onSortChange,
  newestKey,
  dense = true,
  compact = false,
}: {
  rows: Alert[];
  selectedKey: string | null;
  onSelect: (row: Alert) => void;
  sortKey?: SortKey | undefined;
  onSortChange?: (key: SortKey) => void | undefined;
  newestKey?: string | null | undefined;
  dense?: boolean | undefined;
  compact?: boolean | undefined;
}) {
  const sorted = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      switch (sortKey) {
        case "score":
          return b.threat_score - a.threat_score;
        case "confidence":
          return b.confidence - a.confidence;
        case "latency":
          return (b.latency_ms ?? 0) - (a.latency_ms ?? 0);
        default:
          return alertSeconds(b) - alertSeconds(a);
      }
    });
    return copy;
  }, [rows, sortKey]);

  const Th = ({
    children,
    sort,
    className,
  }: {
    children: React.ReactNode;
    sort?: SortKey | undefined;
    className?: string | undefined;
  }) => (
    <th
      className={cn(
        "label-xs sticky top-0 z-10 border-b border-border bg-surface px-2 py-2 text-left font-medium whitespace-nowrap",
        sort && onSortChange && "cursor-pointer hover:text-foreground",
        sort && sortKey === sort && "text-primary",
        className,
      )}
      onClick={sort && onSortChange ? () => onSortChange(sort) : undefined}
    >
      {children}
    </th>
  );

  return (
    <div className="min-w-0 overflow-auto">
      <table className={cn("w-full border-collapse text-sm", compact && "table-fixed")}>
        <thead>
          <tr>
            <Th sort="time" className={compact ? "w-[20%]" : undefined}>
              Time
            </Th>
            <Th className={compact ? "w-[20%]" : undefined}>Source</Th>
            <Th className={compact ? "hidden" : "hidden sm:table-cell"}>Destination</Th>
            <Th className={compact ? "hidden" : "hidden md:table-cell"}>Proto</Th>
            <Th className={compact ? "hidden" : "hidden text-right md:table-cell"}>Port</Th>
            <Th className={compact ? "w-[26%]" : undefined}>Classification</Th>
            <Th className={compact ? "hidden" : "hidden lg:table-cell"}>Detector</Th>
            <Th sort="score" className={cn(compact && "w-[14%]", "text-right")}>
              Fused
            </Th>
            <Th
              sort="confidence"
              className={compact ? "hidden" : "hidden text-right lg:table-cell"}
            >
              Conf
            </Th>
            <Th className={compact ? "hidden" : "hidden text-right xl:table-cell"}>AE err</Th>
            <Th sort="latency" className={compact ? "hidden" : "hidden text-right xl:table-cell"}>
              Lat ms
            </Th>
            <Th className={compact ? "w-[20%]" : undefined}>Verdict</Th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const key = alertKey(row);
            const flow = parseFlow(row.flow_id);
            const selected = key === selectedKey;
            return (
              <tr
                key={key}
                onClick={() => onSelect(row)}
                className={cn(
                  "cursor-pointer border-b border-border/50 transition-colors",
                  dense ? "h-8" : "h-10",
                  selected
                    ? "bg-surface-raised"
                    : "hover:bg-surface-raised/60 even:bg-foreground/[0.012]",
                  key === newestKey && "row-enter",
                )}
              >
                <td className="tech px-2 whitespace-nowrap text-muted-foreground">
                  {fmtClock(alertSeconds(row))}
                </td>
                <td
                  className="tech max-w-[14rem] truncate px-2 whitespace-nowrap"
                  title={row.flow_id}
                >
                  {flow.src ?? row.flow_id}
                  {flow.srcPort ? (
                    <span className="text-muted-foreground">:{flow.srcPort}</span>
                  ) : null}
                </td>
                <td
                  className={cn(
                    "tech max-w-[12rem] truncate px-2 whitespace-nowrap",
                    compact ? "hidden" : "hidden sm:table-cell",
                  )}
                >
                  {flow.dst ?? "—"}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-muted-foreground",
                    compact ? "hidden" : "hidden md:table-cell",
                  )}
                >
                  {flow.proto ?? "—"}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-right text-muted-foreground",
                    compact ? "hidden" : "hidden md:table-cell",
                  )}
                >
                  {flow.dstPort ?? "—"}
                </td>
                <td className="max-w-[12rem] truncate px-2 whitespace-nowrap">
                  {row.predicted_label && row.predicted_label !== "n/a"
                    ? row.predicted_label
                    : row.threat_class}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-muted-foreground",
                    compact ? "hidden" : "hidden lg:table-cell",
                  )}
                >
                  {row.detector}
                </td>
                <td className="tech px-2 text-right">{fmtScore(row.threat_score)}</td>
                <td
                  className={cn(
                    "tech px-2 text-right text-muted-foreground",
                    compact ? "hidden" : "hidden lg:table-cell",
                  )}
                >
                  {fmtScore(row.confidence)}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-right text-muted-foreground",
                    compact ? "hidden" : "hidden xl:table-cell",
                  )}
                >
                  {row.ae_error === null || row.ae_error === undefined
                    ? "—"
                    : fmtScore(row.ae_error, 4)}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-right text-muted-foreground",
                    compact ? "hidden" : "hidden xl:table-cell",
                  )}
                >
                  {row.latency_ms === null || row.latency_ms === undefined
                    ? "—"
                    : row.latency_ms.toFixed(2)}
                </td>
                <td
                  className={cn(
                    "tech px-2 text-[0.6875rem] tracking-wider",
                    verdictColor[row.verdict],
                  )}
                >
                  {row.verdict}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function useTableSort(initial: SortKey = "time") {
  const [sortKey, setSortKey] = useState<SortKey>(initial);
  return { sortKey, setSortKey };
}
