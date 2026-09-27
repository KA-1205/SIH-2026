import { useEffect, useRef, useState } from "react";

import { WS_URL, type Alert } from "@/lib/api";
import { alertKey } from "@/lib/format";

export type StreamState = "connecting" | "live" | "offline";

const MAX_ROWS = 300;

/**
 * Subscribes to WS /ws/alerts. The backend pushes EVERY scored window
 * (benign included), so this is the live event feed, not only alerts.
 * Reconnects with a fixed backoff; no data is synthesised while offline.
 */
export function useAlertStream(enabled = true) {
  const [rows, setRows] = useState<Alert[]>([]);
  const [state, setState] = useState<StreamState>(enabled ? "connecting" : "offline");
  const [lastAt, setLastAt] = useState<number | null>(null);
  const [resetAt, setResetAt] = useState<number | null>(null);
  const seen = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!enabled || typeof window === "undefined") return;
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      setState("connecting");
      try {
        socket = new WebSocket(WS_URL);
      } catch {
        setState("offline");
        retry = setTimeout(connect, 4000);
        return;
      }
      socket.onopen = () => setState("live");
      socket.onmessage = (ev) => {
        try {
          const message = JSON.parse(ev.data as string) as unknown;
          if (
            typeof message === "object" &&
            message !== null &&
            "type" in message &&
            message.type === "reset"
          ) {
            setRows([]);
            setLastAt(null);
            setResetAt(Date.now());
            seen.current.clear();
            return;
          }

          const row = message as Alert;
          const key = alertKey(row);
          if (seen.current.has(key)) return;
          seen.current.add(key);
          if (seen.current.size > 2000) seen.current = new Set([key]);
          setRows((prev) => [row, ...prev].slice(0, MAX_ROWS));
          setLastAt(Date.now());
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (closed) return;
        setState("offline");
        retry = setTimeout(connect, 4000);
      };
    };

    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      socket?.close();
    };
  }, [enabled]);

  /** Merge polled backfill rows under the live ones, de-duplicated. */
  const merge = (backfill: Alert[] | undefined) => {
    const currentBackfill = backfill?.filter((row) => resetAt === null || row.timestamp >= resetAt);
    if (!currentBackfill?.length) return rows;
    const keys = new Set(rows.map(alertKey));
    const extra = currentBackfill.filter((r) => !keys.has(alertKey(r)));
    return [...rows, ...extra.reverse()].slice(0, MAX_ROWS);
  };

  return { rows, state, lastAt, resetAt, merge };
}
