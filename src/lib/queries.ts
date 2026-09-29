import { mutationOptions, queryOptions } from "@tanstack/react-query";

import { api } from "./api";

/**
 * Polling intervals mirror how fast the backend actually changes:
 * health/stats every 3s, the trend every 2s, coverage/meta are near-static.
 * Live alert rows arrive over the WebSocket, /recent_alerts is the backfill.
 */
export const healthQuery = queryOptions({
  queryKey: ["health"],
  queryFn: ({ signal }) => api.health(signal),
  refetchInterval: 3000,
  retry: (failureCount) => failureCount < 25,
  retryDelay: (attempt) => Math.min(1500 * 2 ** (attempt - 1), 15000),
});

export const statsQuery = queryOptions({
  queryKey: ["stats"],
  queryFn: ({ signal }) => api.stats(signal),
  refetchInterval: 3000,
  retry: false,
});

export const trendQuery = queryOptions({
  queryKey: ["trend"],
  queryFn: ({ signal }) => api.trend(180, signal),
  refetchInterval: 2000,
  retry: false,
});

export const recentAlertsQuery = queryOptions({
  queryKey: ["recent_alerts"],
  queryFn: ({ signal }) => api.recentAlerts(100, signal),
  refetchInterval: 5000,
  retry: false,
});

export const coverageQuery = queryOptions({
  queryKey: ["coverage"],
  queryFn: ({ signal }) => api.coverage(signal),
  refetchInterval: 10000,
  retry: false,
});

export const metaQuery = queryOptions({
  queryKey: ["meta"],
  queryFn: ({ signal }) => api.meta(signal),
  refetchInterval: 60000,
  retry: false,
});

export const runSimulationMutation = mutationOptions({
  mutationKey: ["run_simulation"],
  mutationFn: () => api.runSimulation(),
});
