import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, LoaderCircle, Play } from "lucide-react";

import { runSimulationMutation } from "@/lib/queries";

export function SimulationButton() {
  const queryClient = useQueryClient();
  const simulation = useMutation({
    ...runSimulationMutation,
    onSuccess: async () => {
      await Promise.all(
        ["health", "stats", "trend", "recent_alerts", "coverage"].map((queryKey) =>
          queryClient.invalidateQueries({ queryKey: [queryKey] }),
        ),
      );
    },
  });

  return (
    <div className="flex min-w-0 flex-wrap items-center justify-end gap-2">
      {simulation.isError ? (
        <span className="max-w-52 truncate text-[0.6875rem] text-critical" role="alert">
          {simulation.error.message}
        </span>
      ) : null}
      {simulation.isSuccess ? (
        <span className="tech text-[0.6875rem] text-healthy" role="status">
          make drive complete
        </span>
      ) : null}
      <button
        type="button"
        onClick={() => simulation.mutate()}
        disabled={simulation.isPending}
        className="inline-flex h-9 min-w-[11rem] items-center justify-center gap-2 border border-border bg-surface px-3 text-sm transition-colors hover:bg-surface-raised disabled:cursor-wait disabled:opacity-60"
      >
        {simulation.isPending ? (
          <LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" />
        ) : simulation.isSuccess ? (
          <Check className="size-4" />
        ) : (
          <Play className="size-4" />
        )}
        {simulation.isPending
          ? "Running make drive..."
          : simulation.isSuccess
            ? "Run make drive again"
            : "Run make drive"}
      </button>
    </div>
  );
}
