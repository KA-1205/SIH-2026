import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, Panel } from "@/components/primitives";

const TITLE = "About — Sanchar Saṅgaṇaka";
const DESC =
  "Sanchar Saṅgaṇaka: AI based detection of cyber threats in unidirectional IP traffic. SIH 2026 problem statement 26145, team HarTimeError.";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESC },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESC },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: About,
});

const FACTS: Array<[string, string]> = [
  ["Project", "Sanchar Saṅgaṇaka"],
  ["Problem statement", "AI Based Detection of Cyber Threats in Unidirectional IP Traffic"],
  ["SIH problem statement ID", "26145"],
  ["Edition", "Smart India Hackathon 2026"],
  ["Team", "HarTimeError"],
];

const PIPELINE: Array<[string, string]> = [
  [
    "Data diode",
    "Traffic crosses a one-way link; nothing is ever sent back to the monitored network.",
  ],
  ["Packet capture", "Packets are captured on the receiving side of the diode."],
  [
    "Forward-only feature extraction",
    "Flow windows are summarised using only forward-direction features.",
  ],
  ["RF / XGBoost", "Classifies windows into known attack types."],
  ["LSTM autoencoder", "Flags novel or unseen patterns through reconstruction error."],
  [
    "Alert fusion",
    "Combines both model signals and rule detectors into one threat score and verdict.",
  ],
  [
    "Live traffic and real-time alerts",
    "Every scored window is streamed to this console as it is processed.",
  ],
];

function About() {
  return (
    <div className="space-y-4">
      <PageHeader
        title="About"
        description="The project behind this console and how its detection pipeline is put together."
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Panel title="Project">
          <dl className="divide-y divide-border/60">
            {FACTS.map(([k, v]) => (
              <div
                key={k}
                className="flex flex-col gap-0.5 py-2 sm:flex-row sm:justify-between sm:gap-4"
              >
                <dt className="label-xs shrink-0">{k}</dt>
                <dd className="min-w-0 text-sm sm:text-right">{v}</dd>
              </div>
            ))}
          </dl>
        </Panel>
        <Panel title="Detection pipeline">
          <ol className="divide-y divide-border/60">
            {PIPELINE.map(([k, v], i) => (
              <li key={k} className="flex gap-3 py-2">
                <span className="tech w-4 shrink-0 text-muted-foreground">{i + 1}</span>
                <div className="min-w-0">
                  <p className="text-sm">{k}</p>
                  <p className="text-[0.8125rem] text-muted-foreground">{v}</p>
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </div>
  );
}
