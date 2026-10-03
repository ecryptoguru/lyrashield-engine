export type RunStatusTone = "live" | "completed" | "stopped" | "interrupted" | "failed" | "unknown";

export function getRunStatusDisplay(
  status: string | null,
  finished: boolean
): { label: string; tone: RunStatusTone } {
  if (!finished) return { label: "Live", tone: "live" };

  switch (status?.toLowerCase()) {
    case "completed":
      return { label: "Complete", tone: "completed" };
    case "stopped":
      return { label: "Stopped", tone: "stopped" };
    case "interrupted":
      return { label: "Interrupted", tone: "interrupted" };
    case "failed":
      return { label: "Failed", tone: "failed" };
    default:
      return { label: "Finished", tone: "unknown" };
  }
}
