export type FinishOutcome =
  | { state: "pending" }
  | { state: "completed" }
  | { state: "failed"; reason: string };

export function getFinishOutcome(status: string, result: unknown): FinishOutcome {
  const output = result && typeof result === "object" && !Array.isArray(result)
    ? result as Record<string, unknown>
    : {};

  if (status === "running") return { state: "pending" };
  if (status === "completed" && output.success === true && output.scan_completed === true) {
    return { state: "completed" };
  }

  const reason = typeof output.error === "string" && output.error.trim()
    ? output.error
    : status === "completed"
      ? "The completion receipt was not confirmed."
      : "The finish action failed before the scan was finalized.";
  return { state: "failed", reason };
}
