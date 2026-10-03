export type FindingTab = "fix" | "reproduction";

export function resolveFindingTab(
  active: FindingTab,
  hasFix: boolean,
  hasReproduction: boolean
): FindingTab {
  if (active === "fix" && hasFix) return "fix";
  if (active === "reproduction" && hasReproduction) return "reproduction";
  return hasFix ? "fix" : "reproduction";
}
