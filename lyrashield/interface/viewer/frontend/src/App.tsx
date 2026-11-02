import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  AlertCircle,
  Bot,
  Mail,
  ChevronDown,
  History,
} from "lucide-react";
import type { Vulnerability, VulnerabilitySeverity } from "@/types/issues";
import { SEVERITY_COLORS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { ContentSection } from "@/components/vulnerability/ContentSection";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import { buildGraphAgents } from "@/components/live/AgentTranscript";
import AgentDetailModal from "@/components/live/AgentDetailModal";
import { ScanPromptComposer } from "@/components/live/ScanPromptComposer";
import { severityCounts, type ParsedRunSummary } from "@/lib/local-run-parser";
import {
  fetchAuthStatus,
  fetchCapabilities,
  fetchRuns,
  forgetAuth,
  type AuthStatus,
  type LoadedRun,
  type RunsPayload,
} from "@/data/serverSource";
import { useResource, useRunResources } from "@/data/useRunResources";
import { runTitle } from "@/lib/target-utils";
import { getRunStatusDisplay } from "@/lib/run-status";
import Sidebar from "@/components/Sidebar";
import PastRunsView from "@/components/PastRunsView";
import EmailReportView from "@/components/EmailReportView";
import { RunDetails } from "@/components/RunDetails";
import { TrustToast } from "@/components/TrustToast";
import { ReportLoadError } from "@/components/ReportLoadError";

export type View = "overview" | "issues" | "agents" | "history" | "email";

const TRUST_BANNER =
  "This viewer displays local scan results. Exported reports can contain sensitive target details; share them carefully.";

const SEVERITY_ORDER: VulnerabilitySeverity[] = ["critical", "high", "medium", "low"];
const AgentGraph = lazy(() => import("@/components/live/AgentGraph"));

export default function App() {
  const [activeRun, setActiveRun] = useState<string | null>(null);
  const resources = useRunResources(activeRun);
  const { run } = resources;
  const error = resources.summary.error ? "Run summary could not be loaded." : null;
  const [forgetError, setForgetError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const history = useResource("history", signal => fetchRuns(signal));
  const runs = history.data;
  const refreshRuns = history.retry;
  const [launchedName, setLaunchedName] = useState("Current run");
  const capabilities = useResource("capabilities", signal => fetchCapabilities(signal), () => false);
  const canSteer = capabilities.data?.can_steer === true;
  const canControl = capabilities.data?.can_control === true;
  const launchedRun = capabilities.data?.launched_run ?? null;

  const refreshAuth = useCallback(async (signal?: AbortSignal) => {
    try {
      const next = await fetchAuthStatus(signal);
      if (!signal?.aborted) setAuth(next);
    } catch {
      /* auth status is best-effort; the launched run stays viewable */
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refreshAuth(controller.signal);
    return () => controller.abort();
  }, [refreshAuth]);

  useEffect(() => {
    if (activeRun === null && run) setLaunchedName(runTitle(run.summary.targets[0] ?? null, run.summary.runName ?? run.summary.runId ?? "Current run"));
  }, [activeRun, run?.summary.runName, run?.summary.runId]);

  const counts = useMemo(
    () => (run ? severityCounts(run.vulnerabilities) : null),
    [run]
  );
  const selected = run?.vulnerabilities.find((v) => v.id === selectedId) ?? null;
  const agentCount = run?.transcript.agents.length ?? 0;
  const verified = auth?.verified === true;
  const canViewRuns = runs !== null && !runs.locked;

  // Per-run guard for the default view: land on Agents while a scan is live,
  // Overview once it finishes. Applied at most once per run and never once the
  // user has navigated manually (userSetView flips the guard).
  const initialViewAppliedRef = useRef(false);

  // Reset the guard whenever the active run changes so the newly selected run
  // gets its own default.
  useEffect(() => {
    initialViewAppliedRef.current = false;
  }, [activeRun]);

  useEffect(() => {
    if (initialViewAppliedRef.current || !run) return;
    if (run.finished) {
      initialViewAppliedRef.current = true;
      setView("overview");
    } else if (agentCount > 0) {
      // Live and agents have appeared: default to the agent graph. If it is
      // live but no agents exist yet, wait (do not apply, do not set the flag).
      initialViewAppliedRef.current = true;
      setView("agents");
    }
  }, [run, agentCount]);

  // User-initiated navigation: mark the default guard applied so the per-run
  // default effect never yanks the user off the view they chose.
  const userSetView = useCallback((v: View) => {
    initialViewAppliedRef.current = true;
    setView(v);
  }, []);

  const selectRun = useCallback((directoryName: string | null) => {
    userSetView("overview");
    if (directoryName === activeRun) return;
    setActiveRun(directoryName);
    setSelectedId(null);
    // Reset the guard so the per-run default applies to the newly selected run.
    initialViewAppliedRef.current = false;
  }, [activeRun, userSetView]);

  const openEmail = useCallback(() => userSetView("email"), [userSetView]);
  const openEmailFromOverview = openEmail;

  const openHistory = useCallback(() => {
    void refreshRuns();
    userSetView("history");
  }, [refreshRuns, userSetView]);


  const onForget = useCallback(async () => {
    setForgetError(null);
    try {
      await forgetAuth();
      setAuth(null);
      await refreshAuth();
      await refreshRuns();
    } catch (e) {
      setForgetError(e instanceof Error ? e.message : "Could not forget this email.");
    }
  }, [refreshAuth, refreshRuns]);

  return (
    <div className="min-h-screen bg-black text-white flex">
      <Sidebar
        view={view}
        onSelectView={(v) => {
          // Clicking a sidebar view always lands on that section's top level,
          // so leaving a specific issue's detail view and clicking "Issues"
          // returns to the full findings list.
          setSelectedId(null);
          if (v === "history") openHistory();
          else userSetView(v);
        }}
        issuesCount={run?.vulnerabilities.length ?? 0}
        agentCount={agentCount}
        runCount={runs?.count ?? 0}
        finished={run?.finished ?? false}
        verified={verified}
        email={auth?.email ?? null}
        onOpenEmail={openEmail}
        onOpenHistory={openHistory}
        onForget={() => void onForget()}
      />

      <div className="flex-1 min-w-0">
        <TrustToast message={TRUST_BANNER} />
        {/* Top bar */}
        <div className="border-b border-[#222]">
          <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-4 flex flex-wrap items-center gap-x-1.5 gap-y-2">
            <div className="text-base text-white font-medium tracking-tight lg:hidden">LyraShield</div>
            {run && <LiveIndicator finished={run.finished} status={run.summary.status} />}
            <div className="ml-auto flex min-w-0 max-w-full items-center gap-3">
              {canViewRuns && runs.runs.length > 0 && (
                <RunSwitcher
                  runs={runs}
                  activeRun={activeRun}
                  launchedName={launchedName}
                  onSelect={selectRun}
                />
              )}
            </div>
          </div>
        </div>

        <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-8 sm:py-12 space-y-6">
          {forgetError && (
            <div role="alert" className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{forgetError}</p>
            </div>
          )}
          {error && view !== "history" && view !== "email" && (
            <div role="alert" className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{error}</p>
              <button type="button" className="text-sm underline text-red-200" onClick={resources.summary.retry}>Retry</button>
            </div>
          )}

          <ResourceFeedback name="Live controls" resource={capabilities} />
          {view === "history" ? <ResourceFeedback name="History" resource={history} /> : <>
            <ResourceFeedback name="Transcript" resource={resources.transcript} />
            <ResourceFeedback name="Findings" resource={resources.findings} />
            {resources.report.loading && !resources.report.error && <p role="status" className="text-sm text-[#aaa]">Loading report…</p>}
          </>}

          {/* Keyed wrapper: re-mounts on every view / finding / run change so the
              page-in transition replays. */}
          <div
            key={`${activeRun ?? "launched"}:${view}:${selectedId ?? ""}`}
            className="animate-page-in space-y-6"
          >
          {view === "email" ? (
            <EmailReportView
              markdown={run?.reportMarkdown ?? null}
              error={run?.reportError ?? null}
              onRetry={resources.report.retry}
              onExit={() => setView("overview")}
            />
          ) : view === "history" ? (
            <div className="space-y-4">
              <button
                type="button"
                onClick={() => selectRun(null)}
                className="inline-flex min-h-11 items-center gap-1.5 rounded-md px-2 text-sm text-[#888] transition-colors hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 lg:hidden"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to current run
              </button>
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-[#888]" aria-hidden="true" />
                <h1 className="text-2xl font-semibold text-white">Past runs</h1>
              </div>
              {runs && <PastRunsView
                runs={runs}
                activeRun={activeRun}
                onSelectRun={selectRun}
              />}
            </div>
          ) : !run && !error ? (
            <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-10 text-center">
              <div className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[#333] border-t-white animate-spin" />
              <p className="text-sm text-[#888]">Loading run data…</p>
            </div>
          ) : run && counts ? (
            <>
              <SummaryHeader summary={run.summary} />

              {/* Tab strip: shown on small screens where the sidebar is hidden. */}
              <div className="flex gap-5 overflow-x-auto whitespace-nowrap border-b border-[#2a2a2a] lg:hidden">
                <TabButton active={view === "overview"} onClick={() => userSetView("overview")}>
                  Pentest Overview
                </TabButton>
                <TabButton active={view === "issues"} onClick={() => userSetView("issues")}>
                  Issues{run.vulnerabilities.length > 0 ? ` (${run.vulnerabilities.length})` : ""}
                </TabButton>
                {agentCount > 0 && (
                  <TabButton active={view === "agents"} onClick={() => userSetView("agents")}>
                    Agents ({agentCount})
                  </TabButton>
                )}
                {canViewRuns && (
                  <TabButton active={false} onClick={openHistory}>
                    Past runs
                  </TabButton>
                )}
              </div>

              {view === "overview" ? (
                <OverviewTab
                  summary={run.summary}
                  counts={counts}
                  total={run.vulnerabilities.length}
                  reportMarkdown={run.reportMarkdown}
                  reportError={run.reportError}
                  raw={run.raw}
                  finished={run.finished}
                  onOpenEmail={openEmailFromOverview}
                  onRetryReport={resources.report.retry}
                />
              ) : view === "agents" && agentCount > 0 ? (
                <AgentsTab selectedRun={activeRun} run={run} canSteer={canSteer && launchedRun !== null && (activeRun === null || activeRun === launchedRun)} runName={launchedRun ?? ""} canControl={canControl} />
              ) : selected ? (
                <div className="space-y-4">
                  <button
                    onClick={() => setSelectedId(null)}
                    className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] hover:text-white transition-colors"
                  >
                    <ArrowLeft className="w-4 h-4" /> Back to all findings
                  </button>
                  <VulnerabilityDetail vulnerability={selected} />
                </div>
              ) : (
                <FindingsList
                  vulnerabilities={run.vulnerabilities}
                  finished={run.finished}
                  unavailable={resources.findings.error || resources.findings.loading}
                  onSelect={(id) => setSelectedId(id)}
                />
              )}
            </>
          ) : null}
          </div>
        </div>
      </div>

    </div>
  );
}

function ResourceFeedback({ name, resource }: { name: string; resource: { error: boolean; loading: boolean; retry: () => void } }) {
  if (resource.error) return <div role="alert" className="rounded-lg border border-red-500/30 p-4 text-sm text-red-300 flex flex-wrap gap-3">
    <span>{name} could not be loaded. Previously loaded data is retained for this run.</span>
    <button type="button" aria-label={`Retry ${name.toLowerCase()}`} onClick={resource.retry} className="underline">Retry {name.toLowerCase()}</button>
  </div>;
  return resource.loading ? <p role="status" className="text-sm text-[#aaa]">Loading {name.toLowerCase()}…</p> : null;
}

function RunSwitcher({
  runs,
  activeRun,
  launchedName,
  onSelect,
}: {
  runs: RunsPayload;
  activeRun: string | null;
  launchedName: string;
  onSelect: (directoryName: string | null) => void;
}) {
  return (
    <label className="flex min-w-0 items-center gap-2 rounded-lg border border-[#3a3a3a] bg-[rgba(255,255,255,0.05)] px-3 py-2 text-sm text-white transition-colors hover:border-[#555] focus-within:ring-2 focus-within:ring-white/20">
        <History className="h-4 w-4 flex-shrink-0 text-[#888]" aria-hidden="true" />
        <span className="flex-shrink-0 text-[#888]">Pentest</span>
        <select
          value={activeRun ?? ""}
          onChange={(event) => onSelect(event.target.value || null)}
          aria-label="Switch pentest"
          className="min-w-0 max-w-[min(42vw,260px)] cursor-pointer appearance-none truncate bg-transparent font-medium text-white focus-visible:outline-none"
        >
          <option value="">Current run: {launchedName}</option>
          {runs.runs.map((r) => (
            <option key={r.directory_name} value={r.directory_name}>
              {runTitle(r.target, r.name)}
            </option>
          ))}
        </select>
        <ChevronDown className="h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />
    </label>
  );
}

function LiveIndicator({ finished, status }: { finished: boolean; status: string | null }) {
  const display = getRunStatusDisplay(status, finished);
  const color = {
    live: "text-emerald-400",
    completed: "text-emerald-400",
    stopped: "text-amber-400",
    interrupted: "text-amber-400",
    failed: "text-red-400",
    unknown: "text-[#888]",
  }[display.tone];
  return (
    <span role="status" className={`ml-3 inline-flex items-center gap-1.5 text-xs ${color}`}>
      {display.tone === "live" ? (
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full rounded-full bg-current opacity-75 animate-ping" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />
        </span>
      ) : (
        <span className="h-1.5 w-1.5 rounded-full bg-current" />
      )}
      {display.label}
    </span>
  );
}

function formatDuration(seconds: number | null): string | null {
  if (seconds == null) return null;
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function SummaryHeader({ summary }: { summary: ParsedRunSummary }) {
  const duration = formatDuration(summary.durationSeconds);
  return (
    <div>
      <h1 className="text-2xl font-semibold text-white">
        {runTitle(summary.targets[0] ?? null, summary.runName ?? summary.runId ?? "Pentest results")}
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[#888]">
        {summary.targets.length > 0 && (
          <span className="font-mono text-[#aaa]">{summary.targets.join(", ")}</span>
        )}
        {summary.scanMode && <Meta label={summary.scanMode} />}
        {duration && <Meta label={duration} />}
        {summary.status && <Meta label={summary.status} />}
      </div>
    </div>
  );
}

function Meta({ label }: { label: string }) {
  return (
    <>
      <span className="text-[#333]">·</span>
      <span className="capitalize">{label}</span>
    </>
  );
}

function FindingsList({
  vulnerabilities,
  finished,
  unavailable,
  onSelect,
}: {
  vulnerabilities: Vulnerability[];
  finished: boolean;
  unavailable: boolean;
  onSelect: (id: string) => void;
}) {
  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-8 text-center text-sm text-[#888]">
          {unavailable ? "Findings are temporarily unavailable. Retry to confirm the result." : finished ? "No findings in this run." : "No findings yet. The pentest is still running…"}
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {sorted.map((v) => (
        <button
          key={v.id}
          onClick={() => onSelect(v.id)}
          className="animate-card-in cursor-pointer w-full text-left rounded-lg border border-[#222] hover:border-[#444] bg-[rgba(255,255,255,0.02)] px-4 py-3 transition-colors flex items-center gap-3"
        >
          <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${getSeverityDot(v.severity)}`} aria-hidden="true" />
          <span className="flex-1 min-w-0">
            <span className="block text-sm font-medium text-white truncate">{v.title}</span>
            {v.target && (
              <span className="block text-xs text-[#666] font-mono truncate">{v.target}</span>
            )}
          </span>
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${SEVERITY_COLORS[v.severity]}`}
          >
            {v.severity}
          </span>
        </button>
      ))}
    </div>
  );
}

/** Strip a single leading markdown heading (report sections embed their own). */
function stripLeadingHeading(md: string): string {
  return md.replace(/^\s*#{1,6}[ \t]+.*(?:\r?\n)+/, "").trimStart();
}

function dedupeHeadings(md: string): string {
  const out: string[] = [];
  let lastHeading: string | null = null;
  for (const line of md.split("\n")) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) {
      const norm = m[1].trim().toLowerCase();
      if (norm === lastHeading) continue;
      lastHeading = norm;
    } else if (line.trim() !== "") {
      lastHeading = null;
    }
    out.push(line);
  }
  return out.join("\n");
}

/** Download the already-loaded local report. */
function EmailReportCta({ onOpenEmail }: { onOpenEmail: () => void }) {
  return (
    <button
      onClick={onOpenEmail}
      className="group w-full cursor-pointer rounded-xl border border-emerald-500/25 bg-emerald-500/[0.06] p-4 text-left transition-colors hover:border-emerald-500/40"
    >
      <div className="flex items-center gap-3">
        <div
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg"
          style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)" }}
        >
          <Mail className="h-4 w-4 text-emerald-400" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-white">Download the report for this run</p>
          <p className="mt-0.5 text-xs text-[#888]">
            Save the local Markdown report. It may contain sensitive target details.
          </p>
        </div>
        <span className="flex-shrink-0 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-black transition-opacity group-hover:opacity-90">
          Export report
        </span>
      </div>
    </button>
  );
}

function OverviewTab({
  summary,
  counts,
  total,
  reportMarkdown,
  reportError,
  raw,
  finished,
  onOpenEmail,
  onRetryReport,
}: {
  summary: ParsedRunSummary;
  counts: Record<VulnerabilitySeverity, number>;
  total: number;
  reportMarkdown: string | null;
  reportError: string | null;
  raw: Record<string, unknown>;
  finished: boolean;
  onOpenEmail: () => void;
  onRetryReport: () => void;
}) {
  const sections = (
    [
      ["Executive Summary", summary.executiveSummary],
      ["Technical Analysis", summary.technicalAnalysis],
      ["Methodology", summary.methodology],
      ["Recommendations", summary.recommendations],
    ] as const
  )
    .filter(([, content]) => !!content)
    .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }));

  return (
    <div className="space-y-6">
      <div className="animate-card-in">
        <RunDetails raw={raw} durationSeconds={summary.durationSeconds} />
      </div>

      {total > 0 && (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <IssueSeveritySummary findings={{ total, ...counts }} />
        </div>
      )}

      {/* Primary CTA: the one primary on Overview. Hidden until the run is
          finished, since a live scan would only email a partial report. */}
      {finished && (
        <div className="animate-card-in">
          <EmailReportCta onOpenEmail={onOpenEmail} />
        </div>
      )}

      {reportError && (
        <ReportLoadError message={reportError} onRetry={onRetryReport} />
      )}

      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 space-y-8">
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : (
        total === 0 && (
          <p className="text-sm text-[#888]">No summary available for this run yet.</p>
        )
      )}

    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer relative pb-2.5 text-sm font-semibold transition-colors ${
        active ? "text-white" : "text-[#666] hover:text-white"
      }`}
    >
      {children}
      {active && <span className="absolute bottom-0 inset-x-0 h-0.5 bg-white rounded-full" />}
    </button>
  );
}

function AgentsTab({ run, canSteer, runName, canControl, selectedRun }: { selectedRun: string | null; run: LoadedRun; canSteer: boolean; runName: string; canControl: boolean }) {
  const { agents, events } = run.transcript;
  const graphAgents = useMemo(() => buildGraphAgents(agents, events, run.transcript.agent_summaries), [agents, events, run.transcript.agent_summaries]);
  // Clicking a graph node opens the agent's transcript in a modal; no node selected means no modal.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedAgent = selectedId ? (agents.find((a) => a.id === selectedId) ?? null) : null;

  // Live steering is only possible in-process (canSteer) while the scan runs.
  const steerable = canSteer && !run.finished;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[#888]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-white">Agent graph</h2>
          <span className="text-xs text-[#666]">
            {agents.length} agent{agents.length === 1 ? "" : "s"}
          </span>
        </div>
        <p className="mt-1 mb-4 text-xs text-[#666]">
          Click an agent to open its full transcript.
        </p>
        <div className="h-[480px] rounded-lg border border-[#1a1a1a] overflow-hidden">
          <Suspense fallback={<div role="status" className="p-5 text-sm text-[#aaa]">Loading agent graph…</div>}>
            <AgentGraph
              agents={graphAgents}
              selectedAgentId={selectedId}
              onSelectAgent={(id) => setSelectedId(id)}
              eventsLoaded
              eventsEmpty={graphAgents.size === 0}
              scanCompleted={run.finished}
            />
          </Suspense>
        </div>
      </div>

      {/* Live steering: only in-process while the scan runs. Otherwise omitted. */}
      {steerable && <ScanPromptComposer agents={agents} runName={runName} canControl={canControl} />}


      <AgentDetailModal
        open={selectedAgent !== null}
        agent={selectedAgent}
        events={events}
        transcript={run.transcript}
        selectedRun={selectedRun}
        finished={run.finished}
        steerable={steerable}
        runName={runName}
        canControl={canControl}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
