import type { Vulnerability } from "@/types/issues";
import {
  parseRunJson,
  parseVulnerabilitiesJson,
  type ParsedRunSummary,
} from "@/lib/local-run-parser";

/**
 * Data seam for the local viewer: fetches against the local Python server's
 * JSON endpoints (same origin, relative URLs), producing the in-memory
 * `LoadedRun` shape the UI renders plus a `finished` flag driving live polling.
 *
 * The server serves a live in-progress run and a finished one identically; the
 * only signal is `run.finished`.
 */

/** A transcript agent as emitted by GET /api/transcript (already parsed). */
export interface TranscriptAgent {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Chat/tool event data as emitted by GET /api/transcript. */
export interface TranscriptEvent {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface Transcript {
  agents: TranscriptAgent[];
  events: TranscriptEvent[];
  windowed?: boolean;
  older_cursors?: Record<string, string | null>;
  agent_summaries?: Record<string, { tool_count: number; message_count: number; task: string }>;
}

export interface LoadedRun {
  summary: ParsedRunSummary;
  /** Whole raw run record (for llm_usage, targets_info details, etc.). */
  raw: Record<string, unknown>;
  finished: boolean;
  vulnerabilities: Vulnerability[];
  reportMarkdown: string | null;
  reportError: string | null;
  transcript: Transcript;
}

export async function getJson(path: string, signal?: AbortSignal): Promise<unknown> {
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  const timer = setTimeout(() => controller.abort(new Error("Request timed out")), 8000);
  try {
    const res = await fetch(path, { cache: "no-store", signal: controller.signal });
    if (!res.ok) throw new Error(`${path} responded ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

/** Build a ``?run=<name>`` suffix for run-scoped data endpoints. */
function runQuery(runName?: string | null): string {
  return runName ? `?run=${encodeURIComponent(runName)}` : "";
}

export async function fetchRunSummary(runName?: string | null, signal?: AbortSignal): Promise<{
  summary: ParsedRunSummary;
  raw: Record<string, unknown>;
  finished: boolean;
}> {
  const raw = (await getJson("/api/run" + runQuery(runName), signal)) as Record<string, unknown>;
  // parseRunJson tolerates extra keys and takes raw TEXT.
  const summary = parseRunJson(JSON.stringify(raw));
  const finished = raw.finished === true;
  return { summary, raw, finished };
}

export async function fetchVulnerabilities(
  runId: string | null,
  runName?: string | null,
  signal?: AbortSignal
): Promise<Vulnerability[]> {
  const arr = await getJson("/api/vulnerabilities" + runQuery(runName), signal);
  return parseVulnerabilitiesJson(JSON.stringify(arr), runId);
}

export async function fetchReportMarkdown(runName?: string | null, signal?: AbortSignal): Promise<string | null> {
  const obj = (await getJson("/api/report" + runQuery(runName), signal)) as { markdown?: string };
  return obj?.markdown ?? null;
}

export async function fetchTranscript(runName?: string | null, signal?: AbortSignal, page?: { agent: string; before?: string }): Promise<Transcript> {
  const query = new URLSearchParams({ limit: "100" });
  if (runName) query.set("run", runName);
  if (page) { query.set("agent", page.agent); if (page.before) query.set("before", page.before); }
  else query.set("summary", "1");
  const obj = (await getJson("/api/transcript?" + query, signal)) as Partial<Transcript>;
  return {
    agents: Array.isArray(obj?.agents) ? obj.agents : [],
    events: Array.isArray(obj?.events) ? obj.events : [],
    windowed: obj?.windowed === true,
    older_cursors: obj?.older_cursors,
    agent_summaries: obj?.agent_summaries,
  };
}

/** One-shot fetch of every endpoint (used on mount and on final settle). */
export async function fetchAll(runName?: string | null): Promise<LoadedRun> {
  const { summary, raw, finished } = await fetchRunSummary(runName);
  const [vulnerabilities, reportResult, transcript] = await Promise.all([
    fetchVulnerabilities(summary.runId, runName),
    fetchReportMarkdown(runName)
      .then((markdown) => ({ markdown, error: null }))
      .catch(() => ({ markdown: null, error: "The report could not be loaded." })),
    fetchTranscript(runName).catch(() => ({ agents: [], events: [] }) as Transcript),
  ]);
  return {
    summary,
    raw,
    finished,
    vulnerabilities,
    reportMarkdown: reportResult.markdown,
    reportError: reportResult.error,
    transcript,
  };
}

// ---------------------------------------------------------------------------
// Run history + email auth + report send
//
// These endpoints back the "Your runs" sidebar section. Auth and report-send
// responses carry a meaningful JSON body on non-2xx statuses (an ``error``
// code), so they read the body regardless of status rather than throwing.
// ---------------------------------------------------------------------------

export interface RunSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RunListEntry {
  name: string;
  directory_name: string;
  target: string | null;
  scan_mode: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  finished: boolean;
  severity_counts: RunSeverityCounts | null;
}

export interface RunsPayload {
  locked: boolean;
  count: number;
  runs: RunListEntry[];
}

export interface AuthStatus {
  verified: boolean;
  email: string | null;
}

export type OtpStartResult = { ok: true } | { ok: false; error: string };
export type OtpVerifyResult =
  | { verified: true; email: string }
  | { verified: false; error: string };
export type SendReportResult =
  | { ok: true; password: string; filename: string }
  | { ok: false; error: string };

async function postJson(
  path: string,
  body: Record<string, unknown>
): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body */
  }
  return { ok: res.ok, status: res.status, data };
}

export async function fetchRuns(signal?: AbortSignal): Promise<RunsPayload> {
  const obj = (await getJson("/api/runs", signal)) as Partial<RunsPayload>;
  return {
    locked: obj?.locked ?? true,
    count: typeof obj?.count === "number" ? obj.count : 0,
    runs: Array.isArray(obj?.runs) ? (obj.runs as RunListEntry[]) : [],
  };
}

export interface BudgetControlState {
  increment_usd: number | null;
  limit_usd: number | null;
  paused: boolean;
  spent_usd: number;
  resume_requires_increase: boolean;
}

export interface Capabilities {
  can_steer: boolean;
  can_control: boolean;
  launched_run: string | null;
  budget: BudgetControlState | null;
}

export type SteerResult = { ok: true } | { ok: false; error: string };

/** GET /api/capabilities. can_steer is true only inside a live in-TUI scan. */
export async function fetchCapabilities(signal?: AbortSignal): Promise<Capabilities> {
  const obj = (await getJson("/api/capabilities", signal)) as Partial<Capabilities>;
  return {
    can_steer: obj?.can_steer === true,
    can_control: obj?.can_control === true,
    launched_run: typeof obj?.launched_run === "string" ? obj.launched_run : null,
    budget: obj?.budget ?? null,
  };
}

/** Submit with a stable ID so a lost acknowledgement can be retried safely. */
async function submitOperatorAction(path: string, body: Record<string, unknown>): Promise<SteerResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body), cache: "no-store", signal: controller.signal,
    });
    const data = await response.json() as Record<string, unknown>;
    if (response.ok && data.ok === true) return { ok: true };
    return { ok: false, error: String(data.error ?? "unavailable") };
  } catch {
    return { ok: false, error: "delivery_unknown" };
  } finally {
    clearTimeout(timer);
  }
}

export async function steerAgent(
  runName: string, agentId: string, message: string, submissionId: string
): Promise<SteerResult> {
  return submitOperatorAction("/api/agents/steer", {
    run: runName, agent_id: agentId, message, submission_id: submissionId,
  });
}

export async function controlScan(
  runName: string, action: "resume" | "increase_budget", submissionId: string
): Promise<SteerResult> {
  return submitOperatorAction("/api/scan/control", {
    run: runName, action, submission_id: submissionId,
  });
}

/** Receipt lookup never invokes steering or budget mutation, even while live. */
export async function checkOperatorReceipt(body: Record<string, unknown>): Promise<SteerResult> {
  return submitOperatorAction("/api/receipts/check", body);
}

export type SubmitFeedbackResult = { ok: true } | { ok: false; error: string };

/**
 * POST /api/feedback. Sends a feedback message plus a work email (no
 * verification) to the local server, which handles it.
 */
export async function submitFeedback(
  message: string,
  email: string
): Promise<SubmitFeedbackResult> {
  const { ok, data } = await postJson("/api/feedback", { message, email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function fetchAuthStatus(signal?: AbortSignal): Promise<AuthStatus> {
  const obj = (await getJson("/api/auth/status", signal)) as Partial<AuthStatus>;
  return { verified: obj?.verified === true, email: obj?.email ?? null };
}

export async function otpStart(email: string): Promise<OtpStartResult> {
  const { ok, data } = await postJson("/api/auth/otp/start", { email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function otpVerify(email: string, code: string): Promise<OtpVerifyResult> {
  const { ok, data } = await postJson("/api/auth/otp/verify", { email, code });
  if (ok && data.verified === true) {
    return { verified: true, email: String(data.email ?? email) };
  }
  return { verified: false, error: String(data.error ?? "invalid_code") };
}

export async function forgetAuth(): Promise<void> {
  const { ok, data } = await postJson("/api/auth/forget", {});
  if (!ok || data.ok !== true) throw new Error(String(data.error ?? "Could not forget this email."));
}

export async function sendReport(runName?: string | null): Promise<SendReportResult> {
  const { ok, data } = await postJson("/api/report/send", runName ? { run: runName } : {});
  if (ok && data.ok === true) {
    return {
      ok: true,
      password: String(data.password ?? ""),
      filename: String(data.filename ?? "lyrashield-report.pdf"),
    };
  }
  return { ok: false, error: String(data.error ?? "unavailable") };
}
