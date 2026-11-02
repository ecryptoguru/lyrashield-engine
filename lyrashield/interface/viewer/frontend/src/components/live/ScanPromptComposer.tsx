import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ArrowUp, ChevronDown, ChevronUp, Loader2, Sparkles } from "lucide-react";
import { fetchCapabilities, type BudgetControlState, type TranscriptAgent } from "@/data/serverSource";
import { useOperatorReceipts } from "@/data/operatorReceipts";
import { track } from "@/lib/cta";
import { attemptSteering } from "@/lib/steering";
import { cn } from "@/lib/utils";

function formatBudget(value: number) {
  const exact = value.toString();
  if (exact.includes("e")) return exact;
  const [whole, fraction = ""] = exact.split(".");
  return `${whole}.${fraction.padEnd(2, "0")}`;
}

const ROOT_TARGET_VALUE = "__root__";

interface ScanPromptComposerProps {
  /** All agents in the run; used to resolve the root and running children. */
  agents: TranscriptAgent[];
  runName: string;
  canControl?: boolean;
  /**
   * Single-agent (modal) mode: pins the composer to one agent and shows a
   * static "Target: <name>" pill instead of the dropdown. Omit for the
   * multi-agent graph variant.
   */
  fixedAgentId?: string;
  className?: string;
}

/**
 * Faithful port of the pro app's ScanPromptComposer for the local viewer.
 * Collapsed by default into a "Guide the agent" pill; expands into a card with
 * an auto-resizing textarea and a target control. The viewer's steering is
 * immediate (no Enterprise lock, no bridge-connecting state), so this is only
 * rendered by callers when steering is available. Sends via steerAgent, which
 * requires a concrete agent id, so "Root agent" resolves to the root agent's id.
 */
export function ScanPromptComposer({
  agents,
  runName,
  canControl = false,
  fixedAgentId,
  className,
}: ScanPromptComposerProps) {
  const receipts = useOperatorReceipts();
  const submissionRef = useRef<{ key: string; id: string; targetName: string; targetId: string; runName: string; message: string } | null>(null);
  const controlRef = useRef<{ action: string; id: string } | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [focused, setFocused] = useState(false);
  const [value, setValue] = useState("");
  const [sending, setSending] = useState(false);
  const [budget, setBudget] = useState<BudgetControlState | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const refreshBudget = useCallback(async (signal?: AbortSignal) => {
    try {
      const caps = await fetchCapabilities(signal);
      if (!signal?.aborted && caps.launched_run === runName) setBudget(caps.budget);
    } catch {
      // Existing controls remain retryable; budget metadata is best effort.
    }
  }, [runName]);
  useEffect(() => {
    if (!expanded || !canControl) return;
    const controller = new AbortController();
    void refreshBudget(controller.signal);
    const timer = setInterval(() => void refreshBudget(controller.signal), 2000);
    return () => { clearInterval(timer); controller.abort(); };
  }, [expanded, canControl, refreshBudget]);

  const isModal = fixedAgentId != null;

  // Root = the agent with no parent; fall back to the first agent.
  const rootAgent = useMemo(
    () => agents.find((a) => !a.parent_id) ?? agents[0] ?? null,
    [agents]
  );

  // Multi-agent dropdown options: running child agents plus Root (added in JSX).
  const targetOptions = useMemo(
    () => agents.filter((a) => a.parent_id && ["running", "waiting", "budget_paused"].includes(a.status)),
    [agents]
  );

  // Selected target for the multi-agent variant. ROOT sentinel by default.
  const [selectedTarget, setSelectedTarget] = useState<string>(ROOT_TARGET_VALUE);
  const [unknown, setUnknown] = useState(false);

  // If the selected child target disappears (finished), fall back to Root.
  useEffect(() => {
    if (
      !sending && !unknown && selectedTarget !== ROOT_TARGET_VALUE &&
      !targetOptions.some((a) => a.id === selectedTarget)
    ) {
      setSelectedTarget(ROOT_TARGET_VALUE);
    }
  }, [selectedTarget, targetOptions, sending, unknown]);

  // Resolve the concrete agent id + display name for the current target.
  const { targetId, targetName } = useMemo(() => {
    if (isModal) {
      const agent = agents.find((a) => a.id === fixedAgentId) ?? null;
      return {
        targetId: fixedAgentId ?? null,
        targetName: agent?.name ?? "this agent",
      };
    }
    if (selectedTarget === ROOT_TARGET_VALUE) {
      return {
        targetId: rootAgent?.id ?? null,
        targetName: "Root agent",
      };
    }
    const agent = agents.find((a) => a.id === selectedTarget) ?? null;
    return {
      targetId: selectedTarget,
      targetName: agent?.name ?? submissionRef.current?.targetName ?? selectedTarget,
    };
  }, [agents, fixedAgentId, isModal, rootAgent, selectedTarget]);

  useEffect(() => {
    const message = receipts.receipts.find(receipt => receipt.id === submissionRef.current?.id);
    if (message && !["pending", "unknown"].includes(message.phase)) {
      submissionRef.current = null;
      setUnknown(false);
      if (message.phase === "queued") { setValue(""); setFeedback("Receipt confirmed: message queued."); }
      else setFeedback(message.phase === "dismissed" ? "Uncertain submission discarded. It may still have been delivered." : "Message was not accepted. The draft is retained.");
    }
    const control = receipts.receipts.find(receipt => receipt.id === controlRef.current?.id);
    if (control && !["pending", "unknown"].includes(control.phase)) controlRef.current = null;
  }, [receipts.receipts]);

  const empty = value.trim().length === 0;

  // Grow the textarea with its content, capped by max-h via CSS.
  useLayoutEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [value]);

  const handleExpand = useCallback(() => {
    setExpanded(true);
    requestAnimationFrame(() => textareaRef.current?.focus());
  }, []);

  const handleCollapse = useCallback(() => {
    setExpanded(false);
    setFocused(false);
  }, []);

  const handleSend = useCallback(async () => {
    if (sending) return;
    const frozen = unknown ? submissionRef.current : null;
    const message = frozen?.message ?? value.trim();
    const agentId = frozen?.targetId ?? targetId;
    const submissionRun = frozen?.runName ?? runName;
    if (!message || !agentId) return;

    setSending(true);
    setFeedback(null);
    const name = frozen?.targetName ?? targetName;
    const key = JSON.stringify([submissionRun, agentId, message]);
    if (submissionRef.current?.key !== key) {
      submissionRef.current = { key, id: crypto.randomUUID(), targetName: name, targetId: agentId, runName: submissionRun, message };
    }
    const id = submissionRef.current.id;
    const outcome = await attemptSteering(async () => {
      const result = await receipts.submit({ id, runName: submissionRun, kind: "message", agentId, targetName: name, message });
      if (!result.ok && result.error !== "delivery_unknown") submissionRef.current = null;
      return result;
    }, name);
    setUnknown(!outcome.sent && submissionRef.current !== null);
    if (outcome.sent) {
      submissionRef.current = null;
      setValue("");
      setFeedback(outcome.feedback);
      track("agent_steered");
    } else {
      setFeedback(outcome.feedback);
    }
    setSending(false);
  }, [sending, value, targetId, targetName, runName, unknown, receipts.submit]);

  const handleControl = async (action: "resume" | "increase_budget") => {
    if (sending) return;
    if (controlRef.current?.action !== action) {
      controlRef.current = { action, id: crypto.randomUUID() };
    }
    setSending(true);
    setFeedback("Pending control acceptance…");
    const result = await receipts.submit({ id: controlRef.current.id, runName, kind: "control", action });
    if (result.ok) {
      controlRef.current = null;
      await refreshBudget();
      setFeedback(action === "resume" ? "Resume accepted." : "Budget increased by one configured increment. Scan remains paused.");
    } else {
      if (result.error !== "delivery_unknown") controlRef.current = null;
      setFeedback(result.error === "delivery_unknown"
        ? "Delivery unknown. Retry the same control to check acceptance."
        : result.error === "budget_increase_required"
          ? "Budget exhausted. Increase the budget before resuming."
          : "Control was not accepted. The scan may no longer be paused.");
    }
    setSending(false);
  };

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={handleExpand}
        className={cn(
          "mt-4 flex w-full items-center justify-between gap-3 rounded-2xl border border-white/[0.08] bg-[#050505] px-5 py-3 text-left transition-colors duration-300 hover:border-white/[0.12] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20",
          className
        )}
        aria-expanded={false}
        aria-label="Expand live prompt composer"
      >
        <div className="flex min-w-0 items-center gap-2">
          <Sparkles className="h-4 w-4 shrink-0 text-[#666]" />
          <span className="truncate text-sm font-medium text-white">Guide the agent</span>
        </div>
        <ChevronUp className="h-4 w-4 shrink-0 text-[#777]" />
      </button>
    );
  }

  return (
    <div
      className={cn(
        "mt-4 rounded-2xl border border-white/[0.08] bg-[#050505] overflow-hidden transition-colors duration-300",
        focused ? "border-white/[0.18]" : "hover:border-white/[0.12]",
        className
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-[#666]" />
            <p className="text-sm font-medium text-white">Live prompt</p>
          </div>
          <p className="mt-0.5 text-xs text-[#777]">Connected</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {isModal ? (
            <div className="rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-xs text-[#aaa]">
              Target: <span className="text-white">{targetName}</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-[#aaa]">Target:</span>
              <select
                aria-label="Steering target"
                value={selectedTarget}
                disabled={sending || unknown}
                onChange={event => setSelectedTarget(event.target.value)}
                className="h-8 max-w-[140px] rounded-full border border-white/10 bg-[#0a0a0a] px-2 text-xs text-white focus-visible:outline focus-visible:outline-2"
              >
                <option value={ROOT_TARGET_VALUE}>Root agent</option>
                {targetOptions.map(option => <option key={option.id} value={option.id}>{option.name}</option>)}
                {selectedTarget !== ROOT_TARGET_VALUE && !targetOptions.some(a => a.id === selectedTarget) && <option value={selectedTarget}>Original target ({selectedTarget})</option>}
              </select>
            </div>
          )}
          <button
            type="button"
            onClick={handleCollapse}
            className="inline-flex h-7 w-7 items-center justify-center rounded-full text-[#777] transition-colors hover:bg-white/[0.06] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20"
            aria-label="Collapse live prompt composer"
          >
            <ChevronDown className="h-4 w-4" />
          </button>
        </div>
      </div>

      {canControl && agents.some((agent) => agent.status === "budget_paused") && (
        <div className="border-b border-white/10 px-5 py-3 text-xs text-[#bbb]">
          <p>Budget paused. Messages queue until you explicitly resume.</p>
          <p className="mt-1">{budget?.increment_usd != null && budget.limit_usd != null
            ? `Current limit $${formatBudget(budget.limit_usd)}. Increase adds $${formatBudget(budget.increment_usd)} and keeps the scan paused.`
            : "Loading configured budget amount…"}</p>
          {budget?.resume_requires_increase && <p className="mt-1">Budget exhausted. Increase the budget before resuming.</p>}
          <div className="mt-2 flex flex-wrap gap-3">
            <button type="button" disabled={sending || budget?.increment_usd == null} onClick={() => void handleControl("increase_budget")} className="rounded border border-white/30 px-3 py-2 focus-visible:outline focus-visible:outline-2">Increase budget</button>
            <button type="button" disabled={sending || budget?.resume_requires_increase === true} onClick={() => void handleControl("resume")} className="rounded border border-white/30 px-3 py-2 focus-visible:outline focus-visible:outline-2">Resume scan</button>
          </div>
        </div>
      )}
      <div className="px-5 pt-4 pb-3">
        <textarea
          ref={textareaRef}
          rows={1}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing && e.nativeEvent.keyCode !== 229) {
              e.preventDefault();
              void handleSend();
            }
          }}
          placeholder="Send a live prompt to the running pentest…"
          aria-label="Steering message"
          maxLength={4000}
          disabled={sending || unknown}
          className="block w-full resize-none border-0 bg-transparent p-0 text-[15px] leading-6 text-white placeholder:text-[#444] focus:outline-none disabled:opacity-60 max-h-[160px] overflow-y-auto"
        />
      </div>

      {unknown && <div className="px-5 pb-3 text-xs text-amber-200">
        <p>The original target and message are held until delivery is known. Retry uses the same submission.</p>
        <button type="button" className="mt-2 underline" onClick={() => { if (submissionRef.current) receipts.dismiss(submissionRef.current.id); submissionRef.current = null; setUnknown(false); setFeedback("Uncertain submission discarded. It may still have been delivered."); }}>Discard uncertain submission</button>
      </div>}
      <div className="flex items-center justify-between gap-3 px-4 pb-4">
        <div role="status" aria-live="polite" className="text-xs text-[#999]">{sending ? "Pending mailbox acceptance…" : feedback ?? "Press Enter to send."}</div>
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            void handleSend();
          }}
          disabled={sending || empty || !targetId}
          className={cn(
            "inline-flex h-10 min-w-[112px] items-center justify-center gap-2 rounded-full px-4 text-sm font-medium transition-colors",
            sending || empty
              ? "bg-white/[0.08] text-[#666]"
              : "bg-white text-black hover:bg-neutral-200"
          )}
        >
          {sending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <ArrowUp className="h-4 w-4" strokeWidth={2.5} />
          )}
          <span>{sending ? "Pending…" : "Send prompt"}</span>
        </button>
      </div>
    </div>
  );
}

export default ScanPromptComposer;
