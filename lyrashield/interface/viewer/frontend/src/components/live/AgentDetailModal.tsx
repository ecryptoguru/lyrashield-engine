import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent,
} from "react";
import { X } from "lucide-react";
import { AgentTranscript } from "./AgentTranscript";
import { ScanPromptComposer } from "./ScanPromptComposer";
import type { TranscriptAgent, TranscriptEvent } from "@/data/serverSource";

/** Status -> the small leading dot color, matching the graph node styling. */
const STATUS_DOT: Record<string, string> = {
  completed: "bg-emerald-400",
  running: "bg-blue-400",
  waiting: "bg-yellow-400",
  stopped: "bg-[#888]",
  crashed: "bg-red-400",
  failed: "bg-red-400",
};

/** Consider the user "at the bottom" within this many px. */
const NEAR_BOTTOM_PX = 80;

/**
 * Overlay modal showing a single agent's full transcript. A centered
 * ``max-w-6xl`` / ``60vh`` panel that animates in and out via the shared
 * ``agent-modal`` data-state keyframes (fade), with a pinned header
 * (status dot + agent name),
 * the transcript scrolling beneath it, and a footer. Auto-scrolls to follow new
 * activity while the user is near the bottom. Native modal-dialog behaviour
 * traps focus, makes the background inert, and supports Escape.
 *
 * Driven by an ``open`` prop (rather than conditional mounting) so the exit
 * animation can play before unmount; the last agent is retained through the
 * close so content doesn't blank out mid-animation.
 */
export function AgentDetailModal({
  open,
  agent,
  events,
  steerable,
  onClose,
}: {
  open: boolean;
  agent: TranscriptAgent | null;
  events: TranscriptEvent[];
  steerable: boolean;
  onClose: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const nearBottom = useRef(false);

  // Keep the modal mounted through its exit animation (see UpgradeModal).
  const [render, setRender] = useState(open);
  const [state, setState] = useState<"open" | "closed">(open ? "open" : "closed");
  // Defer the (heavy) transcript one frame so the shell + fade paint instantly
  // instead of waiting on the full event list to render.
  const [contentReady, setContentReady] = useState(false);

  // Retain the last non-null agent so the panel keeps rendering its content
  // during the close animation, after the parent has cleared the selection.
  const lastAgentRef = useRef<TranscriptAgent | null>(agent);
  useEffect(() => {
    if (agent) lastAgentRef.current = agent;
  }, [agent]);
  const shownAgent = agent ?? lastAgentRef.current;
  const shownAgentId = shownAgent?.id;

  useEffect(() => {
    if (open) {
      setRender(true);
      setState("open");
      if (render && dialogRef.current && !dialogRef.current.open) {
        const graphTrigger = Array.from(
          document.querySelectorAll<HTMLElement>(".react-flow__node")
        ).find((node) => node.dataset.id === shownAgentId);
        const activeElement = document.activeElement;
        returnFocusRef.current = graphTrigger ?? (
          activeElement instanceof HTMLElement && activeElement !== document.body
            ? activeElement
            : null
        );
        returnFocusRef.current?.focus();
        dialogRef.current.showModal();
        closeButtonRef.current?.focus();
      }
      return;
    }
    if (!render) return;
    setState("closed");
    const t = setTimeout(() => {
      if (dialogRef.current?.open) dialogRef.current.close();
      returnFocusRef.current?.focus();
      returnFocusRef.current = null;
      setRender(false);
    }, 140);
    return () => clearTimeout(t);
  }, [open, render, shownAgentId]);

  // Mount the transcript a frame after the shell is on screen.
  useEffect(() => {
    if (!render) {
      setContentReady(false);
      return;
    }
    const id = requestAnimationFrame(() => setContentReady(true));
    return () => cancelAnimationFrame(id);
  }, [render]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    nearBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
  }, []);

  // Follow new activity when the user is near the bottom (live trailing).
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !nearBottom.current) return;
    requestAnimationFrame(() => {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
    });
  }, [events]);

  useEffect(() => {
    if (!render) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prevOverflow;
    };
  }, [render]);

  const handleBackdropClick = useCallback((event: MouseEvent<HTMLDialogElement>) => {
    if (event.target !== event.currentTarget) return;
    const panel = panelRef.current;
    if (!panel) return;
    const rect = panel.getBoundingClientRect();
    if (
      event.clientX < rect.left || event.clientX > rect.right ||
      event.clientY < rect.top || event.clientY > rect.bottom
    ) {
      onClose();
    }
  }, [onClose]);

  const handleDialogKeyDown = useCallback((event: ReactKeyboardEvent<HTMLDialogElement>) => {
    if (event.key !== "Tab") return;
    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusable = Array.from(
      dialog.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    ).filter((element) => element.getClientRects().length > 0);
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !dialog.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }, []);

  if (!render || !shownAgent) return null;

  return (
    <dialog
      ref={dialogRef}
      data-state={state}
      className="agent-modal fixed inset-0 z-50 m-0 open:flex h-screen w-screen max-h-none max-w-none items-center justify-center border-0 bg-black/80 p-4 sm:p-8"
      onClick={handleBackdropClick}
      onKeyDown={handleDialogKeyDown}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <div
        ref={panelRef}
        className="relative flex h-[60vh] w-[calc(100vw-4rem)] max-w-6xl flex-col overflow-hidden rounded-xl border border-[#222] bg-[#0a0a0a] shadow-2xl"
      >
        <div className="flex items-center justify-between gap-3 border-b border-[#222] px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-2">
            <span
              className={`h-2 w-2 flex-shrink-0 rounded-full ${STATUS_DOT[shownAgent.status] ?? "bg-[#888]"}`}
            />
            <span id={titleId} className="truncate text-sm font-semibold text-white">{shownAgent.name}</span>
            <span className="flex-shrink-0 font-mono text-xs text-[#555]">{shownAgent.id}</span>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            autoFocus
            aria-label="Close"
            className="flex-shrink-0 rounded-md p-1 text-[#888] transition-colors hover:bg-[#1a1a1a] hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div ref={scrollRef} onScroll={handleScroll} className="flex-1 overflow-y-auto p-5">
          {contentReady && (
            <AgentTranscript agent={shownAgent} events={events} showHeader={false} />
          )}
        </div>

        {steerable && (
          <div className="border-t border-[#222] px-5 py-3">
            <ScanPromptComposer
              agents={[shownAgent]}
              fixedAgentId={shownAgent.id}
              className="mt-0"
            />
          </div>
        )}
      </div>
    </dialog>
  );
}

export default AgentDetailModal;
