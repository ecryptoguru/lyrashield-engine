import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { checkOperatorReceipt, controlScan, steerAgent, type SteerResult } from "./serverSource";

type ReceiptPayload = { id: string; runName: string } & (
  | { kind: "message"; agentId: string; targetName: string; message: string }
  | { kind: "control"; action: "resume" | "increase_budget" }
);
export type OperatorReceipt = ReceiptPayload & {
  phase: "pending" | "unknown" | "queued" | "rejected" | "dismissed";
  error?: string;
};
interface ReceiptContext {
  receipts: OperatorReceipt[];
  submit: (payload: ReceiptPayload) => Promise<SteerResult>;
  check: (id: string) => Promise<void>;
  dismiss: (id: string) => void;
}
const Context = createContext<ReceiptContext | null>(null);
const unresolved = (receipt: OperatorReceipt) => receipt.phase === "pending" || receipt.phase === "unknown";

/** Session-owned state survives view, modal and live-composer unmounts. */
export function OperatorReceiptProvider({ children }: { children: ReactNode }) {
  const [receipts, setReceipts] = useState<OperatorReceipt[]>([]);
  const receiptRef = useRef<OperatorReceipt[]>([]);
  const update = useCallback((change: (current: OperatorReceipt[]) => OperatorReceipt[]) => {
    receiptRef.current = change(receiptRef.current);
    setReceipts(receiptRef.current);
  }, []);

  const submit = useCallback(async (payload: ReceiptPayload): Promise<SteerResult> => {
    const previous = receiptRef.current.find(receipt => receipt.id === payload.id);
    if (previous) {
      const { phase: _phase, error: _error, ...original } = previous;
      if (JSON.stringify(original) !== JSON.stringify(payload)) return { ok: false, error: "submission_conflict" };
      if (previous.phase === "pending") return { ok: false, error: "delivery_unknown" };
    } else if (receiptRef.current.filter(unresolved).length >= 4096) {
      return { ok: false, error: "submission_limit" };
    }
    update(current => [...current.filter(receipt => receipt.id !== payload.id && unresolved(receipt)), { ...payload, phase: "pending" }]);
    let result: SteerResult;
    try {
      result = payload.kind === "message"
        ? await steerAgent(payload.runName, payload.agentId, payload.message, payload.id)
        : await controlScan(payload.runName, payload.action, payload.id);
    } catch {
      result = { ok: false, error: "delivery_unknown" };
    }
    const phase = result.ok ? "queued" : result.error === "delivery_unknown" ? "unknown" : "rejected";
    update(current => current.filter(receipt => receipt.id === payload.id || unresolved(receipt))
      .map(receipt => receipt.id === payload.id ? { ...receipt, phase,
        ...(phase === "rejected" && !result.ok ? { error: result.error } : {}) } : receipt));
    return result;
  }, [update]);

  const check = useCallback(async (id: string) => {
    const receipt = receiptRef.current.find(candidate => candidate.id === id);
    if (!receipt || receipt.phase !== "unknown") return;
    update(current => current.map(candidate => candidate.id === id ? { ...candidate, phase: "pending" } : candidate));
    const body = receipt.kind === "message"
      ? { run: receipt.runName, submission_id: receipt.id, agent_id: receipt.agentId, message: receipt.message }
      : { run: receipt.runName, submission_id: receipt.id, action: receipt.action };
    let result: SteerResult;
    try { result = await checkOperatorReceipt(body); }
    catch { result = { ok: false, error: "delivery_unknown" }; }
    // Lookup transport/auth errors cannot prove that an earlier action failed.
    const phase = result.ok ? "queued" : result.status === "rejected" ? "rejected" : "unknown";
    update(current => current.filter(candidate => candidate.id === id || unresolved(candidate))
      .map(candidate => candidate.id === id ? { ...candidate, phase,
        ...(phase === "rejected" && !result.ok ? { error: result.error } : {}) } : candidate));
  }, [update]);

  const dismiss = useCallback((id: string) => {
    update(current => current.filter(receipt => receipt.id === id || unresolved(receipt))
      .flatMap(receipt => receipt.id !== id ? [receipt]
        : receipt.phase === "pending" ? [receipt]
          : receipt.phase === "unknown" ? [{ ...receipt, phase: "dismissed" as const }] : []));
  }, [update]);

  return <Context.Provider value={{ receipts, submit, check, dismiss }}>{children}</Context.Provider>;
}

export function useOperatorReceipts() {
  const context = useContext(Context);
  if (!context) throw new Error("Operator receipt provider is required");
  return context;
}
