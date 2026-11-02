import { useOperatorReceipts } from "@/data/operatorReceipts";

/** Only retained payloads can be reconciled; this panel cannot create a new action. */
export function OperatorReceipts() {
  const { receipts, check, dismiss } = useOperatorReceipts();
  if (!receipts.length) return null;
  return <section aria-label="Operator delivery receipts" aria-live="polite" className="space-y-3 rounded-xl border border-white/15 bg-[#0a0a0a] p-4 text-sm">
    <h2 className="font-semibold text-white">Operator delivery receipts</h2>
    {receipts.map(receipt => {
      const action = receipt.kind === "message" ? "message" : receipt.action === "resume" ? "resume" : "increase budget";
      return <div key={receipt.id} className="space-y-2 break-words text-[#bbb]">
        <p>{receipt.kind === "message" ? `Message to ${receipt.targetName}` : action === "resume" ? "Resume scan" : "Increase budget"} · Original run: {receipt.runName}</p>
        <p>{receipt.phase === "pending" ? "Waiting for acknowledgement…"
          : receipt.phase === "unknown" ? "Delivery unknown. Check the original submission's receipt; its target and payload are retained."
            : receipt.phase === "queued" ? receipt.kind === "message" ? "Acceptance confirmed. The original message was queued." : "Acceptance confirmed. The original control was accepted."
              : receipt.phase === "dismissed" ? "Receipt dismissed. The original submission may already have been delivered."
                : receipt.error === "budget_increase_required" ? "The original resume was not accepted because the budget was exhausted." : "The original submission was not accepted."}</p>
        <div className="flex flex-wrap gap-3">
          {receipt.phase === "unknown" && <button type="button" onClick={() => void check(receipt.id)} className="min-h-11 rounded border border-white/30 px-3 focus-visible:outline focus-visible:outline-2">Check {action} receipt</button>}
          {receipt.phase !== "pending" && <button type="button" onClick={() => dismiss(receipt.id)} className="min-h-11 px-2 underline">Dismiss receipt</button>}
        </div>
      </div>;
    })}
  </section>;
}
