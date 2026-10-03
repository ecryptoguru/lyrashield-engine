"use client";

import type { ToolRendererProps } from "@/types/events";
import { getFinishOutcome } from "@/lib/finish-outcome";
import { TruncatedText } from "./ToolCard";

export default function FinishRenderer({ args, result, status }: ToolRendererProps) {
  const outcome = getFinishOutcome(status, result);
  const executiveSummary = (args.executive_summary as string) ?? "";
  const methodology = (args.methodology as string) ?? "";
  const technicalAnalysis = (args.technical_analysis as string) ?? "";
  const recommendations = (args.recommendations as string) ?? "";

  if (outcome.state === "pending") {
    return <div role="status" className="text-[#888] text-sm">Finalizing scan…</div>;
  }

  if (outcome.state === "failed") {
    return (
      <div role="alert" className="space-y-1">
        <p className="text-red-400 font-semibold text-sm">Scan completion was not confirmed</p>
        <p className="text-[#888] text-sm">{outcome.reason}</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <span role="status" className="text-emerald-400/80 font-semibold text-sm">Penetration test completed</span>
      {executiveSummary && (
        <div><span className="text-emerald-400/60 text-sm font-semibold">Executive Summary</span><div className="mt-1"><TruncatedText text={executiveSummary} maxLines={25} /></div></div>
      )}
      {methodology && (
        <div><span className="text-emerald-400/60 text-sm font-semibold">Methodology</span><div className="mt-1"><TruncatedText text={methodology} maxLines={25} /></div></div>
      )}
      {technicalAnalysis && (
        <div><span className="text-emerald-400/60 text-sm font-semibold">Technical Analysis</span><div className="mt-1"><TruncatedText text={technicalAnalysis} maxLines={25} /></div></div>
      )}
      {recommendations && (
        <div><span className="text-emerald-400/60 text-sm font-semibold">Recommendations</span><div className="mt-1"><TruncatedText text={recommendations} maxLines={25} /></div></div>
      )}
      {!executiveSummary && !methodology && !technicalAnalysis && !recommendations && (
        <div className="text-[#555] text-xs">Generating final report...</div>
      )}
    </div>
  );
}
