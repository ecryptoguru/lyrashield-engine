import { ArrowLeft, Download } from "lucide-react";

export default function EmailReportView({
  markdown,
  onExit,
}: {
  markdown: string | null;
  onExit: () => void;
}) {
  return (
    <div className="mx-auto max-w-xl space-y-4">
      <button onClick={onExit} className="inline-flex items-center gap-2 text-sm text-[#aaa] hover:text-white">
        <ArrowLeft className="h-4 w-4" /> Back to results
      </button>
      <h1 className="text-2xl font-semibold text-white">Export report</h1>
      <p className="text-sm text-[#aaa]">
        Download the local Markdown report. Reports may contain sensitive target details;
        store and share them carefully.
      </p>
      {markdown ? (
        <a
          href={"data:text/markdown;charset=utf-8," + encodeURIComponent(markdown)}
          download="lyrashield-report.md"
          className="inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-black"
        >
          <Download className="h-4 w-4" /> Download Markdown
        </a>
      ) : (
        <p role="status" className="text-sm text-[#aaa]">No report is available for this run.</p>
      )}
    </div>
  );
}
