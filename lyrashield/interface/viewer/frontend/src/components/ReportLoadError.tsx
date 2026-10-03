export function ReportLoadError({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3"
    >
      <p className="text-sm text-red-300">{message}</p>
      <button type="button" className="text-sm underline text-red-200" onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}
