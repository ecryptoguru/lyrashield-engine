import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchReportMarkdown,
  fetchRunSummary,
  fetchTranscript,
  fetchVulnerabilities,
  type LoadedRun,
} from "./serverSource";

/** Each resource owns cancellation, retry and its last successful value for one run. */
export function useResource<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
  poll: boolean | ((data: T) => boolean) = false
) {
  const [state, setState] = useState<{
    key: string;
    data: T | null;
    error: boolean;
    loading: boolean;
    loaded: boolean;
  }>({ key, data: null, error: false, loading: true, loaded: false });
  const [attempt, setAttempt] = useState(0);
  const pollRef = useRef(poll);
  pollRef.current = poll;
  const loadRef = useRef(load);
  loadRef.current = load;
  const pollingEnabled = typeof poll === "boolean" ? poll : true;

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      setState(prev => ({
        key,
        data: prev.key === key ? prev.data : null,
        error: prev.key === key && prev.error,
        loading: prev.key !== key || !prev.loaded,
        loaded: prev.key === key && prev.loaded,
      }));
      let failed = false;
      let keepPolling = pollRef.current === true;
      try {
        const data = await loadRef.current(controller.signal);
        if (typeof pollRef.current === "function") keepPolling = pollRef.current(data);
        if (!controller.signal.aborted) setState({ key, data, error: false, loading: false, loaded: true });
      } catch {
        failed = true;
        if (!controller.signal.aborted) {
          setState(prev => ({
            key,
            data: prev.key === key ? prev.data : null,
            error: true,
            loading: false,
            loaded: prev.key === key && prev.loaded,
          }));
        }
      }
      if (!controller.signal.aborted && (keepPolling || (failed && pollRef.current !== false))) {
        timer = setTimeout(tick, failed || document.visibilityState === "hidden" ? 5000 : 500);
      }
    };
    void tick();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [key, attempt, pollingEnabled]);

  return {
    ...(state.key === key ? state : { key, data: null, error: false, loading: true, loaded: false }),
    retry: useCallback(() => setAttempt(n => n + 1), []),
  };
}

export function useRunResources(runName: string | null) {
  const key = JSON.stringify(runName);
  const summary = useResource(key, signal => fetchRunSummary(runName, signal), data => !data.finished);
  const live = summary.data?.finished !== true;
  const transcript = useResource(key, signal => fetchTranscript(runName, signal), live);
  const findings = useResource(
    key,
    signal => fetchVulnerabilities(summary.data?.summary.runId ?? null, runName, signal),
    live
  );
  const report = useResource(key, signal => fetchReportMarkdown(runName, signal), live);
  const run: LoadedRun | null = summary.data ? {
    ...summary.data,
    transcript: transcript.data ?? { agents: [], events: [] },
    vulnerabilities: findings.data ?? [],
    reportMarkdown: report.data,
    reportError: report.error ? "The report could not be loaded." : null,
  } : null;
  return { run, summary, transcript, findings, report };
}
