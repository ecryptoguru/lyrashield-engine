// Best-effort, anonymous beacon. The local server forwards this to PostHog only
// if the user has telemetry enabled; it never blocks navigation. Undefined
// props are dropped so we only send what is set. NEVER pass PII here (no email,
// code, or report content) - the props are limited to anonymous metadata.
export function track(event: string, props: Record<string, string | undefined> = {}): void {
  try {
    const body: Record<string, string> = { event };
    for (const [key, value] of Object.entries(props)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = JSON.stringify(body);
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon("/api/event", payload);
    } else {
      void fetch("/api/event", { method: "POST", body: payload, keepalive: true });
    }
  } catch {
    /* analytics is best-effort */
  }
}

// Anonymous conversion tracking for a sign-up/upsell click. `surface` records
// where the click happened so one CTA slug can be reused across placements.
export function trackCta(cta: string, surface?: string): void {
  track("cta_clicked", { cta, surface });
}
