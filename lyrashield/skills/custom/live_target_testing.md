---
name: live-target-testing
description: Rules of engagement for live URL/API targets reached through the scan-scoped relay — verified scope, method policy, fail-closed behavior, and evidence discipline for black-box scans
---

# Live Target Testing (scan-scoped relay)

This skill applies when the target is a deployed web application or API and the
sandbox's outbound traffic is routed through a **scan-scoped relay**
(`STRIX_TARGET_RELAY=1` in the environment). The relay enforces the authorized
scope at the network layer — it is not a suggestion.

## Hard rules

- **Authorized targets only.** The scope block in your instructions lists the
  verified hosts. The relay denies anything outside it — a `403` with a deny
  reason (`host_out_of_scope`, `method_not_allowed`, `path_blocked`,
  `revoked`, `rate_limited`, `request_cap`, `byte_cap`). A deny means stop;
  never retry the same denied request with variations to probe the boundary.
- **Never attempt to bypass the relay.** Do not try direct connections,
  alternate DNS, tunneling tricks, IP-literal URLs, or asking the target to
  reach out (SSRF-as-exfil). Out-of-band interactions are out of scope unless
  the scope block names them.
- **Method discipline.** `GET`/`HEAD`/`OPTIONS` are safe. `POST` is permitted
  for testing forms and APIs — but be deliberate: every POST can create state.
  Do not bulk-submit forms, create masses of accounts, trigger email/notification
  storms, or loop destructive actions. `PUT`/`PATCH`/`DELETE` are available only
  when explicitly enabled for this scan.
- **No exfiltration.** Never move target data to external services. Evidence
  lives in the workspace and in your tool transcripts.
- **Rate awareness.** The relay rate-limits per scan and per path. Space out
  requests; if you hit `rate_limited`, slow down or move to a different test —
  do not hammer the limit.

## Available tooling

- `terminal` / shell commands: `curl`, `python` + `httpx`/`requests`, `node` —
  all honor the relay via the proxy environment. Prefer these for request-level
  testing; they print the full response you need as evidence.
- `agent_browser` for page-level testing, login flows, client-side behavior,
  and WebSocket work — its traffic is also relay-scoped.
- The local Caido instance API is reachable, but traffic it sends does **not**
  traverse the relay and will fail closed. Do not use `send_request`-style
  replays against live targets in this mode; craft requests with the tools
  above instead.
- If a request fails with a relay deny or a transport error, treat it as
  scoped-out — not as a flaky target.

## Evidence standard

- A finding is `DETECTED` only with reproducible evidence: the exact request
  (method, path, relevant headers — redact secrets), the decisive response
  excerpt, and why it proves the issue.
- Reproduce important findings at least once before reporting.
- Negative results matter: when a tested control holds (e.g. IDOR rejected,
  injection neutralized), say so in the run summary — the absence of a finding
  is only meaningful if the test actually ran.
- Prefer demonstrating impact with the smallest possible request. Never modify
  another user's data; use the test credentials provided in scope.

## Authentication

- If credentials were provisioned for this scan, they are already applied to
  your requests by the relay — you will not see them. Test the authenticated
  surface normally; do not look for, print, or replay credential material.
- If no authenticated material is provisioned, stay on the unauthenticated
  surface and note it as a coverage limitation in the summary.
