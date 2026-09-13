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

- HTTP request tools may use the relay through the proxy environment. Node
  clients do not universally honor proxy environment variables; verify the
  actual transport before claiming coverage.
- HTTPS clients use the sandbox's local inspection bridge and existing trusted
  testing CA. The bridge terminates local CONNECT and sends inspectable HTTPS
  requests to the remote relay. The remote relay verifies the target's TLS and
  applies method/path limits to each request. Never disable TLS verification.
- Browser HTTP/HTTPS navigation and ordinary requests use the same bridge.
  Confirm successful response receipts before claiming coverage. WebSocket
  upgrades and streaming request bodies remain unsupported; record the gap.
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

- Authentication requires explicit, verified provisioning for this scan. A
  relay grant alone does not establish authentication or hide credentials.
- Without authenticated request evidence, stay on the unauthenticated surface
  and record the limitation. Never print credentials or grant contents.
