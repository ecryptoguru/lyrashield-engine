---
name: websocket
description: WebSocket testing covering cross-site hijacking (CSWSH), per-message authz gaps, injection over frames, subscription IDOR, and transport/rate-limit abuse
---

# WebSocket Security

WebSockets upgrade an HTTP connection into a persistent, bidirectional channel. The handshake carries browser ambient authority (cookies), so every HTTP-auth mistake reappears here — plus a class of bugs unique to long-lived, message-oriented channels. The endpoint proxy does not capture WS frames: test through `agent_browser` (in-page WebSocket objects, CDP network events) and direct clients (`python -m websockets`, `wscat`, or a small `exec_command` script).

## Attack Surface

**Handshake**
- `GET` upgrade request with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key/Version`
- Cookies, `Authorization`, and TLS client auth sent like any HTTP request — this is the CSWSH surface
- `Origin` header is the only cross-site boundary; it is attacker-optional outside browsers
- Path and query parameters (tokens, room ids) land in logs and browser history

**Channel Model**
- Pub/sub topics, rooms, per-user channels (`user-123`, `tenant-42`), presence feeds
- Message envelopes (`{"type": "subscribe", "channel": ...}`, JSON-RPC-ish calls, STOMP/SockJS/SignalR framing)
- Server-pushed events that the UI renders or acts on (chat, notifications, admin actions)

**Termination Points**
- First-party WS server, API gateways (NGINX/Envoy/ALB), managed realtime (Socket.IO, Pusher, Ably, Supabase Realtime, Firebase RTDB, LiveKit)
- Each hop can drop or weaken checks done at another layer

## High-Value Targets

- State-changing messages: payments, role grants, kicks/bans, key rotation, document writes
- Subscription endpoints addressing per-user/per-tenant resources
- Auth carried in `?token=` query params or first-message envelopes
- Channels that leak PII, presence, typing indicators, or admin telemetry
- WS endpoints reachable without the page that normally opens them

## Reconnaissance

### Discovery

- Watch the app with `agent_browser`: instrument `window.WebSocket` before load (`new WebSocket(...)` wrapper recording url, protocols, frames), or read CDP `Network.webSocket*` events
- Check page source and JS bundles for `ws://`, `wss://`, `new WebSocket`, `socket.io`, `signalr`, `phoenix`, `cable` (ActionCable), `centrifuge`
- Identify the framing layer: raw WS, Socket.IO (EIO transport packets), SockJS (`/info` endpoint), STOMP frames, SignalR negotiate

### Handshake Review

- Capture the upgrade request: headers, cookies, `Origin`, auth params
- Confirm scheme: `wss://` required in production; `ws://` on a real deployment is a finding
- Note where auth lives: session cookie, `Sec-WebSocket-Protocol` token, query param, or first-message envelope

### Message Model

- Enumerate message types and who may send each (client→server vs server-only)
- Map subscription addressing: does a channel name identify a user, org, order, room?
- Check whether the client enforces authorization the server should own

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

- Server accepts the upgrade without validating `Origin` (or accepts `null`/arbitrary origins) while authenticating via cookies
- An attacker page opens the victim's authenticated socket cross-origin: full duplex — read pushes and send actions
- Equivalent impact to CSRF + full readback; stronger than classic CSRF because responses flow to the attacker
- Test: hand a crafted `Origin: https://attacker.example` (or `null`) upgrade to the endpoint from a non-browser client; then drive the same from a cross-origin page under `agent_browser`

### Missing per-message authorization

- Auth is checked once at handshake; later frames act as whoever holds the socket
- Token revocation, role demotion, or logout does not sever the live channel
- Test: establish, then revoke/demote in a parallel session, then send privileged messages

### Subscription IDOR / cross-tenant leakage

- Subscribe to another user's channel by guessing ids (`user-124`), enumerating rooms, or replaying another session's channel names
- Server relies on client-supplied channel names without membership checks
- Test: subscribe to sequential/foreign ids and observe pushed data

### Injection over frames

- Message fields flow to SQL, shell, template engines, LDAP, or other users' DOMs (stored XSS via chat/notification payloads)
- JSON fields treated as trusted because "the socket was authenticated"
- Test: standard injection payloads inside message fields; confirm where the value lands (DB query, shell arg, rendered HTML)

### Token in URL

- `wss://host/ws?token=JWT...` leaks via server logs, proxy logs, browser history, Referer on redirects
- Prefer subprotocol or first-message auth; flag query-param tokens as findings

### Cleartext and downgrade

- `ws://` without TLS exposes frames to interception/tampering; mixed-content pages (`https` page → `ws://`) are a tell
- Some stacks accept both `ws` and `wss`; confirm the plaintext listener exists, not just that wss works

### Rate limits and resource exhaustion

- No per-connection message rate, frame-size cap, or subscription count → flood, oversized frames, `permessage-deflate` compression bombs
- Unauthenticated pre-handshake endpoints that allocate state
- Test: measured bursts only — enough to demonstrate absence of a cap, never to exhaust production

### Replay and ordering

- No nonce/timestamp/sequence on state-changing messages → replay captured frames to repeat actions (double-spend, re-grant)
- Test: resend a captured mutating frame and observe duplicate effect

### Origin-check bypasses

- Accepting `null` Origin (sandboxed iframe, `data:` page), suffix/prefix regex bugs (`attacker-example.com`, `example.com.evil.io`), or trusting `Origin` only when present (non-browser clients omit it)

## Testing Methodology

1. **Map the channel** - endpoints, framing layer, auth mechanism, message types, subscription grammar
2. **Handshake abuse** - cross-origin upgrade, missing `Origin`, `null` Origin, `ws://`, token-in-URL
3. **Authorization** - foreign-channel subscribe, post-revocation actions, unauthenticated connect
4. **Payload testing** - injection in every writable field; confirm the downstream sink
5. **Liveness properties** - replay, out-of-order frames, oversized frames, modest rate bursts
6. **Client-side trust** - does the UI render server pushes unsanitized (stored XSS), or act on pushed commands?

## Validation

Findings must carry reproducible handshake and frame evidence: the exact upgrade request, the offending frames, and the observed effect — LyraShield keeps engine claims at DETECTED until that evidence supports independent validation.

1. For CSWSH: a cross-origin page (or `Origin`-spoofed client) opens an authenticated socket and performs an action or reads pushed data
2. For subscription IDOR: a frame addressed to a foreign channel returns data belonging to another user/tenant
3. For per-message authz gaps: a privileged action succeeds after credential revocation/demotion
4. For injection: show the message value reaching the sink (query error, rendered markup, command output)
5. Always capture the exact handshake request and the offending frames as evidence

## False Positives

- Server enforces `Origin` allowlist AND re-validates auth per message, with channels bound to server-side identity
- `Origin` unchecked but handshake requires a non-cookie credential (per-request bearer in subprotocol) — lower risk, note anyway
- Read-only public broadcast channels carrying no user data — note, not a vuln
- Client-side missing checks that the server enforces correctly — hardening note only

## Impact

- Full session-equivalent action + read channel under CSWSH
- Cross-tenant data exposure via subscription IDOR
- Stored/persistent XSS, second-order injection through pushed content
- Replay-driven financial or authorization duplication
- Cost/availability abuse via unbounded frames and subscriptions

## Pro Tips

1. The handshake is the last HTTP moment — everything after is frames; abuse the gap
2. `agent_browser` instrumentation beats proxies here: wrap `WebSocket`/`send`/`onmessage` in page JS to log both directions
3. Socket.IO falls back to HTTP long-polling — test both transports; auth bugs often live in only one
4. Channel naming schemes leak structure: `tenant:`, `user:`, `room:` prefixes are enumeration maps
5. Auth done in `onopen` message ≠ auth done at handshake — the interval between connect and first frame is exploitable surface
6. Compare `Origin` acceptance from a browser context vs `exec_command` client — divergence is a finding
7. CSWSH + stored XSS via push payloads is a full account-takeover chain

## Summary

A WebSocket is secure only when the handshake enforces origin + authentication, every message is authorized and validated as untrusted input, subscriptions are bound to server-side identity, and transport is `wss` with rate/size limits. Test the handshake like an HTTP endpoint and every frame like a POST body.
