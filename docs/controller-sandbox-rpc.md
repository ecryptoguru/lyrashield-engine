# Controller sandbox attachment contract

This is a source adapter, not installed-runtime or production qualification.
The default remains `docker`; `LYRASHIELD_RUNTIME_BACKEND=controller` explicitly
selects the attach-only adapter. Missing signed installed authority fails closed.
No RPC creates an image, container, mount, identity, credential or environment.

The trusted launcher supplies `LYRASHIELD_SUPERVISOR_TOOL_URL` (protected HTTPS
origin), `TOOL_TOKEN`, `ATTEMPT_ID`, `OPERATION_ID`, `AUTHORITY_EPOCH_ID` and
`SANDBOX_HANDLE`, each with the `LYRASHIELD_SUPERVISOR_` prefix. The token is an
ephemeral scan credential, never a signing key. HTTP is used only by explicitly
constructed `MockTransport` fixture clients. The launcher also supplies the public
signed `LYRASHIELD_SUPERVISOR_RUNTIME_AUTHORITY` envelope. The consumer verifies
the pinned signature, issuer, epoch and signed `toolChannel` origin before it
constructs a real transport or sends the bearer credential. The configured origin
must exactly match that signed protected HTTPS origin; caller URLs or keys cannot
override it. Redirects and environment proxy settings
are disabled; TLS certificate verification remains enabled.

Every response includes exact `binding` with `attemptId`, `operationId`,
`authorityEpochId` and opaque `sandboxHandle`. Every POST includes that binding.
Mutations also include original UUID `requestId` and `commandId`; responses echo
`requestId` and `status: COMPLETED`. Operation-specific fields validate inside the
same uncertainty boundary before receipt ACK or cursor commit. A running PTY can acknowledge its completed
start operation with a null process exit code. A timeout, cancellation, malformed
acknowledgement or other status retains the original request ID and blocks new
tool mutations. Normal mutations serialize through receipt validation and ACK;
physical recovery stop may bypass a long command, retaining all uncertain IDs.
The controller must durably record the original operation before
invocation, fence current authority through invocation, and never replay uncertain
work. Reads do not trigger retries of mutations. Recovery stops use one stable
stop request ID derived from the binding, including subsequent cleanup attempts.
Same-session PTY polls/stdin serialize read and cursor commit; their responses
must carry the exact requested session ID.

After validation the client POSTs `request/{originalRequestId}/ack` with binding,
original `requestId` and `responseChecksum` (prefixed SHA-256 of the full retained
response's sorted compact UTF-8 JSON). The server returns those same values with
`status: ACKNOWLEDGED`. Only this metadata ACK retries, at most three times. Missing
ACK retains the original tool ID and never repeats the tool. The server must hold
unacknowledged terminal responses and new work for original-operation recovery.
ACK alone does not prove persisted agent conversation: crashed engines must not
resume a used attempt without durable host attachment identity and reconciliation.
Consumer fixtures do not prove this restart boundary.

All endpoints are under `/v1/sandbox/{attemptId}` and use the scan-bound bearer
credential. GET requests also carry `X-LyraShield-Sandbox-Handle`.

| Endpoint | Request beyond binding/IDs | Response beyond binding/IDs/status |
| --- | --- | --- |
| GET `state` | none | `running`, `runtimeAuthority`, `grant` |
| POST `exec` | `argv`, approved `cwd`, fixed `user: pentester`, `timeoutSeconds`, `maxOutputBytes` | `exitCode`, `stdoutBase64`, `stderrBase64` |
| POST `pty/start` | exec fields plus `tty`, `yieldTimeSeconds`, `maxOutputTokens` | `sessionId`, `outputBase64`, `outputCursor`, nullable `exitCode`, nullable `originalTokenCount` |
| POST `pty/stdin` | owned integer `sessionId`, bounded `chars`, `outputCursor`, yield/output bounds | same PTY fields |
| GET `pty/{sessionId}` | query: `outputCursor`, `yieldTimeSeconds`, `maxOutputTokens` | same PTY fields; cursor cannot move backwards |
| POST `pty/terminate` | no session ID means all processes owned by this attempt | completed acknowledgement |
| POST `files/read` (read-only) | scoped `path`, `maxBytes` | `dataBase64`, bare SHA-256 `sha256` |
| POST `files/write` | scoped `path`, `dataBase64`, bare `sha256` | completed acknowledgement |
| POST `workspace/persist` (read-only) | `maxBytes` | `archiveBase64`, bare `sha256` |
| POST `workspace/hydrate` | `archiveBase64`, bare `sha256` | completed acknowledgement |
| GET `port/{port}` | only an installed exposed port | `host`, `port`, `tls`, empty `query` |
| POST `stop` | stable recovery request ID | completed acknowledgement followed by independently observed `running: false` |
| POST `request/{originalRequestId}/ack` | original `requestId`, canonical `responseChecksum` | `status: ACKNOWLEDGED`, same request ID and checksum |

The native SDK adapter implements all six `BaseSandboxSession` primitives:
`_exec_internal`, `read`, `write`, `running`, `persist_workspace` and
`hydrate_workspace`, plus exposed ports and PTY start/stdin/status/termination.
It reuses SDK higher-level file operations. SDK user/environment/mount provisioning
is intentionally replaced by verification of already-installed state. Requests
cannot select root; shell commands still execute as the installed `pentester`
identity. Paths remain beneath the approved workspace; the server must enforce
symlink-safe descriptor traversal and enforce archive extraction bounds. The
existing Caido client requires a protected private tunnel with its normal Caido
authentication; query credentials are rejected because its SDK cannot preserve
them. Scope authority is checked before Caido bootstrap or project mutations.

Files are limited to 8 MiB, workspace archives to 16 MiB, command output to 1 MiB,
responses to 24 MiB and command execution to 300 seconds. The server may tighten
these limits using approved host policy. PTY output is retained append-only with a
cursor so read-only polls do not repeat already delivered output.
Workspace serialization uses portable tar member paths relative to the workspace,
and hydration extracts beneath the granted root; absolute paths, traversal,
escaping symlinks/hardlinks and special-device entries must be rejected.

## Installed signature chain

`state.runtimeAuthority` and `state.grant` use the existing envelope:
`{raw: canonicalJson, result: {algorithm: RS256, keyId, signature: standardBase64}}`.
Canonical JSON sorts keys, uses compact separators and retains UTF-8 characters.
RSA signatures use SHA-256 with PKCS#1 v1.5 and keys of at least 3072 bits.

The managed root key is bundled in `controller-qualification-key.json`; no caller
key or key selected from environment can replace it. The root body uses
`lyrashield-installed-runtime-authority/1`, `launch-qualified-controller`, exact
product/engine revisions, worker/sandbox/broker/supervisor/provider-gateway image
digests, migration/policy/acceptance digests, epoch and positive Unix-second
`issuedAt`. This immutable installed deployment identity does not expire after
fifteen minutes; it is not an execution lease. Its exact issuer identifies
repository `1286618458`, owner
`116722580`, workflow `.github/workflows/issue-runtime-qualification.yml`, product
source, positive run ID and attempt. The consumer matches the protected host
observer's field sets.
Its signed `toolChannel` has exactly `schema: lyrashield-sandbox-tool-channel/1`
and a canonical protected `https://host[:port]` origin. DNS/IPv4 host labels are
ASCII lowercase; default port 443 is omitted. Paths, queries, fragments and user
credentials are rejected. The worker's protected policy URL must match it.

The root delegates one `sandboxGrantSigner` with schema
`lyrashield-sandbox-grant-signer/1`, purpose `sandbox-tool-grants`, `algorithm`,
opaque `keyId`, identical `epochId`/`epoch`, `publicKey` RSA JWK and
`publicKeySha256` (prefixed SHA-256 of DER SubjectPublicKeyInfo). The delegated key
must differ from the managed root. Its private key remains protected on the host
at `/etc/lyrashield/control/sandbox-grant-key.pem`; it is never mounted into the
worker or engine. A signature authorizes this role only; it cannot issue release
qualification.

The delegated per-attempt body uses `lyrashield-runtime-sandbox-grant/v1`,
`installed: true`, `scanId`, the four binding fields, `imageDigest`, bare
`manifestChecksum`/`policyChecksum`, `workspaceRoot`, `exposedPorts`,
`authorizedHosts`, `relayRequired`, Unix-second `issuedAt`/`expiresAt` and
`capabilities`. A grant is issued no earlier than the root and expires within
900 seconds of its own issue time. The static root never proves that its epoch
remains open: the server must check the live current OPEN database epoch under
the shared fence before new grant issuance and every tool invocation. Image and
policy bind the root sandbox/policy digests. Manifest checksum is SHA-256 over
sorted compact UTF-8 JSON from the pinned SDK's `manifest.model_dump(mode=json)`;
it must describe the already prepared resources. The manifest excludes separate
bind mounts, so nonempty caller bind dictionaries explicitly reject before
transport creation. Supporting them requires an installed approved resource
descriptor binding logical target paths, read-only restrictions and immutable
source/attachment/relay/policy identities to this engine run. Mutable caller host
paths cannot establish that authority or be silently ignored.

Capability entries have `status: supported`, nonempty `detail` and independently
observed nonempty `evidence`. Required entries are `exec`, `pty`, `files`, `ports`,
`network_policy`, `mounts` and `exec_constraints`, plus `scoped_relay` when needed.
Missing observation cannot be converted into support by method availability.
The scan ID, authorized hosts and relay requirements must match the engine run.
Before the last sixty grant seconds, tools automatically request authenticated
state renewal. Renewal serializes and retains the identical root and static grant
contents; only issue/expiry times may advance. The server must live-fence the same
OPEN epoch before renewing. No new attempt or paid execution starts.

The product still must implement the fenced server, prepared descriptor/source
installation, independent observations, managed root issuer, protected local
signer, grant renewal, provider integration, authenticated receipts and real
crash/recovery validation. Fixture signatures and simulated HTTP responses prove
consumer behavior only. They do not open production admission.
