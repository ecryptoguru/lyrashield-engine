# Guarded native sandbox start

The image owns `/opt/lyrashield/sandbox_start.py`, the SDK-free shared
`controller_authority.py` verifier and the pinned managed public key. The
controller invokes only this fixed command as `pentester`:

```text
/app/.venv/bin/python -I /opt/lyrashield/sandbox_start.py --ticket /run/lyrashield/tickets/{requestId}.json
```

No caller selects a wrapper, signing key, environment, credential, mount or
deadline. Public installed authority is read from
`/etc/lyrashield/runtime-authority.json`; the approved resource descriptor is
read from `/etc/lyrashield/sandbox-resource.json`. Records and ancestor
directories must be root-owned, have no group/world write access and contain no
symlinks. The admitted process remains the existing nonroot `pentester` identity.
There are no networking or model-routing changes.

The installed resource schema is `lyrashield-prepared-sandbox-resource/1`.
Its exact bytes bind scan, attempt, operation, epoch, opaque handle, approved
container, image, SDK manifest, policy and `/workspace`. It must also contain
the complete trusted source/attachment/relay/mount descriptors produced by the
preparation compiler. Copying caller host paths into this record does not
qualify them. Mounted-source integration remains a separate launch requirement.

The ticket uses the existing canonical `raw/result` RS256 envelope, signed by
the epoch's delegated `sandboxGrantSigner`, never by a worker-supplied key.
The root authority's pinned signature, issuer, role, epoch and key delegation
verify before the local ticket. Its exact schema is
`lyrashield-sandbox-start-ticket/1`, purpose `sandbox-tool-start`.

| Ticket fields | Binding |
| --- | --- |
| `scanId`, `attemptId`, `operationId`, `authorityEpochId`, `sandboxHandle` | original persisted attempt |
| `guardId`, `authorityChecksum`, `actionChecksum`, `requestId`, `commandId` | original immutable guard and request; issuer must verify them under the live fence |
| `containerId`, `imageDigest`, `manifestChecksum`, `runtimePolicyDigest` | exact prepared owned resource and installed root identity |
| `resourceDescriptorChecksum`, `runtimeAuthorityChecksum` | prefixed SHA-256 of retained resource bytes and canonical root body bytes |
| `command`, `commandSha256` | canonical `{argv,cwd,user}`; fixed `pentester`, `/workspace`, bounded argv |
| `clock` | `CLOCK_MONOTONIC`, exact kernel `bootId` and `timeNamespace`, decimal-string `issuedAtNs` and `deadlineNs` |
| `executionDeadlineNs` | separate signed absolute lifetime, no later than issue time plus 300 seconds |

The start deadline is at most ten seconds after the qualified native clock
sample. Derive it conservatively from the existing guarded DB clock/deadline
read using a qualified same-kernel monotonic sample taken before the query.
Network/query delay must shorten validity. A macOS host clock, an arbitrary
relative counter or worker-provided clock cannot substitute for this proof.
Nanoseconds use decimal strings so long host uptime cannot lose JS precision.
Retain the signed ticket with its original authenticated operation before dispatch.

After all verification and directory setup, the final fresh monotonic sample
defines **start admission**. Starting a precreated Docker exec after this
deadline is rejected with exit code 125 and no admission frame. This does not
promise zero scheduling delay between admission and the first tool instruction.

Admission writes one first stderr frame:

```text
LYRASHIELD_START_ADMISSION {canonical JSON}\n
```

The frame contains schema `lyrashield-sandbox-start-admission/1`, original
request/guard/command checksum, `admittedAtNs` and `executionDeadlineNs`.
The protected server must bind the frame to the original exact Docker exec and
ticket, strip only that first frame, and preserve subsequent tool stdout/stderr.
TTY transport can change the frame's line ending to CRLF; normalize only the
control frame. Tool bytes retain normal TTY behavior. A frame is admission
evidence, not a terminal receipt or proof the engine received its response.

**Arm the protected whole-sandbox watchdog before dispatch**, using the signed
absolute execution deadline. It must remain independently runnable if sandbox
processes stop, fork or change process groups. On expiry, uncertain start,
missing acknowledgement or a dead engine, stop the entire original owned
sandbox and independently observe it stopped. Keep the original operation and
uncertain holds; never recreate paid work. Process-group timeout or a Python
check alone does not establish this lifetime boundary. POSIX timer signals are
asynchronous and exec resets those timers; this change adds no LSM or promise
of kernel-atomic expiry.

Native ticket binding is not a standalone one-use ledger. The server must
deduplicate original guard/request identities, retain terminal responses and
receipt ACKs, and reject fresh engine attachments to used uncertain attempts.
No agent transcript replay framework is needed to safely finalize a crashed
attempt as failed/inconclusive after reconciliation.

Disposable tests run the exact pinned Linux sandbox base with a read-only
checked-source overlay and test-only public signing root. They verify delayed
start rejection, unchanged output, clock/resource substitution failures and
whole-sandbox termination of a `SIGSTOP` process by separately owned control.
They do not qualify the production image, installed watchdog, real guard issuer,
mounted repository sources, live engine attachment or paid execution.
