# Runtime and dependency qualification — 2026-11-02

The owned runtime fixes preserve evidence on unrelated bad requests, select
Responses by admitted GPT-6 capability and explicit API policy, bound LLM
preflight to 30 seconds, and share Docker context/TLS selection across discovery,
image acquisition, and sessions. CA-only and mutual TLS retain HTTPS even when
Docker SDK context properties omit that material. Malformed/partial TLS fails
closed. Raw context metadata preserves the distinction between TLS encryption
and certificate verification: `SkipTLSVerify: true` still enables encrypted
transport without stored PEMs, while an omitted flag does not inherit the SDK
normalization. Preflight honors the configured hard output cap (up to 64 probe output
tokens) and persists successful paid usage before a later probe failure exits.

## Source validation

- Full Python suite: **3,067 passed, 7 skipped**, with one upstream Pydantic warning.
- Full lint/format: **441 Python files**. Full mypy: **246 source files**.
- Root/delegate/fallback/dedupe routing, native Responses wire token limits,
  retries, compaction, pricing/cache, usage serialization, private Docker SDK
  signatures, packaging, and cancellation regression suites passed.
- Real Docker context metadata fixtures prove CA-only and mutual TLS over HTTPS,
  including contexts with a Kubernetes stack orchestrator. A mocked seven-token
  main/dedupe probe preserves its hard cap and writes the successful nine-token
  main usage into the failed receipt when the judge times out.

## Frozen dependency graph

The engine lock retains OpenAI Agents **0.19.4** and OpenAI **2.48.0**, qualifying
LiteLLM **1.101.3** independently. Narrow security updates also include aiohttp
3.14.5, graphql-core 3.2.13, MCP 1.30.0, certifi 2026.10.18, filelock 4.2.1,
msgpack 1.2.3, Pillow 13.0.0, pypdf 6.21.4, setuptools 84.1.0, and virtualenv
21.14.10, with required packaging 26.3 and yarl 1.25.1.

Vite is exactly pinned to **6.4.5**. The initially requested 6.4.4 was rejected
by the fresh [GHSA-8g5g-mxqh-grgj](https://github.com/advisories/GHSA-8g5g-mxqh-grgj)
advisory. npm ci, typecheck, build, and audit pass; the existing chunk-size
warning remains. LiteLLM 1.101.0 also retained CVE-2026-114612; 1.101.3 is the
qualified security patch. Virtualenv 21.14.9 retained CVE-2026-113713.

| Advisory audit scope | Distributions | Known vulnerabilities |
| --- | ---: | ---: |
| Engine base runtime, local macOS | 92 | 0 |
| Engine all extras/groups, local macOS | 135 | 0 |
| Engine all extras/groups, Linux Python 3.12 / x86_64 | 136 | 0 |
| Engine all extras/groups, Linux Python 3.12 / aarch64 | 136 | 0 |
| Engine all extras/groups, Linux Python 3.13 / x86_64 | 136 | 0 |
| Engine all extras/groups, Linux Python 3.13 / aarch64 | 136 | 0 |
| Engine all extras/groups, Linux Python 3.14 / x86_64 | 136 | 0 |
| Engine all extras/groups, Linux Python 3.14 / aarch64 | 136 | 0 |
| Sandbox tool Python graph | 105 | 0 |

Linux target environments were evaluated against every frozen exported
requirement marker before marker removal; all retained exact pins and hashes
were preserved for advisory checks. The targets include Linux-only Jeepney and
SecretStorage. `linux-audit-targets.json` records target environments and the
SHA256 hashes of each evaluated requirements file and advisory receipt. These
are target dependency/advisory results, separate from installed image proof.

The sandbox's unchanged Semgrep 1.178.0 wheel uses exact reviewed metadata
exceptions for MCP 1.30.0 and OpenTelemetry API/SDK/exporter 1.45.1 with matching
instrumentation 0.66b1. Every original dependency field and METADATA RECORD hash
is checked before any write. The real hash-locked installation passes pip check,
JWT validation/denial and redirect checks, and its unchanged CLI emits the
expected single JSON finding. Real thread/requests instrumentation preserves
parent context and exports OTLP protobuf to a loopback fixture. No paid provider
or external telemetry service is contacted. See the sandbox dependency
[exception policy](../../../containers/README.md).

## Decoder and scanner provenance

The signed Kali snapshot still serves vulnerable Brotli `1.2.0-4+b1` on both
architectures. The installer adds no Debian apt source and overlays only official
Debian `libbrotli1=1.2.0-4.1` after architecture-specific SHA256 verification.
Tampered bytes never reach installation. Both exact packages pass a real decoder
invocation in the separate component verification image. The manifest digest and
package hashes are retained in `brotli-component-receipt.json`.

TruffleHog **3.99.2** release archives match the upstream checksum manifest; its
manifest SHA256 matches GitHub's published release-asset digest
`53d747ab72d83c97f851adc03e6d4c488f685c73dbc5b0619f2affff9439cb6b`.
Both Linux architecture binaries execute `--version` successfully on the pinned
Kali base. The checked upstream checksum file is retained here.

## Authenticated runtime archive transport

Kali's [official site registry](https://www.kali.org/docs/community/list-of-official-kali-sites/)
identifies `kali.download` as its Cloudflare-backed package mirror. The archive
and CDN served byte-identical signed `kali-last-snapshot` InRelease metadata
(SHA256 `62375e475a01fed422730632651d784cc42c4145223313178c8519f9822eefc6`).
The measured 87.2 MB Chromium asset transferred from the CDN at 13.48 MB/s,
removing the observed archive download bottleneck. The runtime build first
installs CA certificates through the signed archive and then uses HTTPS for
bulk packages, retaining the pinned keyring, explicit `signed-by`, suite, and
all three fail-closed apt settings. No insecure TLS or repository flags were
added. The exact transport and trust receipt is retained in
`kali-cdn-transport-receipt.json`. Both rebuilt images carry the exact input
revision in `org.opencontainers.image.revision`.

## Remaining acceptance gate

Complete sandbox image builds for both architectures are still running against
the signed Kali archive. Full image digests, installed image advisory scans, and
full sandbox smoke acceptance remain unproven. The decoder component manifest
is **not** a qualified sandbox image digest. No deployment or release was made.
