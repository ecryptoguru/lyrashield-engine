# Sandbox Go security overlay

These are LyraShield rebuilds of the exact upstream application revisions listed
in `sources.tsv`. CLI application versions stay equal to those sources. The
binaries are not represented as the vendor's original release artifacts.

Each source archive URL and SHA256 is recorded before extraction. The reviewed
per-tool `go.mod` and `go.sum` select the security graph while retaining upstream
module replacements. The build requires Go1.27.3, Go checksum database
verification, readonly compilation and unchanged lock checksums. No tool is
UPX-packed, so image audits can inspect every executable's Go build metadata.

The image retains this manifest, upstream LICENSE/NOTICE files, source URL/SHA,
actual resolved module locks, compatibility patches and `go version -m` output
under `/usr/local/share/lyrashield/go-tools/`. Compiler license/patent notices are
included. Source remains available at the immutable URLs; the application
licenses and copyright notices remain those of the respective upstream projects.

Security floors include x/net0.62.0 and its required crypto0.58.0/text0.43.0 graph,
compress1.18.7, pgx5.12.0 for Katana, go-jose4.1.6/grpc1.83.2 for Trivy and
TruffleHog, and the additional exact tool-specific fixes documented in the locks.
Gitleaks retains its `gore2regex` build tag; fixed rardecode2.2.1 restores the WriteTo API required by
the original archives0.1.2 adapter. Trivy retains `jsonv2`. Both retain their upstream
version ldflags. All eight original image binaries used CGO_ENABLED=0; the
rebuilds preserve that setting on both Linux architectures.

Gospider's compatibility patch recognizes IP literals before the patched
publicsuffix parser rejects them. It preserves the previously working direct-IP
crawl capability without changing domain-target scope handling. Trivy's patch
uses Go1.27's errors.ErrUnsupported replacement for experimental json.SkipFunc
without consuming decoder input, preserving the location-tracking fallback.

Compatibility fixtures run against loopback HTML and synthetic secret/benign
files, including gzip/tar, Zstandard and XZ traversal. They use no credentials, verification
providers or external targets. Source compilation, fixture success and the raw
image vulnerability audit are separate release checks. Advisory rows with no
fixed version remain visible and require package/symbol/trigger-condition
analysis tied to the actual executable digest; this overlay supplies no ignores.

Primary references:
- https://go.dev/dl/
- https://go.dev/doc/devel/release#go1.27.3
- https://pkg.go.dev/vuln/GO-2026-6866
- https://github.com/jackc/pgx/blob/v5.12.0/CHANGELOG.md
- https://github.com/nwaples/rardecode/blob/v2.2.1/reader.go

Trivy's module Go directive is raised to 1.27.0 to match its patched JSON API
contract; the exact compiler remains 1.27.3. The source package tests keep Go
vet enabled and verify fallback input preservation.

Independent govulncheck adds Goldmark 1.7.17 (GO-2026-5320/CVE-2026-5160)
where already imported. `verify_goldmark.go` checks escaped links, autolinks,
images and a benign HTTPS link against each actual selected graph during the
build. The old 1.7.13 renderer fails the same regression. See
https://pkg.go.dev/vuln/GO-2026-5320 and the upstream fixed renderer.
