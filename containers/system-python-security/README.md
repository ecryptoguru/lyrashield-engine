# Qualified system Python security amendments

This is the separate repair path for Debian-owned system Python. It does not
change the application venv or relax its pip RECORD/BOM verifier. The qualification
input has SHA256
`4499b68a97dc24edd3830c2baaef243b7e559473db91e10a2bcd8d3a8b54b9d4`.

`leaves.json` pins eight packages for arm64 and amd64. The installer verifies the
archived `InRelease` with the image's official keyring through `sqv`, verifies the
compressed Packages index against that signed Release, matches the binary/source
identity and hash in that index, verifies each deb, and rejects an APT plan other
than eight upgrades, zero additions and zero removals. No repository is added.
The archive URLs are mutable: if a pinned index has rotated out, the build fails
closed. Supply those exact artifacts through `--cache` for offline builds; update
the entire qualification explicitly rather than accepting new unsigned bytes.

`amendments.json` records exact full-file SHA256 and original dpkg MD5 anchors,
package versions, minimal replacements, resulting hashes and upstream commits.
It covers h2, hpack, SoupSieve, Mako, OAuthLib PKCE and device-code validation,
setuptools' private jaraco, and system pip's urllib3. Every input is checked before
source mutation. The installer and amendment are intended for the qualified
baseline, once, after its final APT operation; an already-amended or drifting base
fails its original-byte contract.

The system pip package has no top-level RECORD/BOM. Its complete 446-file original
source inventory and dpkg ownership are checked independently. The replacement
urllib3 wheel is fixed at 2.8.0 with SHA256
`0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3`.
Only its package sources, typing marker and license enter pip's private namespace;
the one absolute self-import is adapted. The original pip vendor manifest is
updated. Both pip and setuptools seed wheels are checked against original SHA256
and complete outer RECORDs, rewritten reproducibly, and rehashed. The setuptools
seed's nested private jaraco RECORD is also updated. Normal upstream package
versions are retained; they are not claims of unmodified official bytes.

The installed receipts under `/usr/share/lyrashield/security/` identify the
original signed packages and each downstream before/after hash. Original dpkg
metadata remains available, so an intentional amended-file MD5 difference can be
reconciled with the receipt rather than hidden. No package, capability, license,
`pkg_resources` API, module, or dependency is removed; obsolete compiled caches
are discarded so old code cannot shadow the amended source.

## Docker integration

The runtime owner must integrate after **the last APT command**, before final
smokes. These standalone files deliberately do not edit the common Dockerfile:

```dockerfile
COPY containers/system-python-security /opt/lyrashield/system-python-security
RUN /usr/bin/python3 /opt/lyrashield/system-python-security/install_leaves.py \
    && /usr/bin/python3 /opt/lyrashield/system-python-security/amend_sources.py \
    && /usr/bin/python3 /opt/lyrashield/system-python-security/verify_runtime.py
```

The verifier and provenance remain root-owned in the image so the final
non-root offline smoke can repeat the checks after all subsequent installation.
`python3-brotli` and `libbrotli1` are owned by the runtime repair lane and must
also be pinned to compatible fixed signed packages. Effective CA distrust,
application pip, Node, native tools and final-image gates remain in that lane.
Do not run another APT installation after the amendments or the changed source
and seed wheel may be overwritten. To test fail-closed behavior, run
`check_preconditions.py /path/to/pinned-urllib3.whl` after leaf installation and
before `amend_sources.py`. Pass `--urllib3-wheel` for an offline amendment.

## Evidence and advisory boundaries

The arm64 ephemeral qualification used baseline image config digest
`52e38fb8105145c7b049291c4ecc1e12d619633acd47cf97f3ab704ac2d118c0`,
no network, a 512 MiB memory cap and 0.5 CPU. Both architecture signed artifact
chains are verified; amd64 installation and execution are not claimed by this
lane. `provenance/arm64-ephemeral-*.json` and the raw smoke log record the actual
amended test filesystem, not a rebuilt or published image.

`verify_runtime.py` exercises actual H2Connection header parsing, all HPACK prefix
widths, valid/invalid tar and template operations, bounded SoupSieve cases, PKCE's
constant-time API, device-grant token issuance, signed-leaf package APIs,
mitmproxy request objects, Wapiti HTML report generation, ndiff XML comparison,
and a fresh offline venv seeded from the amended pip/setuptools wheels. The fresh
seed repeats private-jaraco extraction and actual pip requests PoolManager checks.
No external target, scan, paid provider, image build or image pull is involved.

The author's [OAuth device grant advisory](https://github.com/oauthlib/oauthlib/security/advisories/GHSA-3jp2-3mrg-2vxc)
specifies 4.0.1; the aggregator's 4.0.0 floor is insufficient. This patch ports the
required device-code field, validator hook, status mapping and stored-scope
checks from upstream commit `77a5f1c8ce00da2b0b8c5f6e9cc129920085f114`, retaining
3.x client/authentication interfaces. Unknown, missing, pending, slow-down,
expired, denied and approved states are tested; only approval issues a token.
Installed lazr.restfulclient is a consumer, and this repository defines no inbound
device-grant server. Arbitrary custom scripts are not declared unreachable.

Pip's private msgpack remains the Python fallback, not `_cmsgpack`. The
[leak advisory](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-j586-36cw-2gc2)
identifies the C decoder and separately discusses the fallback; the
[reuse-after-error advisory](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-6v7p-g79w-8964)
concerns native memory safety. Runtime assertions prove both pip Packer and
Unpacker originate from the fallback. The separate Debian native extension is
upgraded. No blanket CVE ignore or invented version is used.

`advisory-dispositions.json` preserves all 51 original advisory decisions, the
five pip-vendored urllib3 advisories, Mako's missed finding, and all nine unmatched
distributions. It distinguishes existing Debian backports and Linux platform
boundaries from applied fixes and outstanding runtime/final-image gates.
