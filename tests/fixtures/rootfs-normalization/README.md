# Original package metadata fixtures

These intentionally retain duplicate JSON keys. Do not format or canonicalize the fixtures.

They were extracted from the amd64 and arm64 native candidates in held run `42538824189`; both architectures contained identical bytes. They reproduce the original coverage failures without downloading packages during tests.

| Fixture | Package license | SHA-256 |
| --- | --- | --- |
| `source-map.package.json` | BSD-3-Clause (declared by package) | `3982740d6a191217de9200430ec40ac7db82912801f9e318d20ed2420834b7ea` |
| `windows-release.package.json` | MIT (declared by package) | `4d30a8eaf0f3692f37b1ffd58170c7b739bc22748b84f613a370a069c3ae95c1` |

Only these complete input hashes authorize collapsing their conflicting non-identity `types` / `engines` fields. Any changed input, unreviewed conflict, duplicate identity, or nested duplicate remains rejected. Output must preserve the effective parsed document and package identity.
