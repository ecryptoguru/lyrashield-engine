#!/usr/bin/env python3
"""Apply run and content policy to JSON emitted by successful gh verification.

This parser does not verify signatures. Invoke only on stdout from gh attestation
verify with the fixed signer, revision, source ref, and hosted-runner policy.
"""

import argparse
import json
import re
from pathlib import Path


QUAL_TYPE = "https://lyrashieldai.com/attestations/sandbox-qualification/v1"
SBOM_TYPE = "https://lyrashieldai.com/attestations/sandbox-sbom/v1"
COVERAGE_TYPE = "https://lyrashieldai.com/attestations/sandbox-sbom-coverage/v1"
PROV_TYPE = "https://slsa.dev/provenance/v1"


def require(value, message):
    if not value:
        raise ValueError(message)


def read_json(path):
    require(path.is_file() and 0 < path.stat().st_size <= 16 * 1024 * 1024, f"invalid file: {path}")
    return json.loads(path.read_bytes())


def accepted(records, *, predicate_type, expected, args, invocation):
    require(isinstance(records, list), "expected verified result list")
    signer = f"https://github.com/{args.repo}/.github/workflows/publish-sandbox.yml@{args.ref}"
    for record in records:
        if not isinstance(record, dict):
            continue
        result = record.get("verificationResult") or {}
        certificate = (result.get("signature") or {}).get("certificate") or {}
        statement = result.get("statement") or {}
        expected_cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "buildSignerURI": signer,
            "buildSignerDigest": args.revision,
            "sourceRepositoryURI": f"https://github.com/{args.repo}",
            "sourceRepositoryDigest": args.revision,
            "sourceRepositoryRef": args.ref,
            "runnerEnvironment": "github-hosted",
            "runInvocationURI": invocation,
        }
        if not all(certificate.get(k) == v for k, v in expected_cert.items()):
            continue
        if (
            statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("predicateType") != predicate_type
        ):
            continue
        if statement.get("subject") != [
            {"name": args.image, "digest": {"sha256": args.digest[7:]}}
        ]:
            continue
        predicate = statement.get("predicate")
        if predicate_type == PROV_TYPE:
            if (
                not isinstance(predicate, dict)
                or ((predicate.get("runDetails") or {}).get("metadata") or {}).get("invocationId")
                != invocation
            ):
                continue
        elif predicate != expected:
            continue
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "image", "digest", "revision", "ref", "run-id", "run-attempt"):
        parser.add_argument("--" + name, required=True)
    for name in ("provenance", "qualification", "sbom", "expected-qualification", "expected-sbom"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--expected-coverage", type=Path)
    parser.add_argument("--phase", required=True, choices=("publication", "coverage"))
    args = parser.parse_args()
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest)), "invalid subject digest")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", args.revision)), "invalid revision")
    require(
        bool(re.fullmatch(r"[1-9][0-9]*", args.run_id))
        and bool(re.fullmatch(r"[1-9][0-9]*", args.run_attempt)),
        "invalid run identity",
    )
    invocation = (
        f"https://github.com/{args.repo}/actions/runs/{args.run_id}/attempts/{args.run_attempt}"
    )
    attestations = [
        (args.provenance, PROV_TYPE, None),
        (args.qualification, QUAL_TYPE, args.expected_qualification),
        (args.sbom, SBOM_TYPE, args.expected_sbom),
    ]
    if args.phase == "coverage":
        require(
            args.coverage is not None and args.expected_coverage is not None,
            "coverage phase requires coverage and expected coverage",
        )
        attestations.append((args.coverage, COVERAGE_TYPE, args.expected_coverage))
    elif args.coverage is not None or args.expected_coverage is not None:
        raise ValueError("publication phase does not accept coverage predicates")
    for path, predicate_type, expected_path in attestations:
        expected = read_json(expected_path) if expected_path else None
        if expected is not None:
            require(
                isinstance(expected, dict)
                and expected.get("runId") == args.run_id
                and expected.get("runAttempt") == args.run_attempt
                and expected.get("indexDigest") == args.digest,
                "expected predicate identity mismatch",
            )
        require(
            accepted(
                read_json(path),
                predicate_type=predicate_type,
                expected=expected,
                args=args,
                invocation=invocation,
            ),
            f"no accepted {predicate_type} attestation",
        )


if __name__ == "__main__":
    main()
