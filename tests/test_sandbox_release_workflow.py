"""Release-gate invariants for the published sandbox image."""

from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "publish-sandbox.yml"
CI_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
SMOKE = Path(__file__).parents[1] / "scripts" / "smoke-sandbox.sh"


def test_ci_audits_hash_pinned_container_locks_without_dependency_resolution() -> None:
    content = CI_WORKFLOW.read_text(encoding="utf-8")
    audit_job = content.split("  python-audit:", 1)[1].split("\n  verify:", 1)[0]

    assert "Audit hash-pinned Dirsearch package" in audit_job
    assert (
        "pip-audit --require-hashes --disable-pip -r containers/dirsearch-requirements.txt"
    ) in audit_job
    assert "Audit hash-pinned sandbox Python dependency lock" in audit_job
    assert (
        "pip-audit --require-hashes --disable-pip -r containers/python-requirements.txt"
    ) in audit_job


def test_published_sandbox_is_smoke_qualified_and_attested() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "platforms: linux/amd64,linux/arm64" in content
    smoke = SMOKE.read_text(encoding="utf-8")
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    replay_probe = ci.split("name: Guarded replay egress probes (built image)", 1)[1].split(
        "\n      - name:", 1
    )[0]
    assert "from caido_api import _ip_denial, _replay_denial as blocked" in replay_probe
    assert "blocked(url) is not None" in replay_probe
    assert 'bash scripts/smoke-sandbox.sh "$image" "$platform"' in content
    assert "bash scripts/smoke-sandbox.sh lyrashield-sandbox:ci" in ci
    for invariant in (
        'test "$(id -u)" != "0"',
        'test "$(pwd)" = "/workspace"',
        "test -f /app/certs/ca.p12",
        "test ! -S /var/run/docker.sock",
        "test ! -w /etc",
        "caido-cli --version",
        "getcap /usr/lib/nmap/nmap",
        "nmap -sn 127.0.0.1",
        "import caido_api",
        "200|400",
    ):
        assert invariant in smoke
    assert "candidate-${{ github.sha }}" in content
    assert (
        'image="${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.image.outputs.digest }}"'
        in content
    )
    assert "docker_args=(--rm)" in smoke
    assert 'docker_args+=(--platform "$platform")' in smoke
    assert 'docker run "${docker_args[@]}" "$image"' in smoke
    assert "docker buildx imagetools create" in content
    assert "RELEASE_TAG: ${{ github.ref_name }}" in content
    assert 'for tag in "$RELEASE_TAG" "${{ github.sha }}"' in content
    assert "${{ env.IMAGE_NAME }}:${{ github.ref_name }}" not in content
    assert "Build the exact platform image" not in content
    assert content.index("Smoke the exact candidate digest") < content.index(
        "Promote the smoke-qualified digest"
    )
    assert content.index("Promote the smoke-qualified digest") < content.index(
        "Generate an SPDX SBOM"
    )
    assert "push: true" in content
    assert "provenance: mode=max" in content
    assert "sbom: true" in content
    assert "sbom-path: sandbox.spdx.json" in content
    assert "subject-digest: ${{ steps.image.outputs.digest }}" in content
    assert "push-to-registry: true" in content
    assert "@v" not in content
