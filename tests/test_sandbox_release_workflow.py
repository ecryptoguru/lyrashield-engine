"""Release-gate invariants for the published sandbox image."""

from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "publish-sandbox.yml"


def test_published_sandbox_is_smoke_qualified_and_attested() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "linux/amd64, linux/arm64" in content
    assert "getcap /usr/lib/nmap/nmap" in content
    assert "nmap -sn 127.0.0.1" in content
    assert "push: true" in content
    assert "provenance: mode=max" in content
    assert "sbom: true" in content
    assert "sbom-path: sandbox.spdx.json" in content
    assert "subject-digest: ${{ steps.image.outputs.digest }}" in content
    assert "push-to-registry: true" in content
    assert "@v" not in content
