"""Release-gate invariants for the published sandbox image."""

from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "publish-sandbox.yml"


def test_published_sandbox_is_smoke_qualified_and_attested() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "platforms: linux/amd64,linux/arm64" in content
    assert "getcap /usr/lib/nmap/nmap" in content
    assert "nmap -sn 127.0.0.1" in content
    assert "candidate-${{ github.sha }}" in content
    assert (
        'image="${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.image.outputs.digest }}"'
        in content
    )
    assert 'docker run --rm --platform "$platform" "$image"' in content
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
