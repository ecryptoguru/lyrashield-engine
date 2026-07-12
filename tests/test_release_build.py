from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_binary_uses_product_adapter_entrypoint() -> None:
    spec = (ROOT / "strix.spec").read_text()
    assert "['lyrashield_adapter/cli.py']" in spec
    assert "['strix/interface/main.py']" not in spec


def test_product_adapter_can_run_as_a_script() -> None:
    adapter = (ROOT / "lyrashield_adapter/cli.py").read_text()
    assert 'if __name__ == "__main__":' in adapter
    assert "    main()" in adapter


def test_binary_does_not_bundle_unused_litellm_proxy_modules() -> None:
    spec = (ROOT / "strix.spec").read_text()
    assert "collect_submodules('litellm')" not in spec


def test_binary_does_not_request_missing_hidden_imports() -> None:
    spec = (ROOT / "strix.spec").read_text()
    for module in (
        "xmltodict",
        "defusedxml",
        "strix.tools.proxy._calls",
        "strix.tools.python.tool",
    ):
        assert f"'{module}'" not in spec


def test_build_script_fails_when_binary_smoke_test_fails() -> None:
    script = (ROOT / "scripts/build.sh").read_text()
    assert 'scripts/smoke_release.py "$RELEASE_DIR/$BINARY_NAME" "$VERSION"' in script
    assert '"$RELEASE_DIR/$BINARY_NAME" --help' not in script
    assert 'echo -e "${RED}Binary test failed${NC}"; exit 1' in script
