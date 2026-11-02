"""The development fixture publisher never follows or replaces output links."""

from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

import pytest


@pytest.fixture
def generator(monkeypatch):
    source = Path(__file__).resolve().parents[1] / "scripts" / "generate-http-evidence-fixtures.py"
    spec = importlib.util.spec_from_file_location("http_fixture_generator", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("LYRASHIELD_RUN_RECORD_V1_1", "1")
    monkeypatch.setenv("LYRASHIELD_PENDING_HTTP_EVIDENCE", "1")
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "local")
    monkeypatch.setattr(module, "STANDARD_CASES", ("reverse-reuse",))
    monkeypatch.setattr(module, "NEGATIVE_CASES", ())
    return module


@pytest.mark.parametrize("link", ["root", "dangling_root", "case", "file", "summary"])
async def test_generate_refuses_existing_output_and_preserves_external_sentinels(
    generator, tmp_path, link
):
    output = tmp_path / "fixtures"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "run.json"
    sentinel.write_bytes(b"test-owned sentinel")
    if link == "root":
        case = outside / "reverse-reuse"
        case.mkdir()
        (case / "run.json").write_bytes(b"test-owned case sentinel")
        output.symlink_to(outside, target_is_directory=True)
    elif link == "dangling_root":
        output.symlink_to(outside / "not-created", target_is_directory=True)
    else:
        output.mkdir()
        if link == "case":
            (output / "reverse-reuse").symlink_to(outside, target_is_directory=True)
        elif link == "file":
            case = output / "reverse-reuse"
            case.mkdir()
            (case / "run.json").symlink_to(sentinel)
        else:
            (output / "summary.json").symlink_to(sentinel)
    before = {
        path.relative_to(outside): path.read_bytes()
        for path in outside.rglob("*")
        if path.is_file()
    }
    try:
        with pytest.raises(FileExistsError):
            await generator.generate(output)
    finally:
        after = {
            path.relative_to(outside): path.read_bytes()
            for path in outside.rglob("*")
            if path.is_file()
        }
        assert after == before
        assert not (outside / "not-created").exists()


async def test_generate_requires_fresh_root_even_without_links(generator, tmp_path):
    output = tmp_path / "fixtures"
    output.mkdir()
    with pytest.raises(FileExistsError):
        await generator.generate(output)
    assert not list(output.iterdir())


async def test_generate_api_publishes_private_files_and_summary(generator, tmp_path):
    output = tmp_path / "fixtures"
    summary = await generator.generate(output)
    assert json.loads((output / "summary.json").read_text()) == summary
    assert summary["reverse-reuse"]["exchanges"] == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    case = output / "reverse-reuse"
    assert stat.S_IMODE(case.stat().st_mode) == 0o700
    for path in (*case.iterdir(), output / "summary.json"):
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_main_refuses_summary_symlink_without_modifying_external_file(
    generator, tmp_path, monkeypatch
):
    output = tmp_path / "fixtures"
    output.mkdir()
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"test-owned sentinel")
    (output / "summary.json").symlink_to(sentinel)
    monkeypatch.setattr("sys.argv", ["fixture-generator", "--output-dir", str(output)])
    try:
        with pytest.raises(FileExistsError):
            generator.main()
    finally:
        assert sentinel.read_bytes() == b"test-owned sentinel"


@pytest.mark.parametrize("injected", ["case", "artifact", "summary", "absent_artifact"])
async def test_links_inserted_after_root_creation_are_not_followed(
    generator, tmp_path, monkeypatch, injected
):
    output = tmp_path / "fixtures"
    outside = tmp_path / "sentinel"
    outside.write_bytes(b"test-owned sentinel")
    if injected == "case":
        run = generator._run_case

        async def insert_case(state, case):
            outcome = await run(state, case)
            (output / case).symlink_to(tmp_path, target_is_directory=True)
            return outcome

        monkeypatch.setattr(generator, "_run_case", insert_case)
    else:
        if injected == "absent_artifact":
            monkeypatch.setattr(generator, "STANDARD_CASES", ("overflow-failed",))
        publish = generator._write_exclusive
        inserted = False

        def insert_file(directory_fd, name, payload):
            nonlocal inserted
            selected = "summary.json" if injected == "summary" else "run.json"
            if not inserted and name == selected:
                inserted = True
                filename = "http_exchanges.json" if injected == "absent_artifact" else name
                generator.os.symlink(outside, filename, dir_fd=directory_fd)
            return publish(directory_fd, name, payload)

        monkeypatch.setattr(generator, "_write_exclusive", insert_file)
    try:
        with pytest.raises(FileExistsError):
            await generator.generate(output)
    finally:
        assert outside.read_bytes() == b"test-owned sentinel"
