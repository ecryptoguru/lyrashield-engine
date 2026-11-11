"""Synthetic tests for a single-layer, inert capability-aware changeset."""

import hashlib
import io
import tarfile

import pytest

from scripts import catalog_pax_capability_headers as catalog


CAP = b"SCHILY.xattr.security.capability"


def record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + len(body) + 1 != size:
        size = len(str(size)) + len(body) + 1
    return str(size).encode() + b" " + body


def fixture():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("bin/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        pax = record(b"path", b"bin/actual") + record(CAP, b"\x00\xffcap")
        extension = tarfile.TarInfo("pax")
        extension.type = tarfile.XHDTYPE
        extension.size = len(pax)
        archive.addfile(extension, io.BytesIO(pax))
        binary = tarfile.TarInfo("placeholder")
        binary.size = 3
        archive.addfile(binary, io.BytesIO(b"abc"))
        link = tarfile.TarInfo("bin/alias")
        link.type = tarfile.LNKTYPE
        link.linkname = "bin/actual"
        archive.addfile(link)
        sym = tarfile.TarInfo("bin/sym")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../elsewhere"
        archive.addfile(sym)
        archive.addfile(tarfile.TarInfo("bin/.wh.victim"))
        archive.addfile(tarfile.TarInfo("bin/.wh..wh..opq"))
    return out.getvalue()


def inspect(data, *, expected=None, **kwargs):
    fn = getattr(catalog, "inspect_layer_changeset", None)
    assert fn is not None, "expected complete per-member changeset collector"
    digest = expected or "sha256:" + hashlib.sha256(data).hexdigest()
    return fn(io.BytesIO(data), digest, **kwargs)


def test_collects_all_members_and_exact_capability_for_later_overlay():
    data = fixture()
    result = inspect(data)
    assert [row.path for row in result] == [
        "bin",
        "bin/actual",
        "bin/alias",
        "bin/sym",
        "bin/.wh.victim",
        "bin/.wh..wh..opq",
    ]
    assert [row.kind for row in result] == [
        "dir",
        "file",
        "hardlink",
        "symlink",
        "whiteout",
        "opaque",
    ]
    assert result[1].capability_value == b"\x00\xffcap"
    assert data[result[1].data_offset : result[1].data_offset + result[1].size] == b"abc"
    assert result[2].target == "bin/actual" and result[3].target == "../elsewhere"
    assert result[4].target == "bin/victim" and result[5].target == "bin"
    assert all(row.capability_value is None for row in result if row.path != "bin/actual")
    assert all(row.data_offset is None for row in result if row.kind != "file")
    assert "actual" not in repr(result[1]) and "cap" not in repr(result[1])


def test_no_changeset_returned_for_bad_diffid_or_incomplete_framing():
    data = fixture()
    with pytest.raises(ValueError):
        inspect(data, expected="sha256:" + "0" * 64)
    with pytest.raises(ValueError):
        inspect(data[:-512] + b"X" * 512)


def test_duplicate_names_and_capability_on_hardlink_are_rejected():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(tarfile.TarInfo("a"))
        archive.addfile(tarfile.TarInfo("a"))
    with pytest.raises(ValueError):
        inspect(out.getvalue())
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        pax = record(CAP, b"x")
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = len(pax)
        archive.addfile(header, io.BytesIO(pax))
        link = tarfile.TarInfo("alias")
        link.type = tarfile.LNKTYPE
        link.linkname = "target"
        archive.addfile(link)
    with pytest.raises(ValueError):
        inspect(out.getvalue())


def test_invalid_whiteout_rejected_instead_of_being_interpreted_as_file():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        whiteout = tarfile.TarInfo(".wh.target")
        whiteout.size = 1
        archive.addfile(whiteout, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        inspect(out.getvalue())


@pytest.mark.parametrize("name", [".wh.", ".wh..", ".wh...", ".wh..wh.fake"])
def test_invalid_whiteout_targets_fail_closed(name):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(tarfile.TarInfo(name))
    with pytest.raises(ValueError):
        inspect(out.getvalue())


def test_path_only_pax_is_associated_but_opaque_payload_not_retained():
    out = io.BytesIO()
    pax = record(b"path", b"effective")
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = len(pax)
        archive.addfile(header, io.BytesIO(pax))
        archive.addfile(tarfile.TarInfo("placeholder"))
    (row,) = inspect(out.getvalue())
    assert row.path == "effective" and row.pax_header_offset == 0
    assert row.pax_payload is None and row.capability_value is None


def test_linux_literal_member_names_are_opt_in_and_never_host_paths():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(tarfile.TarInfo("a\\b"))
    data = out.getvalue()
    with pytest.raises(ValueError):
        inspect(data)
    assert inspect(data, linux_literal_paths=True)[0].path == "a\\b"
    with pytest.raises(ValueError):
        inspect(data, linux_literal_paths=1)


def test_capability_budget_rejection_never_returns_partial_records(monkeypatch):
    data = fixture()
    monkeypatch.setattr(catalog, "MAX_TOTAL_PAX_BYTES", 1)
    with pytest.raises(ValueError, match="aggregate"):
        inspect(data)


def test_fragmented_stream_preserves_pax_association_and_exact_offsets():
    class Fragmented(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 73))

    data = fixture()
    result = catalog.inspect_layer_changeset(
        Fragmented(data), "sha256:" + hashlib.sha256(data).hexdigest()
    )
    assert result[1].capability_value == b"\x00\xffcap"
    assert data[result[1].data_offset : result[1].data_offset + result[1].size] == b"abc"


def test_member_count_and_path_byte_limits_apply_to_changesets(monkeypatch):
    data = fixture()
    monkeypatch.setattr(catalog, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="limit"):
        inspect(data)
    monkeypatch.setattr(catalog, "MAX_ENTRIES", 100_000)
    monkeypatch.setattr(catalog, "MAX_PATH_BYTES", 2)
    with pytest.raises(ValueError, match="limit"):
        inspect(data)


def test_no_pax_value_or_member_path_is_in_a_result_representation():
    output = repr(inspect(fixture()))
    assert "bin/" not in output and "elsewhere" not in output and "\\xffcap" not in output
