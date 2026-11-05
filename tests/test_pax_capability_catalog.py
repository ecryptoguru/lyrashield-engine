"""Synthetic checks for an unwired raw capability header catalog."""

import hashlib
import io
import os
import tarfile
import traceback

import pytest

from scripts import catalog_pax_capability_headers as catalog


CAP = b"SCHILY.xattr.security.capability"
VALUE = b"\x00\xff\n=\x80binary\x00"


def record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + len(body) + 1 != size:
        size = len(str(size)) + len(body) + 1
    return str(size).encode() + b" " + body


def make_tar(payload, *, name="raw-name", kind=tarfile.REGTYPE, target="raw-target"):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        extended = tarfile.TarInfo("synthetic-pax")
        extended.type = tarfile.XHDTYPE
        extended.size = len(payload)
        archive.addfile(extended, io.BytesIO(payload))
        member = tarfile.TarInfo(name)
        member.type = kind
        if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
            member.linkname = target
        archive.addfile(member)
    return out.getvalue()


def inspect(data):
    return catalog.inspect_layer(io.BytesIO(data), "sha256:" + hashlib.sha256(data).hexdigest())


def test_raw_binary_and_path_override_are_associated_to_following_file():
    payload = record(b"path", b"dir/effective") + record(CAP, VALUE)
    (observation,) = inspect(make_tar(payload))
    assert observation.path == "dir/effective"
    assert observation.kind == "file" and observation.target == ""
    assert observation.member_header_offset == 1024
    assert observation.pax_header_offset == 0
    assert observation.pax_payload == payload and observation.value == VALUE
    assert "effective" not in repr(observation) and "binary" not in repr(observation)


@pytest.mark.parametrize("pax", [False, True], ids=["raw", "pax"])
def test_linux_literal_backslash_capability_member_is_opt_in(pax):
    payload = record(CAP, VALUE) + (record(b"path", b"dir\\literal") if pax else b"")
    data = make_tar(payload, name="raw" if pax else "dir\\literal")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with pytest.raises(ValueError):
        catalog.inspect_layer(io.BytesIO(data), digest)
    (observation,) = catalog.inspect_layer(io.BytesIO(data), digest, linux_literal_paths=True)
    assert observation.path == "dir\\literal"


def test_linux_literal_catalog_keeps_whiteout_policy_and_strict_option_type():
    data = make_tar(record(CAP, VALUE), name=".wh.a\\b")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with pytest.raises(ValueError):
        catalog.inspect_layer(io.BytesIO(data), digest, linux_literal_paths=True)
    with pytest.raises(ValueError):
        catalog.HeaderReader(linux_literal_paths=1)


def test_symlink_path_and_linkpath_are_inert_and_preserved():
    payload = (
        record(CAP, VALUE) + record(b"linkpath", b"../target//") + record(b"path", b"dir/link")
    )
    (observation,) = inspect(make_tar(payload, kind=tarfile.SYMTYPE))
    assert (observation.path, observation.kind, observation.target) == (
        "dir/link",
        "symlink",
        "../target//",
    )
    assert observation.pax_payload == payload and observation.value == VALUE


@pytest.mark.parametrize(
    "payload",
    [
        record(CAP, b"x") + record(CAP, b"y"),
        record(b"path", b"a") + record(b"path", b"b") + record(CAP, b"x"),
        record(b"private-key", b"private") + record(CAP, b"x"),
        record(CAP, b""),
        b"01 x=x\n",
    ],
)
def test_duplicate_unknown_empty_and_noncanonical_records_fail(payload):
    with pytest.raises(ValueError):
        inspect(make_tar(payload))


@pytest.mark.parametrize(
    "name,kind", [("hard", tarfile.LNKTYPE), (".wh.old", tarfile.REGTYPE), ("dir", tarfile.DIRTYPE)]
)
def test_capability_on_ambiguous_inode_or_whiteout_is_rejected(name, kind):
    with pytest.raises(ValueError):
        inspect(make_tar(record(CAP, VALUE), name=name, kind=kind))


def test_linkpath_override_on_regular_file_rejected():
    with pytest.raises(ValueError):
        inspect(make_tar(record(CAP, VALUE) + record(b"linkpath", b"target")))


def test_no_observations_are_returned_on_diffid_mismatch_or_truncation():
    data = make_tar(record(CAP, VALUE))
    with pytest.raises(ValueError):
        catalog.inspect_layer(io.BytesIO(data), "sha256:" + "0" * 64)
    with pytest.raises(ValueError):
        inspect(data[:1024])


def test_multiple_observations_keep_raw_headers_and_member_offsets_distinct():
    out = io.BytesIO()
    records = [
        record(b"path", b"first") + record(CAP, b"first\x00"),
        record(b"path", b"second") + record(CAP, b"second\xff"),
    ]
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for payload in records:
            extension = tarfile.TarInfo("pax")
            extension.type = tarfile.XHDTYPE
            extension.size = len(payload)
            archive.addfile(extension, io.BytesIO(payload))
            archive.addfile(tarfile.TarInfo("raw"))
    first, second = inspect(out.getvalue())
    assert (first.path, first.member_header_offset, first.pax_payload, first.value) == (
        "first",
        1024,
        records[0],
        b"first\x00",
    )
    assert (second.path, second.member_header_offset, second.pax_payload, second.value) == (
        "second",
        2560,
        records[1],
        b"second\xff",
    )


def test_raw_payload_and_observation_budgets_fail_closed(monkeypatch):
    data = make_tar(record(CAP, VALUE))
    monkeypatch.setattr(catalog, "MAX_TOTAL_PAX_BYTES", 1)
    with pytest.raises(ValueError, match="aggregate"):
        inspect(data)
    monkeypatch.setattr(catalog, "MAX_TOTAL_PAX_BYTES", 9999)
    monkeypatch.setattr(catalog, "MAX_OBSERVATIONS", 0)
    with pytest.raises(ValueError, match="aggregate"):
        inspect(data)


def test_no_host_capability_metadata_is_applied(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "setxattr", lambda *_args, **_kwargs: calls.append(True), raising=False)
    inspect(make_tar(record(CAP, VALUE)))
    assert calls == []


def test_pax_path_to_whiteout_cannot_carry_capability():
    with pytest.raises(ValueError):
        inspect(make_tar(record(b"path", b".wh.victim") + record(CAP, VALUE)))


def test_earlier_complete_observation_is_not_returned_on_bad_later_tar():
    data = make_tar(record(CAP, VALUE))
    corrupted = data[:-512] + b"X" * 512
    with pytest.raises(ValueError):
        inspect(corrupted)


def test_invalid_pax_path_encoding_does_not_leak_archive_bytes():
    data = make_tar(record(b"path", b"private-name-\xff") + record(CAP, VALUE))
    with pytest.raises(ValueError) as caught:
        inspect(data)
    assert "private-name" not in "".join(traceback.format_exception(caught.value))


def test_per_value_and_uncompressed_stream_limits_fail_closed(monkeypatch):
    data = make_tar(record(CAP, VALUE))
    monkeypatch.setattr(catalog, "MAX_VALUE_BYTES", len(VALUE) - 1)
    with pytest.raises(ValueError, match="limit"):
        inspect(data)
    monkeypatch.setattr(catalog, "MAX_VALUE_BYTES", len(VALUE))
    monkeypatch.setattr(catalog, "MAX_LAYER_BYTES", len(data) - 1)
    with pytest.raises(ValueError, match="limit"):
        inspect(data)


def test_no_capability_record_produces_no_metadata_observation():
    assert inspect(make_tar(record(b"path", b"effective"))) == ()
