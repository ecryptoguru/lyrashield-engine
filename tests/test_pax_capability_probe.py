"""Synthetic byte-exact, non-applying capability PAX probe checks."""

import hashlib
import io
import os
import tarfile

import pytest

from scripts import probe_pax_capability as probe


KEY = b"SCHILY.xattr.security.capability"
VALUE = b"\x00\xff\n=\x80bytes\x00"


def record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return str(length).encode() + b" " + body


def make_tar(payload, *, name="file", kind=tarfile.REGTYPE, add_member=True):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        extended = tarfile.TarInfo("pax")
        extended.type = tarfile.XHDTYPE
        extended.size = len(payload)
        archive.addfile(extended, io.BytesIO(payload))
        if add_member:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = 4
                archive.addfile(entry, io.BytesIO(b"data"))
            else:
                archive.addfile(entry)
    return output.getvalue()


def diff(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_byte_exact_capability_is_bound_to_immediately_following_file_without_applying(monkeypatch):
    data = make_tar(record(KEY, VALUE), name="private-file-name")
    applied = []
    monkeypatch.setattr(
        os, "setxattr", lambda *_args, **_kwargs: applied.append(True), raising=False
    )
    observations = probe.inspect_layer(io.BytesIO(data), diff(data))
    assert len(observations) == 1
    observation = observations[0]
    assert observation.path == "private-file-name"
    assert observation.member_header_offset == 1024
    assert observation.file_size == 4
    assert observation.value == VALUE
    assert "private-file-name" not in repr(observation) and "bytes" not in repr(observation)
    assert applied == []


@pytest.mark.parametrize(
    "payload",
    [
        record(KEY, b"a") + record(KEY, b"b"),
        record(KEY, b""),
        record(b"SCHILY.xattr.other", b"x"),
        record(b"path", b"elsewhere") + record(KEY, b"x"),
        b"bad-record",
    ],
)
def test_unknown_duplicate_empty_or_malformed_records_fail_closed(payload):
    data = make_tar(payload)
    with pytest.raises(ValueError):
        probe.inspect_layer(io.BytesIO(data), diff(data))


@pytest.mark.parametrize(
    "name,kind",
    [
        ("bad/../path", tarfile.REGTYPE),
        (".wh.old", tarfile.REGTYPE),
        ("dir", tarfile.DIRTYPE),
        ("link", tarfile.SYMTYPE),
    ],
)
def test_capability_only_binds_safe_regular_file(name, kind):
    data = make_tar(record(KEY, VALUE), name=name, kind=kind)
    with pytest.raises(ValueError):
        probe.inspect_layer(io.BytesIO(data), diff(data))


def test_digest_truncation_and_dangling_header_never_return_observations():
    data = make_tar(record(KEY, VALUE))
    for candidate, expected in (
        (data, "sha256:" + "0" * 64),
        (data[:1024], diff(data[:1024])),
        (make_tar(record(KEY, VALUE), add_member=False), None),
    ):
        with pytest.raises(ValueError):
            probe.inspect_layer(io.BytesIO(candidate), expected or diff(candidate))


def test_value_limit_fails_closed(monkeypatch):
    data = make_tar(record(KEY, VALUE))
    monkeypatch.setattr(probe, "MAX_VALUE_BYTES", len(VALUE) - 1)
    with pytest.raises(ValueError, match="limit"):
        probe.inspect_layer(io.BytesIO(data), diff(data))


def test_two_records_stay_bound_to_their_own_following_headers():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, value in [("a", b"first\x00"), ("b", b"second\xff")]:
            payload = record(KEY, value)
            extended = tarfile.TarInfo("pax")
            extended.type = tarfile.XHDTYPE
            extended.size = len(payload)
            archive.addfile(extended, io.BytesIO(payload))
            entry = tarfile.TarInfo(name)
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"data"))
    data = output.getvalue()
    observations = probe.inspect_layer(io.BytesIO(data), diff(data))
    assert [(o.path, o.member_header_offset, o.value) for o in observations] == [
        ("a", 1024, b"first\x00"),
        ("b", 3072, b"second\xff"),
    ]


def test_stacked_headers_and_duplicate_member_paths_reject():
    def build(*, stacked):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2):
                payload = record(KEY, VALUE)
                extended = tarfile.TarInfo("pax")
                extended.type = tarfile.XHDTYPE
                extended.size = len(payload)
                archive.addfile(extended, io.BytesIO(payload))
                if not stacked:
                    archive.addfile(tarfile.TarInfo("same"))
            if stacked:
                archive.addfile(tarfile.TarInfo("file"))
        return output.getvalue()

    for data in (build(stacked=True), build(stacked=False)):
        with pytest.raises(ValueError):
            probe.inspect_layer(io.BytesIO(data), diff(data))


def test_aggregate_value_and_observation_limits_fail_closed(monkeypatch):
    data = make_tar(record(KEY, VALUE))
    monkeypatch.setattr(probe, "MAX_TOTAL_VALUE_BYTES", len(VALUE) - 1)
    with pytest.raises(ValueError, match="aggregate limit"):
        probe.inspect_layer(io.BytesIO(data), diff(data))
    monkeypatch.setattr(probe, "MAX_TOTAL_VALUE_BYTES", len(VALUE) + 1)
    monkeypatch.setattr(probe, "MAX_OBSERVATIONS", 0)
    with pytest.raises(ValueError, match="aggregate limit"):
        probe.inspect_layer(io.BytesIO(data), diff(data))


def test_later_invalid_header_and_nonzero_trailer_never_return_observations():
    data = make_tar(record(KEY, VALUE))
    for candidate in (data[:2048] + b"X" * 512, data[:-512] + b"X" * 512):
        with pytest.raises(ValueError):
            probe.inspect_layer(io.BytesIO(candidate), diff(candidate))


@pytest.mark.parametrize("limit", ["MAX_ENTRIES", "MAX_PATH_BYTES", "MAX_LAYER_BYTES"])
def test_stream_and_path_budgets_fail_closed(monkeypatch, limit):
    data = make_tar(record(KEY, VALUE))
    monkeypatch.setattr(probe, limit, 0)
    with pytest.raises(ValueError):
        probe.inspect_layer(io.BytesIO(data), diff(data))


def test_invalid_record_error_omits_archive_content():
    secret = b"private-archive-value"
    data = make_tar(record(b"private-archive-key", secret), name="private-path")
    with pytest.raises(ValueError) as exc:
        probe.inspect_layer(io.BytesIO(data), diff(data))
    assert "private" not in str(exc.value)
