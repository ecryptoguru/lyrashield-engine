"""Synthetic tests for an unwired, aggregate-only PAX layer stream."""

import gzip
import hashlib
import io
import subprocess
import sys
import tarfile

import pytest

from scripts import diagnose_pax_capability_rejection as drain
from scripts import verify_pax_capability_stream as verify
from scripts.verify_oci_layer_binding import OCI_GZIP, OCI_TAR


def record(key, value):
    body = key + b"=" + value + b"\n"
    size = len(body) + 2
    while len(str(size)) + 1 + len(body) != size:
        size = len(str(size)) + 1 + len(body)
    return str(size).encode() + b" " + body


def layer(
    payload, *, kind=tarfile.REGTYPE, linkname="private-target", member_name="private-member-name"
):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        pax = tarfile.TarInfo("pax")
        pax.type = tarfile.XHDTYPE
        pax.size = len(payload)
        archive.addfile(pax, io.BytesIO(payload))
        member = tarfile.TarInfo(member_name)
        member.type = kind
        if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
            member.linkname = linkname
        archive.addfile(member)
    raw = output.getvalue()
    compressed = gzip.compress(raw)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    return compressed, descriptor, "sha256:" + hashlib.sha256(raw).hexdigest()


class Fetch:
    def __init__(self, data, status=0):
        self.stdout = io.BytesIO(data)
        self.status = status
        self.killed = False

    def poll(self):
        return self.status

    def wait(self, timeout=None):  # noqa: ARG002
        return self.status

    def kill(self):
        self.killed = True
        self.status = -9


@pytest.mark.parametrize(
    "payload, kind, linkname, role, syntax",
    [
        (record(b"path", b"/private"), tarfile.REGTYPE, "x", "member", "absolute"),
        (record(b"path", b"private\\x"), tarfile.REGTYPE, "x", "member", "backslash"),
        (record(b"linkpath", b"/private"), tarfile.LNKTYPE, "x", "hardlink", "absolute"),
        (record(b"linkpath", b"private\\x"), tarfile.LNKTYPE, "x", "hardlink", "backslash"),
        (
            record(b"SCHILY.xattr.security.capability", b"x"),
            tarfile.SYMTYPE,
            "private\\x",
            "symlink",
            "backslash",
        ),
    ],
    ids=[
        "member-absolute",
        "member-backslash",
        "hardlink-absolute",
        "hardlink-backslash",
        "symlink-backslash",
    ],
)
def test_verified_rejection_drain_role_and_syntax(
    private_root, payload, kind, linkname, role, syntax
):
    compressed, descriptor, diff = layer(payload, kind=kind, linkname=linkname)
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert result == {
        "scope": "verified-layer-bytes-rejected-parser-prefix-only",
        "status": "rejected",
        "reason": "unsafe-path",
        "role": role,
        "syntax": syntax,
        "bytesVerified": True,
        "tarFramingVerified": False,
        "finalImageVerified": False,
        "releaseQualified": False,
    }
    assert "private" not in str(result)
    assert not list(private_root.iterdir())


@pytest.mark.parametrize("failure", ["digest", "diffid", "truncated", "producer", "cleanup"])
def test_verified_rejection_drain_never_returns_reason_on_failure(private_root, failure):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError("PRIVATE-CLEANUP")

    compressed, descriptor, diff = layer(record(b"path", b"/private"))
    if failure == "digest":
        descriptor["digest"] = "sha256:" + "0" * 64
    if failure == "diffid":
        diff = "sha256:" + "0" * 64
    if failure == "truncated":
        compressed = compressed[:-5]
    fetch = (
        BadCleanup(compressed) if failure == "cleanup" else Fetch(compressed, failure == "producer")
    )
    with pytest.raises(ValueError) as caught:
        drain.diagnose_fetched_layer(fetch, descriptor, diff, private_root)
    assert "private" not in str(caught.value).lower()
    assert not hasattr(caught.value, "category")


def test_verified_rejection_drain_has_no_success_for_valid_or_other_rejection(private_root):
    for payload in [
        record(b"SCHILY.xattr.security.capability", b"x"),
        record(b"PRIVATE-KEY", b"x"),
    ]:
        compressed, descriptor, diff = layer(payload)
        with pytest.raises(ValueError, match="incomplete"):
            drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, private_root)


def test_verified_rejection_drain_does_not_claim_remaining_tar_framing(private_root):
    compressed, _, _ = layer(record(b"path", b"/private"))
    raw = gzip.decompress(compressed)[:-1] + b"x"
    compressed = gzip.compress(raw)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(raw).hexdigest()
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert result["status"] == "rejected"
    assert result["bytesVerified"] is True
    assert result["tarFramingVerified"] is False


def test_verified_rejection_drain_matches_member_before_hardlink_precedence(private_root):
    payload = record(b"path", b"/private") + record(b"linkpath", b"/target")
    compressed, descriptor, diff = layer(payload, kind=tarfile.LNKTYPE)
    result = drain.diagnose_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert result["role"] == "member"
    assert result["syntax"] == "absolute"


def test_verified_rejection_drain_accepts_short_reads(private_root):
    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 37))

    compressed, descriptor, diff = layer(record(b"path", b"/private"))
    fetch = Fetch(compressed)
    fetch.stdout = ShortReader(compressed)
    result = drain.diagnose_fetched_layer(fetch, descriptor, diff, private_root)
    assert result["bytesVerified"] is True
    assert fetch.stdout.closed


def test_verified_rejection_drain_honors_reserve_during_remaining_stream(private_root, monkeypatch):
    compressed, _, _ = layer(record(b"path", b"/private"))
    raw = gzip.decompress(compressed) + bytes(1024 * 1024)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    descriptor = {"mediaType": OCI_TAR, "digest": digest, "size": len(raw)}
    samples = iter([10 * 1024**3, 0])
    monkeypatch.setattr(drain, "free_space", lambda _fd: next(samples))
    with pytest.raises(ValueError, match="incomplete"):
        drain.diagnose_fetched_layer(Fetch(raw), descriptor, digest, private_root)


@pytest.fixture
def private_root(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(verify, "free_space", lambda _fd: 10 * 1024**3)
    monkeypatch.setattr(drain, "free_space", lambda _fd: 10 * 1024**3)
    return root


@pytest.mark.parametrize(
    "kind, expected", [(tarfile.REGTYPE, "file"), (tarfile.SYMTYPE, "symlink")]
)
def test_only_aggregate_counts_follow_verified_complete_stream(private_root, kind, expected):
    secret = b"PRIVATE-CAPABILITY-\x00\xff"
    compressed, descriptor, diff = layer(
        record(b"SCHILY.xattr.security.capability", secret), kind=kind
    )
    result = verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert result["capabilityHeaders"] == 1
    assert result["fileHeaders"] == (expected == "file")
    assert result["symlinkHeaders"] == (expected == "symlink")
    assert result["finalImageVerified"] is False and result["releaseQualified"] is False
    assert "PRIVATE" not in str(result) and "private-member" not in str(result)
    assert not list(private_root.iterdir())


@pytest.mark.parametrize("failure", ["descriptor", "diffid", "fetch", "truncated"])
def test_no_counts_on_any_verification_failure(private_root, failure):
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"private"))
    if failure == "descriptor":
        descriptor["digest"] = "sha256:" + "0" * 64
    if failure == "diffid":
        diff = "sha256:" + "0" * 64
    if failure == "truncated":
        compressed = compressed[:-5]
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(
            Fetch(compressed, 1 if failure == "fetch" else 0), descriptor, diff, private_root
        )


def test_unsupported_pax_stops_as_incomplete_without_exposing_content(private_root):
    compressed, descriptor, diff = layer(record(b"PRIVATE-KEY", b"PRIVATE-VALUE"))
    with pytest.raises(ValueError, match="incomplete") as caught:
        verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert "PRIVATE" not in str(caught.value)
    assert not list(private_root.iterdir())


def test_optional_prefix_reason_is_unverified_and_never_contains_archive_text(private_root):
    compressed, descriptor, diff = layer(record(b"PRIVATE-KEY", b"PRIVATE-VALUE"))
    # A wrong descriptor reinforces that the parser stops before byte authentication.
    descriptor["digest"] = "sha256:" + "0" * 64
    fetch = Fetch(compressed)
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(fetch, descriptor, diff, private_root, diagnostic=True)
    assert caught.value.category == "unsupported-pax-key"
    assert caught.value.byte_verified is False
    assert "PRIVATE" not in str(caught.value)
    assert fetch.stdout.closed
    assert not list(private_root.iterdir())


def test_cleanup_failure_suppresses_optional_prefix_reason(private_root):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError("PRIVATE-CLEANUP-CONTENT")

    compressed, descriptor, diff = layer(record(b"PRIVATE-KEY", b"PRIVATE-VALUE"))
    with pytest.raises(ValueError, match="cleanup incomplete") as caught:
        verify.inspect_fetched_layer(
            BadCleanup(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert not hasattr(caught.value, "category")
    assert "PRIVATE" not in str(caught.value)


def test_mutated_prefix_reason_cannot_expose_archive_text():
    error = verify.UnverifiedPrefixRejectionError("unsupported-pax-key")
    error._category = "PRIVATE-VALUE"
    assert error.category == "parser-rejected"
    assert error.byte_verified is False


@pytest.mark.parametrize(
    "payload, kind, linkname, reason, role",
    [
        (record(b"path", b"/private"), tarfile.REGTYPE, "x", "unsafe-path", "unknown"),
        (record(b"path", b"x" * 4097), tarfile.REGTYPE, "x", "path-length", "unknown"),
        (
            record(b"path", b"../private"),
            tarfile.REGTYPE,
            "x",
            "ambiguous-path-components",
            "member-or-hardlink",
        ),
        (record(b"path", b"private/"), tarfile.REGTYPE, "x", "member-trailing-slash", "member"),
        (record(b"linkpath", b"private"), tarfile.REGTYPE, "x", "linkpath-on-non-link", "member"),
        (
            record(b"linkpath", b"private/"),
            tarfile.LNKTYPE,
            "x",
            "hardlink-target-trailing-slash",
            "hardlink",
        ),
        (
            record(b"SCHILY.xattr.security.capability", b"x"),
            tarfile.SYMTYPE,
            "private\x01",
            "symlink-target-character",
            "symlink",
        ),
    ],
    ids=[
        "unsafe",
        "length",
        "components",
        "member-slash",
        "linkpath",
        "hardlink-slash",
        "symlink-control",
    ],
)
def test_member_link_fixed_detail_from_real_parser(
    private_root, payload, kind, linkname, reason, role
):
    compressed, descriptor, diff = layer(payload, kind=kind, linkname=linkname)
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == "member-link-policy"
    assert caught.value.member_link_reason == reason
    assert caught.value.member_link_role == role
    assert caught.value.byte_verified is False
    assert "private" not in str(caught.value)


def test_member_link_detail_mutation_fails_closed():
    error = verify.UnverifiedPrefixRejectionError("member-link-policy", "unsafe-path")
    error._member_link_reason = "PRIVATE-VALUE"
    assert error.member_link_reason == "unavailable"
    assert error.member_link_role == "unknown"
    error = verify.UnverifiedPrefixRejectionError("parser-rejected", "unsafe-path")
    assert error.member_link_reason == "unavailable"
    assert error.member_link_role == "unknown"


def test_member_link_encoding_reason_is_role_ambiguous(private_root):
    compressed, descriptor, diff = layer(
        record(b"SCHILY.xattr.security.capability", b"x"), member_name="private-\udcff"
    )
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == "member-link-policy"
    assert caught.value.member_link_reason == "member-or-link-encoding"
    assert caught.value.member_link_role == "unknown"
    assert caught.value.byte_verified is False


@pytest.mark.parametrize(
    "payload, category",
    [
        (record(b"path", b"../private"), "member-link-policy"),
        (record(b"path", b"private\x01value"), "pax-value-or-encoding"),
        (record(b"SCHILY.xattr.security.capability", b"x" * 4097), "parser-limit"),
    ],
    ids=["path-traversal", "pax-control", "oversized-capability"],
)
def test_new_prefix_categories_use_real_parser(private_root, payload, category):
    compressed, descriptor, diff = layer(payload)
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == category
    assert caught.value.byte_verified is False
    assert "private" not in str(caught.value)


def test_new_prefix_category_for_bad_tar_framing(private_root):
    compressed, _, _ = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    raw = gzip.decompress(compressed)[:-1] + b"x"
    compressed = gzip.compress(raw)
    descriptor = {
        "mediaType": OCI_GZIP,
        "digest": "sha256:" + hashlib.sha256(compressed).hexdigest(),
        "size": len(compressed),
    }
    diff = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == "tar-framing"
    assert caught.value.byte_verified is False


def test_unrecognized_parser_error_never_exposes_dynamic_data(private_root, monkeypatch):
    def reject(_self, _data):
        raise ValueError("PRIVATE-DYNAMIC-DETAIL")

    monkeypatch.setattr(verify.HeaderReader, "feed", reject)
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == "parser-rejected"
    assert caught.value.member_link_reason == "unavailable"
    assert caught.value.member_link_role == "unknown"
    assert caught.value.byte_verified is False
    assert "PRIVATE" not in str(caught.value)


def test_cleanup_failure_suppresses_new_prefix_category(private_root):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError("PRIVATE-CLEANUP")

    compressed, descriptor, diff = layer(record(b"path", b"../private"))
    with pytest.raises(ValueError, match="cleanup incomplete") as caught:
        verify.inspect_fetched_layer(
            BadCleanup(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert not hasattr(caught.value, "category")
    assert "PRIVATE" not in str(caught.value)


def test_forged_fetch_exception_never_becomes_a_parser_reason(private_root):
    class ForgedStream(io.BytesIO):
        def read(self, *_args):
            raise verify.UnverifiedPrefixRejectionError("unsupported-pax-key")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    fetch = Fetch(compressed)
    fetch.stdout = ForgedStream(compressed)
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(fetch, descriptor, diff, private_root, diagnostic=True)
    assert not hasattr(caught.value, "category")
    assert fetch.stdout.closed


def test_default_rejection_and_producer_failure_do_not_expose_prefix_reason(private_root):
    compressed, descriptor, diff = layer(record(b"PRIVATE-KEY", b"PRIVATE-VALUE"))
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)
    assert str(caught.value) == "capability stream incomplete"
    assert not hasattr(caught.value, "category")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed, 1), descriptor, diff, private_root, diagnostic=True
        )
    assert str(caught.value) == "capability stream incomplete"
    assert not hasattr(caught.value, "category")


def test_optional_prefix_reason_classifies_unsupported_member_without_path(private_root):
    compressed, descriptor, diff = layer(
        record(b"SCHILY.xattr.security.capability", b"private"), kind=tarfile.FIFOTYPE
    )
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert caught.value.category == "unsupported-tar-entry"
    assert caught.value.byte_verified is False
    assert "private" not in str(caught.value)


def test_optional_prefix_reason_is_not_given_for_digest_failure(private_root):
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    descriptor["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError) as caught:
        verify.inspect_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, diagnostic=True
        )
    assert str(caught.value) == "capability stream incomplete"
    assert not hasattr(caught.value, "category")


def test_space_reserve_is_checked_and_no_counts_are_returned(private_root, monkeypatch):
    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    monkeypatch.setattr(verify, "free_space", lambda _fd: 0)
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(Fetch(compressed), descriptor, diff, private_root)


def test_invalid_root_stops_owned_live_fetch_without_returning_counts(tmp_path):
    class LiveFetch(Fetch):
        def __init__(self):
            super().__init__(b"", status=None)

    fetch = LiveFetch()
    with pytest.raises(ValueError, match="incomplete"):
        verify.inspect_fetched_layer(fetch, {}, "bad", tmp_path / "missing")
    assert fetch.killed and fetch.stdout.closed


def test_no_counts_if_cleanup_fails_after_complete_stream(private_root):
    class BadCleanup(Fetch):
        def poll(self):
            raise RuntimeError("PRIVATE-CLEANUP-CONTENT")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    with pytest.raises(ValueError, match="cleanup incomplete") as caught:
        verify.inspect_fetched_layer(BadCleanup(compressed), descriptor, diff, private_root)
    assert "PRIVATE" not in str(caught.value)


def test_process_exiting_between_poll_and_kill_still_reaps_and_closes(private_root):
    class RaceFetch(Fetch):
        def poll(self):
            return None

        def kill(self):
            raise ProcessLookupError("already exited")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    fetch = RaceFetch(compressed)
    result = verify.inspect_fetched_layer(fetch, descriptor, diff, private_root)
    assert result["capabilityHeaders"] == 1 and fetch.stdout.closed


@pytest.mark.parametrize("failure", ["poll", "kill", "wait", "close"])
def test_all_cleanup_steps_are_attempted_when_one_fails(private_root, failure):
    class FaultFetch(Fetch):
        def __init__(self, data):
            super().__init__(data)
            self.attempts = []
            self.wait_calls = 0

        def poll(self):
            self.attempts.append("poll")
            if failure == "poll":
                raise RuntimeError("private")
            return None if failure == "kill" else 0

        def kill(self):
            self.attempts.append("kill")
            if failure == "kill":
                raise RuntimeError("private")

        def wait(self, timeout=None):  # noqa: ARG002 - matches subprocess protocol
            self.wait_calls += 1
            self.attempts.append("wait" if self.wait_calls > 1 else "verified-wait")
            if failure == "wait" and self.wait_calls > 1:
                raise RuntimeError("private")
            return 0

    class FaultStream(io.BytesIO):
        def close(self):
            fetch.attempts.append("close")
            super().close()
            if failure == "close":
                raise RuntimeError("private")

    compressed, descriptor, diff = layer(record(b"SCHILY.xattr.security.capability", b"x"))
    fetch = FaultFetch(compressed)
    fetch.stdout = FaultStream(compressed)
    with pytest.raises(ValueError, match="cleanup incomplete") as caught:
        verify.inspect_fetched_layer(fetch, descriptor, diff, private_root)
    assert "private" not in str(caught.value)
    assert "wait" in fetch.attempts and "close" in fetch.attempts
    if failure in {"poll", "kill"}:
        assert "kill" in fetch.attempts


def test_failed_kill_with_live_child_times_out_then_closes_stdout(private_root, monkeypatch):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], stdout=subprocess.PIPE
    )

    class KillFails:
        def __init__(self, process):
            self.process = process
            self.stdout = process.stdout

        def poll(self):
            return self.process.poll()

        def kill(self):
            raise PermissionError("synthetic kill failure")

        def wait(self, timeout=None):
            return self.process.wait(timeout=timeout)

    monkeypatch.setattr(verify, "FETCH_EXIT_SECONDS", 0.05)
    fetch = KillFails(child)
    try:
        with pytest.raises(ValueError, match="cleanup incomplete"):
            verify.inspect_fetched_layer(fetch, {}, "bad", private_root)
        assert child.poll() is None and fetch.stdout.closed
    finally:
        child.kill()
        child.wait(timeout=5)


def test_linux_literal_classifier_does_not_misattribute_symlink_target(private_root):
    compressed, descriptor, diff = layer(
        record(b"SCHILY.xattr.security.capability", b"x"),
        kind=tarfile.SYMTYPE,
        member_name="member\\literal",
        linkname="target\\rejected",
    )
    result = drain.diagnose_fetched_layer(
        Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
    )
    assert (result["role"], result["syntax"]) == ("symlink", "backslash")


def test_linux_literal_member_backslash_does_not_mask_absolute_hardlink_target(private_root):
    compressed, descriptor, diff = layer(
        record(b"path", b"member\\literal") + record(b"linkpath", b"/target"),
        kind=tarfile.LNKTYPE,
    )
    result = drain.diagnose_fetched_layer(
        Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
    )
    assert (result["role"], result["syntax"]) == ("hardlink", "absolute")


def test_linux_literal_backslash_alone_does_not_create_a_rejection(private_root):
    compressed, descriptor, diff = layer(record(b"path", b"member\\literal"))
    with pytest.raises(ValueError, match="incomplete"):
        drain.diagnose_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
        )


def test_diagnostic_rejects_nonboolean_literal_policy(private_root):
    compressed, descriptor, diff = layer(record(b"path", b"/private"))
    with pytest.raises(ValueError, match="incomplete"):
        drain.diagnose_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=1
        )


def test_linux_literal_classifier_selects_real_absolute_rejection_with_backslash(private_root):
    compressed, descriptor, diff = layer(record(b"path", b"/member\\literal"))
    result = drain.diagnose_fetched_layer(
        Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
    )
    assert (result["role"], result["syntax"]) == ("member", "absolute")


def test_linux_literal_classifier_pax_linkpath_rejects_symlink_target(private_root):
    payload = record(b"path", b"member\\literal") + record(b"linkpath", b"target\\rejected")
    compressed, descriptor, diff = layer(payload, kind=tarfile.SYMTYPE)
    result = drain.diagnose_fetched_layer(
        Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
    )
    assert (result["role"], result["syntax"]) == ("symlink", "backslash")


def test_linux_literal_rejection_reports_nothing_if_digest_mismatches(private_root):
    compressed, descriptor, diff = layer(
        record(b"path", b"member\\literal") + record(b"linkpath", b"/target"),
        kind=tarfile.LNKTYPE,
    )
    descriptor["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="incomplete") as caught:
        drain.diagnose_fetched_layer(
            Fetch(compressed), descriptor, diff, private_root, linux_literal_paths=True
        )
    assert "target" not in str(caught.value)
