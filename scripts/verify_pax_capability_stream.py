"""Unwired aggregate-only streamed PAX capability header observation."""

# ruff: noqa: INP001, BLE001, TRY301  # Sanitize all failures before returning data.
import os
import stat
import time

from scripts.catalog_pax_capability_headers import MAX_LAYER_BYTES, MAX_SECONDS, HeaderReader
from scripts.spool_verified_oci_layer import free_space, require_no_acl
from scripts.verify_oci_layer_binding import verify_layer_stream


MAX_COMPRESSED_BYTES = 4 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
FETCH_EXIT_SECONDS = 10


def inspect_fetched_layer(fetch, item, diff_id, private_root):
    """Return only aggregate counts after complete same-stream verification.

    The caller must authenticate the descriptor and DiffID and supervise the
    fetch process group with an external deadline. This is not a final image,
    inode, OCI runtime, capability validity, SBOM or release qualification.
    No input bytes or metadata are written, extracted or applied.
    """
    root = None
    try:
        root = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        state = os.fstat(root)
        if (
            not stat.S_ISDIR(state.st_mode)
            or state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) != 0o700
        ):
            raise ValueError("private root invalid")
        require_no_acl(root)
        if (
            not isinstance(item, dict)
            or type(item.get("size")) is not int
            or not 0 < item["size"] <= MAX_COMPRESSED_BYTES
        ):
            raise ValueError("compressed byte limit exceeded")
        reader = HeaderReader()
        deadline = time.monotonic() + MAX_SECONDS
        count = 0

        def consume(data):
            nonlocal count
            if time.monotonic() > deadline:
                raise TimeoutError("stream deadline exceeded")
            if free_space(root) < MIN_FREE_BYTES + 1024 * 1024:
                raise ValueError("temporary storage reserve insufficient")
            count += len(data)
            if count > MAX_LAYER_BYTES:
                raise ValueError("uncompressed byte limit exceeded")
            reader.feed(data)

        descriptor, size = verify_layer_stream(fetch.stdout, item, diff_id, 0, on_data=consume)
        reader.complete()
        if fetch.wait(timeout=FETCH_EXIT_SECONDS) != 0:
            raise ValueError("fetch process failed")
        if count != size:
            raise ValueError("stream byte count mismatch")
        files = sum(observation.kind == "file" for observation in reader.observations)
        links = sum(observation.kind == "symlink" for observation in reader.observations)
        if files + links != len(reader.observations):
            raise ValueError("unsupported observation kind")
        return {
            "scope": "verified-single-layer-pax-header-aggregate-only",
            "descriptorDigest": descriptor["digest"],
            "compressedBytes": descriptor["size"],
            "diffId": diff_id,
            "uncompressedBytes": size,
            "capabilityHeaders": files + links,
            "fileHeaders": files,
            "symlinkHeaders": links,
            "sourceRetained": False,
            "finalImageVerified": False,
            "releaseQualified": False,
        }
    except Exception:
        raise ValueError("capability stream incomplete") from None
    finally:
        try:
            if fetch.poll() is None:
                fetch.kill()
            fetch.wait()
            if fetch.stdout is not None:
                fetch.stdout.close()
        except Exception:
            raise ValueError("capability stream cleanup incomplete") from None
        finally:
            if root is not None:
                os.close(root)
