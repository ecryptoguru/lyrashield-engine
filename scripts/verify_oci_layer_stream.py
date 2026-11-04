#!/usr/bin/env python3
"""Verify one caller-anchored layer stream; not image or release qualification."""

import argparse
import json
import re
import signal
import sys
import zlib

from verify_oci_layer_binding import MAX_SECONDS, timeout, verify_layer_stream


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--size", required=True)
    parser.add_argument("--diff-id", required=True)
    parser.add_argument("--media-type", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]{0,10}", args.size):
        raise ValueError("invalid descriptor size")
    descriptor = {"digest": args.digest, "size": int(args.size), "mediaType": args.media_type}
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(MAX_SECONDS)
    result, uncompressed_size = verify_layer_stream(sys.stdin.buffer, descriptor, args.diff_id, 0)
    signal.alarm(0)
    result["scope"] = "single_layer_integrity_only"
    result["uncompressedSize"] = uncompressed_size
    print(json.dumps(result, sort_keys=True))  # noqa: T201 - machine-readable report


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, zlib.error, TimeoutError) as exc:
        print(f"layer stream verification failed: {exc}", file=sys.stderr)  # noqa: T201
        sys.exit(1)
