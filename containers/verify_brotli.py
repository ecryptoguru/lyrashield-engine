"""Verify the installed fixed Brotli decoder and execute a real decode."""

# ruff: noqa: INP001
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path


def main() -> None:
    versions = {}
    for name in ("libbrotli1", "python3-brotli"):
        for field in ("Version", "source:Version"):
            version = subprocess.check_output(  # noqa: S603 - fixed package and field choices
                ["/usr/bin/dpkg-query", "-W", f"-f=${{{field}}}", name], text=True
            ).strip()
            subprocess.run(  # noqa: S603 - fixed Debian version comparison
                ["/usr/bin/dpkg", "--compare-versions", version, "ge", "1.2.0-4.1"], check=True
            )
            versions[f"{name}:{field}"] = version
    architecture = subprocess.check_output(
        ["/usr/bin/dpkg", "--print-architecture"], text=True
    ).strip()
    reviewed = {
        "amd64": (
            "x86_64-linux-gnu",
            "9e3475c0183fcca66b495e3d9036774c7ba569e2b9bbe579f263d9d4972e386a",
            "7938f62f22d8b31e7da4ab313e9a5fa8365f8f6bbf8297efb440f89a5934213b",
        ),
        "arm64": (
            "aarch64-linux-gnu",
            "35c99321b037c8999d0d28293e35c176816c9bcf8730894f64fe12723d0d581e",
            "abe6cf5d3e8af2a5328ac004a5d762968441f407fc2116060aa41828d2c1c15b",
        ),
    }
    triplet, shared_sha256, extension_sha256 = reviewed[architecture]
    library = Path(f"/usr/lib/{triplet}/libbrotlidec.so.1.2.0")
    assert hashlib.sha256(library.read_bytes()).hexdigest() == shared_sha256
    decoder = ctypes.CDLL(str(library))
    decoder.BrotliDecoderVersion.restype = ctypes.c_uint32
    assert decoder.BrotliDecoderVersion() >= 0x1002000
    encoded = b"\x0b\x02\x80hello\x03"
    output_size = ctypes.c_size_t(16)
    output = ctypes.create_string_buffer(16)
    status = decoder.BrotliDecoderDecompress(
        len(encoded), encoded, ctypes.byref(output_size), output
    )
    assert status == 1
    assert output.raw[: output_size.value] == b"hello"
    # This must use the system interpreter: its statically linked extension is
    # independent of the shared library loaded through ctypes above.
    extension = subprocess.check_output(
        [
            "/usr/bin/python3",
            "-c",
            "import brotli,_brotli,json,hashlib; "
            "assert brotli.decompress(bytes.fromhex('0b028068656c6c6f03')) == b'hello'; "
            "print(json.dumps({'version':brotli.__version__,'file':_brotli.__file__,"
            "'sha256':hashlib.sha256(open(_brotli.__file__,'rb').read()).hexdigest()}))",
        ],
        text=True,
    )
    extension_info = json.loads(extension)
    assert extension_info["sha256"] == extension_sha256
    assert importlib.util.find_spec("brotli") is None, (
        "review newly installed application Brotli separately"
    )
    print(  # noqa: T201 - JSON smoke receipt
        json.dumps(
            {
                "packages": versions,
                "ctypes_real_decode": "pass",
                "shared_library_sha256": shared_sha256,
                "system_python_real_decode": extension_info,
                "application_python_brotli": "not installed in isolated application venv",
            }
        )
    )


if __name__ == "__main__":
    main()
