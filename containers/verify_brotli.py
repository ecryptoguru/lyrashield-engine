"""Verify the installed fixed Brotli decoder and execute a real decode."""

# ruff: noqa: INP001
from __future__ import annotations

import ctypes
import subprocess


def main() -> None:
    package_version = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "libbrotli1"], text=True
    ).strip()
    subprocess.run(  # noqa: S603 - fixed Debian version comparison
        ["/usr/bin/dpkg", "--compare-versions", package_version, "ge", "1.2.0-4.1"], check=True
    )
    decoder = ctypes.CDLL("libbrotlidec.so.1")
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
    print(f"Brotli fixed decoder {package_version}: real decode passed")  # noqa: T201


if __name__ == "__main__":
    main()
