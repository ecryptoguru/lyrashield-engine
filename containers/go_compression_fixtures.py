"""Independent C-encoded compressed fixtures for the Go archive decoders."""

# ruff: noqa: INP001
from __future__ import annotations

import base64
import ctypes
import lzma


TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def payload() -> bytes:
    return (
        "compressed fixture for an independently encoded decoder regression\n"
        + "".join(
            f"padding {i:04d}: alpha beta gamma delta epsilon theta repeated safe fixture text\n"
            for i in range(256)
        )
        + (f'github_token="{TOKEN}"\n' * 16)
    ).encode()


# Encoded by libzstd (C, level 1) and liblzma (preset 9), independently
# of the patched Go codecs. The source payload is deterministic and harmless.
ZSTD = base64.b64decode(
    "KLUv/WDDUKUOAGbcRyAwbWs4tFK7/zfMhgFanCU1KV6KNlxLtntLwFQEBXGpHFMAQwAiAI55EuWBNIs8cD5kPBAC"
    "AjYOnFJxoGN5wCOAEEKnkSAxwgUgUZCmkUxDMoeRUVnIeKKMyiKRZ+IxExkTuciYICeBh1EYRzIRUwJhnCibRjIL"
    "hLIIS6WO3HONLZU6as81tlTqiD3X2FKpo/VcY0uljtRzjS2VOkrPNbZU6qjPNbZU6ujnGlsq9Skhp2TA5kQ5oVwk"
    "c+CUAf////////////////////////////////9zjS2VOnrPNRYBjmkMbFkLKkkKfZyAHB6Cc7QDxlgGKqaCKiZo"
    "WByNgIFEPiizQRHhmEijbdu2bdu2bdu2bdu2bdu2bdu2bdv2gQKoEcAv7P8xBuFrtBsSWEEgQeD/f/3NZ3QPpaqq"
    "qqpVlSpV1aqqqqpKVauqqlKtqqqqlKqqqipVVVVVSquqqqpSVVWlqlRVVVU1VVWqqkpVVVVVqVJVVa1UVVVVFVVV"
    "VVWlqqqqqlJVVVVVke45qqqqKg00VbVWVZWaqqqrqkpNVdWqqlInVdWqqlJTVbUqVampqlqrqtRUpVpVVWqqqlZV"
    "JTW1qlZV9TJSpE7/AQ9Qqw=="
)

XZ = base64.b64decode(
    "/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM4FHCAVxdADGbyfP2vI7Fzh1Xui+7+oi2rS1fwBwthW1lvBj2qCPks1Rn"
    "LLaMtF9VmKKsPY8GvLu3Y4j68Vo798yXFDbzoZxser2wqC5swN6doKxPvHF4ljsTzGh6hj4uVeK7pY3J3DDflF8Q"
    "ZToKIwm4i7HuVq0Th/PS6E1rEXog8Bt0+YhWgV2c/3DDsE7iNs7DDdvLkpmLVYH3dmQa9N/3McN4zbG+t64UFRVn"
    "skt8xfjuWjyMw/B7umd9k1LUILRZYydGFd+sOet2ag4icZdy5G1FgGz7N+OULroViRx9Q94i0w4qYke9HlDZ9jCT"
    "dTgl2oGBvUckh7DUvnYb8rUz1ZR/d2NDud0RaRncbjekCS+DyCxnaU0/h69jkSyJ7ROiXC1G1GtX++eDxtCYCT5s"
    "SzLUsboKsejjrVZejJ7zsH87pqE2NFYBlh08xJ2rjBgpbuTbqqh/0zVHkRTkMToAAACbKygImQDuEAAB+ALDowEA"
    "WY+J5rHEZ/sCAAAAAARZWg=="
)


def verified_fixtures() -> dict[str, bytes]:
    expected = payload()
    for encoded in (ZSTD, XZ):
        if TOKEN.encode() in encoded:
            raise ValueError("stored secret would bypass the compressed-block regression")
    if lzma.decompress(XZ) != expected:
        raise ValueError("independent XZ decode differs")
    decoder = ctypes.CDLL("libzstd.so.1")
    decoder.ZSTD_decompress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    decoder.ZSTD_decompress.restype = ctypes.c_size_t
    decoder.ZSTD_isError.argtypes = [ctypes.c_size_t]
    decoder.ZSTD_isError.restype = ctypes.c_uint
    output = ctypes.create_string_buffer(len(expected))
    size = decoder.ZSTD_decompress(output, len(output), ZSTD, len(ZSTD))
    if decoder.ZSTD_isError(size) or size != len(expected) or output.raw[:size] != expected:
        raise ValueError("independent Zstandard decode differs")
    return {".zst": ZSTD, ".xz": XZ}
