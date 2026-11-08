#!/usr/bin/env python3
"""Fail closed if Syft silently drops scalar package.json people fields."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_syft_cataloger.py /absolute/path/to/syft")
    syft = Path(sys.argv[1])
    if not syft.is_absolute() or not syft.is_file():
        raise SystemExit("Syft must be an absolute path to an existing binary")
    expected = set()
    with tempfile.TemporaryDirectory(prefix="lyra-syft-gate-") as temporary:
        root = Path(temporary)
        for field in ("authors", "contributors", "maintainers"):
            for kind in ("string", "object"):
                name = f"lyra-sbom-scalar-{field}-{kind}"
                expected.add((name, "1.2.3"))
                metadata = root / "node_modules" / name / "package.json"
                metadata.parent.mkdir(parents=True)
                metadata.write_text(
                    json.dumps(
                        {
                            "name": name,
                            "version": "1.2.3",
                            field: "Tester <test@example.invalid>"
                            if kind == "string"
                            else {"name": "Tester"},
                        }
                    ),
                    encoding="utf-8",
                )
        output = root / "scan.spdx.json"
        subprocess.run(  # noqa: S603 - caller supplies the checksum-verified Syft binary
            [
                str(syft),
                "scan",
                str(root),
                "--override-default-catalogers",
                "javascript-package-cataloger",
                "-o",
                f"spdx-json={output}",
            ],
            check=True,
            timeout=60,
            env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )
        document = json.loads(output.read_bytes())
        packages = document.get("packages")
        if not isinstance(packages, list):
            raise TypeError("Syft output has no SPDX packages")
        found = {(p.get("name"), p.get("versionInfo")) for p in packages if isinstance(p, dict)}
        missing = sorted(expected - found)
        if missing:
            raise ValueError(f"Syft omitted JavaScript regression fixtures: {missing}")


if __name__ == "__main__":
    main()
