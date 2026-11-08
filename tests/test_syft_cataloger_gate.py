"""Regression gate for silent JavaScript package omission by Syft."""

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts/check_syft_cataloger.py"


def test_gate_rejects_successful_scan_that_omits_a_fixture(tmp_path):
    fake = tmp_path / "syft"
    names = [
        f"lyra-sbom-scalar-{field}-{kind}"
        for field in ("authors", "contributors", "maintainers")
        for kind in ("string", "object")
    ]
    result = {"packages": [{"name": name, "versionInfo": "1.2.3"} for name in names]}
    fake.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "arg = next(x for x in sys.argv if x.startswith('spdx-json='))\n"
        f"pathlib.Path(arg.split('=', 1)[1]).write_text({json.dumps(json.dumps(result))})\n"
    )
    fake.chmod(0o755)
    command = [sys.executable, str(SCRIPT), str(fake)]
    assert subprocess.run(command, capture_output=True, check=False).returncode == 0  # noqa: S603
    result["packages"].pop()
    fake.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "arg = next(x for x in sys.argv if x.startswith('spdx-json='))\n"
        f"pathlib.Path(arg.split('=', 1)[1]).write_text({json.dumps(json.dumps(result))})\n"
    )
    assert subprocess.run(command, capture_output=True, check=False).returncode != 0  # noqa: S603
