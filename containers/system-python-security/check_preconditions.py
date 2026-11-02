#!/usr/bin/python3
"""Prove a late seed mismatch rejects the entire amendment before any write.

Run after signed leaf installation, before amend_sources.py, in an ephemeral
qualified baseline. The fixture copies only the amendment's declared inputs.
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from amend_sources import HERE, amend


manifest = json.loads((HERE / "amendments.json").read_text())
with tempfile.TemporaryDirectory(prefix="system-python-negative-") as tmp:
    root = Path(tmp)
    names = {p["path"] for p in manifest["patches"]}
    names.update("usr/lib/python3/dist-packages/" + n for n in manifest["pip"]["files"])
    names.update(manifest["pip"][n] for n in ("seed_path", "setuptools_seed_path"))
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile("/" + name, path)
    sentinel = root / manifest["patches"][0]["path"]
    before = sentinel.read_bytes()
    late_input = root / manifest["pip"]["setuptools_seed_path"]
    late_input.write_bytes(late_input.read_bytes() + b"tamper fixture")
    try:
        amend(root, Path(sys.argv[1]).read_bytes(), check_owners=False)
    except ValueError as error:
        assert "seed" in str(error), str(error)
    else:
        raise AssertionError("tampered input accepted")
    assert sentinel.read_bytes() == before, "an early source was mutated before late validation"
    assert not (root / "usr/share/lyrashield/security/system-python-amendments.json").exists()
print("late-seed tamper rejected before any source mutation")  # noqa: T201
