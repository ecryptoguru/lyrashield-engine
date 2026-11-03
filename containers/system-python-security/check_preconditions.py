#!/usr/bin/python3
"""Exercise production preflight and rollback against exact qualified inputs.

Run after leaf installation and before amendment. All experiments use temporary,
inert copies; only original-file ownership checks are omitted for those copies.
The normal source and seed hashes, wheel RECORD and output contracts still apply.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import safe_io
from amend_sources import HERE, amend, sha


MANIFEST = json.loads((HERE / "amendments.json").read_text())
WHEEL = Path(sys.argv.pop(1)).read_bytes()


class PreconditionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="system-python-preflight-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        names = {p["path"] for p in MANIFEST["patches"]}
        names.update("usr/lib/python3/dist-packages/" + n for n in MANIFEST["pip"]["files"])
        names.update(MANIFEST["pip"][n] for n in ("seed_path", "setuptools_seed_path"))
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile("/" + name, path)
        self.before = {n: sha((self.root / n).read_bytes()) for n in names}
        self.target = self.root / MANIFEST["patches"][0]["path"]
        self.receipt = self.root / "usr/share/lyrashield/security/system-python-amendments.json"

    def assert_original(self):
        self.assertEqual({n: sha((self.root / n).read_bytes()) for n in self.before}, self.before)
        self.assertFalse(self.receipt.exists())

    def test_late_seed_tamper_before_write(self):
        seed = self.root / MANIFEST["pip"]["setuptools_seed_path"]
        seed.write_bytes(seed.read_bytes() + b"tamper fixture")
        untouched = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, "seed"):
            amend(self.root, WHEEL, check_owners=False)
        self.assertEqual(self.target.read_bytes(), untouched)
        self.assertFalse(self.receipt.exists())

    def test_source_symlink_never_modifies_internal_or_external_bytes(self):
        external = self.base / "outside.py"
        external.write_bytes(self.target.read_bytes())
        self.target.unlink()
        self.target.symlink_to(external)
        with self.assertRaises((ValueError, OSError)):
            amend(self.root, WHEEL, check_owners=False)
        self.assert_original()
        self.assertEqual(
            sha(external.read_bytes()), self.before[str(self.target.relative_to(self.root))]
        )

    def test_linked_receipt_never_modifies_external_bytes(self):
        self.receipt.parent.mkdir(parents=True)
        external = self.base / "outside.json"
        external.write_bytes(b"receipt sentinel")
        self.receipt.symlink_to(external)
        with self.assertRaises((ValueError, OSError)):
            amend(self.root, WHEEL, check_owners=False)
        self.assertEqual({n: sha((self.root / n).read_bytes()) for n in self.before}, self.before)
        self.assertEqual(external.read_bytes(), b"receipt sentinel")

    def test_late_bad_receipt_parent_is_safe_and_retryable(self):
        bad = self.root / "usr/share/lyrashield"
        bad.write_bytes(b"not a directory")
        with self.assertRaises(OSError):
            amend(self.root, WHEEL, check_owners=False)
        self.assert_original()
        bad.unlink()
        amend(self.root, WHEEL, check_owners=False)
        self.assertTrue(self.receipt.is_file())

    def test_mid_write_failure_rolls_back_and_retry_succeeds(self):
        replace = safe_io.os.replace
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected publication failure")
            return replace(*args, **kwargs)

        with (
            patch.object(safe_io.os, "replace", fail_second),
            self.assertRaisesRegex(OSError, "injected"),
        ):
            amend(self.root, WHEEL, check_owners=False)
        self.assert_original()
        self.assertFalse(list(self.root.rglob(".lyrashield-*")))
        amend(self.root, WHEEL, check_owners=False)
        self.assertTrue(self.receipt.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
