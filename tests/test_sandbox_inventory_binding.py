"""Hosted inventory identity and executed-source binding regressions."""

import ast
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import bind_sandbox_inventory as binding


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.revision = "a" * 40
        self.tree = "b" * 40
        self.environment = {
            "GITHUB_REPOSITORY": "ecryptoguru/lyrashield-engine",
            "GITHUB_REPOSITORY_ID": "1297157605",
            "GITHUB_REPOSITORY_OWNER_ID": "116722580",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": "ecryptoguru/lyrashield-engine/"
            + binding.WORKFLOW
            + "@refs/heads/main",
            "GITHUB_SHA": self.revision,
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        self.receipt = {
            "schema": "lyrashield.sandbox.independent-package-inventory.v1",
            "status": "bounded_scope_matched",
            "releaseQualified": False,
            "limits": {"processingSeconds": 1800},
        }

    def git(self, _repository, *arguments):
        if arguments == ("rev-parse", "HEAD"):
            return (self.revision + "\n").encode()
        if arguments == ("rev-parse", self.revision + "^{tree}"):
            return (self.tree + "\n").encode()
        return b"committed source\n"

    def bind(self, environment=None, receipt=None):
        with (
            patch.object(binding, "git", side_effect=self.git),
            patch.object(binding, "read_regular", return_value=b"committed source\n"),
        ):
            return binding.bind(
                self.receipt if receipt is None else receipt,
                Path("/checked-out-source"),
                self.environment if environment is None else environment,
            )

    def test_exact_hosted_identity_and_resource_bounds_are_bound_without_upgrading(self):
        original = copy.deepcopy(self.receipt)
        result = self.bind()
        self.assertEqual(result["verifier"]["revision"], self.revision)
        self.assertEqual(result["verifier"]["tree"], self.tree)
        self.assertEqual(set(result["verifier"]["sourceFiles"]), set(binding.VERIFIER_FILES))
        self.assertTrue(
            all(value.startswith("sha256:") for value in result["verifier"]["sourceFiles"].values())
        )
        self.assertFalse(result["releaseQualified"])
        self.assertEqual(result["limits"]["verifierAddressSpaceBytes"], 4 * 1024**3)
        self.assertEqual(result["limits"]["helperAddressSpaceBytes"], 2 * 1024**3)
        self.assertEqual(self.receipt, original)

    def test_wrong_repository_owner_workflow_branch_revision_and_run_are_rejected(self):
        for key, value in (
            ("GITHUB_REPOSITORY", "fork/lyrashield-engine"),
            ("GITHUB_REPOSITORY_ID", "1"),
            ("GITHUB_REPOSITORY_OWNER_ID", "1"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_WORKFLOW_REF", "ecryptoguru/lyrashield-engine/other@refs/heads/main"),
            ("GITHUB_SHA", "c" * 40),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ATTEMPT", "1;echo forged"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.bind({**self.environment, key: value})

    def test_qualification_upgrade_rebinding_and_resource_substitution_are_rejected(self):
        for replacement in (
            {"releaseQualified": True},
            {"status": "qualified"},
            {"verifier": {}},
            {"limits": {"verifierAddressSpaceBytes": 999}},
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.bind(receipt={**self.receipt, **replacement})

    def test_dirty_executed_source_is_rejected(self):
        with (
            patch.object(binding, "git", side_effect=self.git),
            patch.object(binding, "read_regular", return_value=b"modified source\n"),
            self.assertRaisesRegex(ValueError, "source changed"),
        ):
            binding.bind(self.receipt, Path("/source"), self.environment)

    def test_executed_python_import_closure_is_fully_bound(self):
        repository = Path(__file__).resolve().parents[1]
        seen = set()

        def visit(source):
            if source in seen:
                return
            seen.add(source)
            for node in ast.walk(ast.parse((repository / source).read_text())):
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("scripts.")
                ):
                    visit(node.module.replace(".", "/") + ".py")

        visit("scripts/acquire_sandbox_inventory.py")
        visit("scripts/bind_sandbox_inventory.py")
        self.assertEqual(
            set(binding.VERIFIER_FILES),
            seen | {binding.WORKFLOW, "scripts/prepare_independent_inventory_tools.sh"},
        )

    @unittest.skipUnless(Path("/usr/bin/git").is_file(), "requires the fixed host git executable")
    def test_actual_checkout_can_be_bound_only_to_committed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_text("measured source\n")
            binding.git(root, "init", "--initial-branch=main")
            binding.git(root, "add", "input")
            binding.git(
                root,
                "-c",
                "user.name=Inventory test",
                "-c",
                "user.email=inventory@example.invalid",
                "commit",
                "-m",
                "bound source fixture",
            )
            revision = binding.git(root, "rev-parse", "HEAD").decode().strip()
            environment = {**self.environment, "GITHUB_SHA": revision}
            with patch.object(binding, "VERIFIER_FILES", ("input",)):
                result = binding.bind(self.receipt, root, environment)
                self.assertEqual(result["verifier"]["revision"], revision)
                (root / "input").write_text("changed after checkout\n")
                with self.assertRaisesRegex(ValueError, "source changed"):
                    binding.bind(self.receipt, root, environment)


if __name__ == "__main__":
    unittest.main()
