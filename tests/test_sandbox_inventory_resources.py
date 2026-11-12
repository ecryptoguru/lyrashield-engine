"""Exercise scratch placement and process exhaustion in a real Linux subprocess."""

import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import acquire_sandbox_inventory as acquire
from scripts import check_go_sbom_coverage as go_inspector
from scripts import verify_sandbox_package_inventory as verifier


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux resource and procfs semantics")
class ResourceTests(unittest.TestCase):
    def test_outer_process_limits_are_enforced_by_kernel(self):
        code = (
            "import json,resource; "
            "from scripts.acquire_sandbox_inventory import apply_process_limits;"
            "apply_process_limits(); print(json.dumps([resource.getrlimit(resource.RLIMIT_AS),"
            "resource.getrlimit(resource.RLIMIT_CPU),resource.getrlimit(resource.RLIMIT_NOFILE)]))"
        )
        result = subprocess.run(  # noqa: S603 - fixed local resource-policy test module
            [sys.executable, "-c", code], check=True, capture_output=True, timeout=10
        )
        self.assertEqual(json.loads(result.stdout), [[4 * 1024**3] * 2, [1800] * 2, [256] * 2])

    def test_inspector_succeeds_when_separate_default_temp_filesystem_is_full(self):
        if os.environ.get("LYRA_TEST_FULL_TMP") != "/scratch":
            self.skipTest("requires dedicated small /scratch tmpfs")
        self.assertNotEqual(Path("/scratch").stat().st_dev, Path("/tmp").stat().st_dev)  # noqa: S108 - isolated container test
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            binary = root / "elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\0\x3e\0" + b"\0" * 16)
            tool = root / "go"
            tool.write_text(f"#!{sys.executable}\nprint('{{}}')\n")
            tool.chmod(0o700)
            with tempfile.TemporaryFile(dir="/scratch") as filled:
                hit_limit = False
                for _ in range(2048):
                    try:
                        os.write(filled.fileno(), b"x" * 1024)
                    except OSError as error:
                        self.assertEqual(error.errno, errno.ENOSPC)
                        hit_limit = True
                        break
                self.assertTrue(hit_limit, "test tmpfs was not bounded to 1 MiB")
                previous_environment = os.environ.get("TMPDIR")
                with patch.object(tempfile, "tempdir", "/scratch"):
                    result, _, _ = go_inspector.inspect_binary(
                        binary, tool, "amd64", scratch=scratch
                    )
                    with verifier.private_command_scratch(scratch):
                        output = verifier.bounded_command(
                            [sys.executable, "-c", "import os; print(os.environ['TMPDIR'])"],
                            1024,
                            5,
                        )
                    self.assertEqual(tempfile.tempdir, "/scratch")
                    self.assertEqual(os.environ.get("TMPDIR"), previous_environment)
                self.assertEqual(result, {})
                self.assertEqual(output.decode().strip(), str(scratch))

    def test_command_scratch_rejects_public_directory_and_restores_environment(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            scratch = Path(directory) / "public"
            scratch.mkdir(mode=0o755)
            scratch.chmod(0o755)
            before = os.environ.get("TMPDIR")
            with self.assertRaises(ValueError), verifier.private_command_scratch(scratch):
                pass
            self.assertEqual(os.environ.get("TMPDIR"), before)

    def test_verifier_cli_redacts_exceptions_with_untrusted_metadata(self):
        code = (
            "from scripts import verify_sandbox_package_inventory as v\n"
            "def fail():\n"
            "    raise ValueError('private-package-identity')\n"
            "v.main=fail\n"
            "v.run_cli()\n"
        )
        result = subprocess.run(  # noqa: S603 - fixed local redaction regression
            [sys.executable, "-c", code], check=False, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"Independent inventory verification failed.\n")
        self.assertNotIn(b"private-package-identity", result.stderr)

    def test_inspector_uses_checked_scratch_with_unusable_default_temp(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            bad_temp = (
                Path("/scratch/unavailable") if Path("/scratch").is_dir() else root / "missing"
            )
            binary = root / "elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\0\x3e\0" + b"\0" * 16)
            tool = root / "go"
            tool.write_text(
                f"#!{sys.executable}\n"
                "import json,os,sys\n"
                "fd=sys.argv[-1].rsplit('/',1)[-1]\n"
                "print(json.dumps({'snapshot':os.readlink('/proc/self/fd/'+fd),"
                "'output':os.readlink('/proc/self/fd/1'),'tmpdir':os.environ.get('TMPDIR')}))\n"
            )
            tool.chmod(0o700)
            with patch.object(tempfile, "tempdir", str(bad_temp)):
                result, _, _ = go_inspector.inspect_binary(binary, tool, "amd64", scratch=scratch)
            self.assertTrue(result["snapshot"].startswith(str(scratch) + "/"))
            self.assertTrue(result["output"].startswith(str(scratch) + "/"))
            self.assertEqual(result["tmpdir"], str(scratch))

    def test_go_inspector_fails_when_its_address_space_is_exhausted(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            binary = root / "elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\0\x3e\0" + b"\0" * 16)
            tool = root / "go"
            tool.write_text(f"#!{sys.executable}\nbytearray(256*1024*1024)\n")
            tool.chmod(0o700)
            with self.assertRaises(subprocess.CalledProcessError):
                go_inspector.inspect_binary(
                    binary, tool, "amd64", scratch=scratch, max_address_space=64 * 1024**2
                )

    def test_verifier_limits_address_space_cpu_fds_and_temp_location(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            output = root / "limits.json"
            code = (
                "import errno,json,os,resource,sys; f=[]; "
                "\ntry:\n while True: f.append(open('/dev/null'))\n"
                "except OSError as e: fd_error=e.errno\n"
                "try:\n bytearray(256*1024*1024)\n mem_error=False\n"
                "except MemoryError: mem_error=True\n"
                "json.dump({'as':resource.getrlimit(resource.RLIMIT_AS),"
                "'cpu':resource.getrlimit(resource.RLIMIT_CPU),"
                "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE),"
                "'fd_error':fd_error,'mem_error':mem_error,'tmpdir':os.environ['TMPDIR']},"
                "open(sys.argv[1],'w'))"
            )
            # Reserve one descriptor for the result after exhausting the FD limit.
            code = code.replace(
                "except OSError as e: fd_error=e.errno",
                "except OSError as e: fd_error=e.errno; f.pop().close()",
            )
            with (
                patch.object(acquire, "VERIFIER_ADDRESS_SPACE", 128 * 1024**2),
                patch.object(acquire, "VERIFIER_CPU_SECONDS", 10),
                patch.object(acquire, "VERIFIER_FDS", 32),
            ):
                acquire.run_verifier([sys.executable, "-c", code, str(output)], scratch)
            result = json.loads(output.read_text())
            self.assertEqual(result["as"], [128 * 1024**2] * 2)
            self.assertEqual(result["cpu"], [10, 10])
            self.assertEqual(result["nofile"], [32, 32])
            self.assertEqual(result["fd_error"], 24)  # EMFILE on Linux
            self.assertTrue(result["mem_error"])
            self.assertEqual(result["tmpdir"], str(scratch))

    def test_wall_deadline_reaps_child_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "pid"
            code = (
                "import os,pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(10)"
            )
            with (
                patch.object(acquire, "VERIFIER_WALL_SECONDS", 0.5),
                self.assertRaises(subprocess.TimeoutExpired),
            ):
                acquire.run_verifier([sys.executable, "-c", code, str(marker)], root)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)

    def test_cpu_exhaustion_terminates_verifier(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with (
                patch.object(acquire, "VERIFIER_CPU_SECONDS", 1),
                self.assertRaises(subprocess.CalledProcessError) as caught,
            ):
                acquire.run_verifier([sys.executable, "-c", "while True: pass"], Path(directory))
            self.assertLess(caught.exception.returncode, 0)


if __name__ == "__main__":
    unittest.main()
