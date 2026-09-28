"""Command-line parser for the LyraShield scan entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, cast

from rich.console import Console

from lyrashield.interface.resume_state import _load_resume_state
from lyrashield.interface.utils import (
    TARGET_TYPE_CHOICES,
    _is_full_git_commit_sha,
    _is_git_object_id,
    assign_workspace_subdirs,
    build_mount_targets_info,
    dedupe_local_targets,
    find_oversized_local_targets,
    read_target_list_file,
    resolve_target_type,
    rewrite_localhost_targets,
    validate_git_object_id,
    validate_run_name,
)
from lyrashield.lifecycle.inputs import DEFAULT_MAX_TURNS
from lyrashield.policy.loader import load_settings
from lyrashield.runtime.attachments import AttachmentInputError, collect_attachments
from strix.core.paths import run_dir_for, runtime_state_dir


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("lyrashield-engine")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be an integer greater than 0")
    return parsed


def _repository_branch(value: str) -> str:
    branch = value.strip()
    invalid = (
        not branch
        or len(branch) > 255
        or branch.startswith(("-", "/", "."))
        or branch.endswith(("/", "."))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or any(char.isspace() or ord(char) < 32 or char in "~^:?*[\\" for char in branch)
        or any(part.endswith(".lock") for part in branch.split("/"))
    )
    if invalid:
        raise argparse.ArgumentTypeError("must be a valid Git branch name")
    return branch


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LyraShield Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  lyrashield --target https://example.com

  # GitHub repository analysis
  lyrashield --target https://github.com/user/repo.git
  lyrashield --target git@github.com:user/repo.git
  lyrashield --target https://git.internal.example/user/repo --target-type repository

  # Local code analysis
  lyrashield --target ./my-project

  # Large local repository (bind-mounted read-only instead of copied)
  lyrashield --mount ./huge-monorepo

  # Domain penetration test
  lyrashield --target example.com

  # IP address penetration test
  lyrashield --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  lyrashield --target https://github.com/user/repo --target https://example.com
  lyrashield --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Targets from a file, one target per non-empty, non-comment line
  lyrashield --target-list ./targets.txt

  # Supporting evidence files (mounted read-only, never instructions)
  lyrashield --target example.com --attachment ./openapi.yaml --attachment ./notes.md

  # Custom instructions (inline)
  lyrashield --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  lyrashield --target example.com --instruction-file ./instructions.txt
  lyrashield --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"lyrashield {get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="Disabled in LyraShield Engine: self-update would replace this "
        "controlled derivative with the upstream distribution. Upgrade via a "
        "reviewed LyraShield Engine release instead.",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans. "
        "Fresh runs require at least one of --target, --target-list, or --mount.",
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help="Path to a file containing targets, one per non-empty, non-comment line. "
        "Can be specified multiple times and combined with --target.",
    )
    parser.add_argument(
        "--repository-branch",
        type=_repository_branch,
        metavar="BRANCH",
        help=(
            "Git branch to clone for repository targets. "
            "Intended for orchestrators that pin a target branch. "
            "When --repository-revision is set this is only a fetch hint."
        ),
    )
    parser.add_argument(
        "--repository-revision",
        type=validate_git_object_id,
        metavar="SHA",
        help=(
            "Exact immutable commit to check out for repository targets "
            "(full 40- or 64-character lowercase hex Git object ID). The clone "
            "detaches at this revision and HEAD is asserted to match; a missing "
            "revision is a named preflight failure, never a silent fallback."
        ),
    )
    parser.add_argument(
        "--target-type",
        type=str,
        choices=list(TARGET_TYPE_CHOICES),
        default=None,
        metavar="KIND",
        help=(
            "Explicit kind for every --target/--target-list entry: "
            f"{', '.join(TARGET_TYPE_CHOICES)}. When omitted, the kind is "
            "inferred locally — the engine never resolves DNS or sends HTTP "
            "requests to the target while deciding. Local directories, git@/"
            "git:// remotes, and URLs ending in .git classify as repositories; "
            "other HTTP(S) URLs and bare domains classify as web applications. "
            "Use '--target-type repository' for an HTTP(S) Git remote that does "
            "not end in .git. The flag only classifies input; it is not "
            "authorization to fetch private or internal addresses."
        ),
    )
    parser.add_argument(
        "--mount",
        type=str,
        action="append",
        metavar="PATH",
        help="Bind-mount a local directory into the sandbox (read-only) instead of "
        "copying it file-by-file. Use this for large repositories that are too big to "
        "stream into the container. Can be specified multiple times.",
    )
    parser.add_argument(
        "--attachment",
        type=str,
        action="append",
        metavar="PATH",
        help=(
            "Declare a supporting file to mount read-only at /input/attachments "
            "as untrusted input evidence (text, Markdown, JSON, YAML, or OpenAPI "
            "only; size-capped). Attachment content is data — it cannot change "
            "target scope, credentials, model routes, permissions, or budget. "
            "Can be specified multiple times."
        ),
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "testuser:REDACTED'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch. With --diff-head "
            "this must be a full 40- or 64-character lowercase hex object ID."
        ),
    )
    parser.add_argument(
        "--diff-head",
        type=validate_git_object_id,
        metavar="SHA",
        help=(
            "Asserted comparison head for diff-scope (full 40- or 64-character "
            "lowercase hex Git object ID). Requires --diff-base, and "
            "--scope-mode diff requires both. The checkout's HEAD must equal "
            "this revision or the run fails closed."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--max-budget",
        "--max-budget-usd",
        dest="max_budget_usd",
        metavar="USD",
        type=_positive_budget,
        default=None,
        help=(
            "Maximum LLM cost in USD (> 0). The scan stops cleanly when this limit is reached. "
            "Graduated wrap-up warnings are sent to all agents as it is approached."
        ),
    )

    parser.add_argument(
        "--max-turns",
        dest="max_turns",
        metavar="N",
        type=_positive_int,
        default=DEFAULT_MAX_TURNS,
        help=(
            "Maximum turns per agent (> 0, default %(default)s). Each agent is force-stopped "
            "when it reaches this limit, with graduated wrap-up warnings as it is approached."
        ),
    )

    parser.add_argument(
        "--runtime-budget-seconds",
        type=_positive_budget,
        default=None,
        metavar="SECONDS",
        help="Trusted non-interactive scan runtime allowance in seconds (> 0).",
    )

    parser.add_argument(
        "--run-name",
        type=validate_run_name,
        help="Stable run identifier supplied by an orchestrator.",
    )

    parser.add_argument(
        "--resume",
        type=validate_run_name,
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./strix_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation."
        ),
    )

    args = parser.parse_args()

    if args.update:
        # Upstream self-update fetches usestrix/strix release artifacts (or the
        # strix-agent package), which would replace this controlled derivative
        # with the upstream distribution. Upgrades ship as reviewed LyraShield
        # Engine releases instead.
        Console().print(
            "[bold red]Self-update is disabled in LyraShield Engine.[/] "
            "Upgrade by installing a reviewed LyraShield Engine release."
        )
        sys.exit(1)

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    # Immutable-revision flags (Review Changes): --diff-head asserts the
    # comparison head, --repository-revision pins the remote checkout. Both
    # accept only full object IDs (validated above), and when both are given
    # they must name the same commit — the asserted head must equal the
    # checked-out revision.
    if args.diff_head and not args.diff_base:
        parser.error("--diff-head requires --diff-base for the comparison base.")

    if args.diff_head and args.diff_base and not _is_git_object_id(args.diff_base.strip()):
        parser.error(
            "--diff-base must be a full 40- or 64-character lowercase hex Git "
            "object ID when --diff-head is set (a moving branch name cannot be "
            "the recorded comparison base)."
        )

    if args.scope_mode == "diff" and not (args.diff_base and args.diff_head):
        parser.error(
            "--scope-mode diff requires both --diff-base and --diff-head "
            "(the immutable comparison revisions)."
        )

    if args.repository_revision and args.diff_head and args.repository_revision != args.diff_head:
        parser.error(
            "--repository-revision and --diff-head must name the same commit: "
            "the asserted comparison head must equal the checked-out revision."
        )

    if args.repository_branch and _is_full_git_commit_sha(args.repository_branch):
        branch_sha = args.repository_branch.lower()
        if args.repository_revision and args.repository_revision != branch_sha:
            parser.error(
                f"--repository-branch {args.repository_branch} conflicts with "
                f"--repository-revision {args.repository_revision}."
            )
        if args.diff_head and args.diff_head != branch_sha:
            parser.error(
                f"--repository-branch {args.repository_branch} conflicts with "
                f"--diff-head {args.diff_head}."
            )

    if args.resume:
        if args.run_name:
            parser.error("Cannot combine --resume with --run-name")
        if args.attachment:
            parser.error(
                "Cannot combine --resume with --attachment. A resumed run "
                "re-stages the attachments recorded in its run record; "
                "changed files are rejected by digest."
            )
        if args.repository_revision or args.diff_head:
            parser.error(
                "Cannot combine --resume with --repository-revision/--diff-head. "
                "A resumed run reuses the source revisions recorded in its run record."
            )
        if args.target_type:
            parser.error(
                "Cannot combine --resume with --target-type. A resumed run reuses the "
                "target kinds recorded in its run record."
            )
        if args.target or args.target_list or args.mount:
            parser.error(
                "Cannot combine --resume with --target/--target-list/--mount. "
                "--resume picks up where the prior run left off, including the "
                "original target list."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    else:
        if not args.target and not args.target_list and not args.mount:
            parser.error(
                "the following arguments are required: -t/--target, --target-list, or --mount "
                "(or use --resume <run_name> to continue a prior scan)"
            )
        target_strs: list[str] = cast("list[str]", args.target or [])
        target_list_paths: list[str] = cast("list[str]", args.target_list or [])
        mount_paths: list[str] = cast("list[str]", args.mount or [])
        targets_info: list[dict[str, Any]] = []
        targets: list[str] = list(target_strs)
        for target_list_path in target_list_paths:
            try:
                targets.extend(read_target_list_file(target_list_path))
            except ValueError as e:
                parser.error(str(e))

        if args.target_type and not targets:
            parser.error(
                "--target-type applies to --target/--target-list inputs; "
                "--mount directories are always classified local_code."
            )

        for target in targets:
            try:
                target_type, target_dict = resolve_target_type(target, args.target_type)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError as e:
                parser.error(str(e))

        try:
            targets_info.extend(build_mount_targets_info(mount_paths))
        except ValueError as e:
            parser.error(str(e))

        targets_info = dedupe_local_targets(targets_info)
        args.targets_info = targets_info

        if args.repository_revision and not any(
            t.get("type") == "repository" for t in targets_info
        ):
            parser.error(
                "--repository-revision requires at least one repository target "
                "(a remote Git URL). For a checked-out local repository, use "
                "--diff-base/--diff-head to assert its revisions instead."
            )

        assign_workspace_subdirs(targets_info)
        rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)

        # Supporting-file evidence: validate shape (regular file, no symlink /
        # traversal / executable bit, allowlisted text extension) and bound
        # per-file and aggregate size before any staging into the sandbox.
        try:
            args.attachments = collect_attachments(cast("list[str]", args.attachment or []))
        except AttachmentInputError as e:
            parser.error(str(e))

        max_local_copy_mb = load_settings().runtime.max_local_copy_mb
        max_copy_bytes = max_local_copy_mb * 1024 * 1024
        oversized = find_oversized_local_targets(targets_info, max_copy_bytes)
        if oversized:
            details = "; ".join(
                f"{path} ({size / (1024 * 1024):.0f} MB)" for path, size in oversized
            )
            parser.error(
                f"Local target too large to stream into the sandbox: {details}. "
                f"The limit is {max_local_copy_mb} MB "
                "(set STRIX_MAX_LOCAL_COPY_MB to change it). Re-run with "
                "--mount <path> to bind-mount the directory instead of copying it."
            )

    return args
