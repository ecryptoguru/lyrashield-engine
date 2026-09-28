"""Restore and validate persisted scan state before a resumed run."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    import argparse

from lyrashield.artifacts.writer import read_resume_record, read_run_record
from lyrashield.interface.utils import _read_only_head_revision
from lyrashield.policy.loader import load_settings
from lyrashield.policy.settings import is_lyrashield_product
from lyrashield.runtime.attachments import AttachmentInputError, restore_attachments
from strix.core.paths import run_dir_for, runs_base_dir


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    resolved_run_dir = run_dir.resolve()
    resolved_base = runs_base_dir().resolve()
    if not resolved_run_dir.is_relative_to(resolved_base):
        parser.error(
            f"--resume {args.resume}: run directory resolves outside the runs base "
            f"({resolved_base})"
        )
    state_path = run_dir / "run.json"
    if not state_path.is_file() or state_path.is_symlink():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    for p in (run_dir / "agents.json", run_dir / "agents.db"):
        if p.is_symlink() or (p.exists() and not p.is_file()):
            parser.error(f"--resume {args.resume}: invalid snapshot file {p}")
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    # Prefer the private resume record: it preserves unsanitized execution
    # fields (cloned_repo_path, source_path) that run.json redacts for the
    # public worker contract (comment #5). Fall back to the public record.
    resume_state = read_resume_record(run_dir)
    targets_info_source = resume_state.get("targets_info")
    local_sources_source = resume_state.get("local_sources")
    if not isinstance(targets_info_source, list):
        targets_info_source = state.get("targets_info")
    if not isinstance(local_sources_source, list):
        local_sources_source = state.get("local_sources")

    raw_targets_info: Any = targets_info_source or []
    if not isinstance(raw_targets_info, list):
        parser.error(f"--resume {args.resume}: run.json targets_info is not a list")
    raw_targets_info = cast("list[Any]", raw_targets_info)

    targets_info: list[dict[str, Any]] = [
        cast("dict[str, Any]", raw) for raw in raw_targets_info if isinstance(raw, dict)
    ]

    if not targets_info:
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    # A recorded immutable revision binds every restored repository clone:
    # acquisition pins each checkout to --repository-revision or the recorded
    # diff head, so resume must find that exact HEAD. The comparison is
    # read-only — never a checkout, fetch or repair — so a tampered cache is
    # left untouched for inspection rather than silently reset.
    expected_revision_raw = state.get("repository_revision") or state.get("diff_head")
    expected_revision = (
        str(expected_revision_raw).strip().lower() if expected_revision_raw else None
    )

    cloned_repo_paths: set[Path] = set()
    for target in targets_info:
        details_raw: Any = target.get("details")
        details: dict[str, Any] = (
            cast("dict[str, Any]", details_raw) if isinstance(details_raw, dict) else {}
        )
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not isinstance(cloned, str) or not cloned:
            continue
        cloned_path = Path(cloned).expanduser().resolve()
        repo_base = (Path(tempfile.gettempdir()) / "strix_repos").resolve()
        if cloned_path.is_symlink() or not cloned_path.is_relative_to(repo_base):
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} resolves outside "
                f"the allowed cache directory."
            )
        if not cloned_path.exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )
        if expected_revision:
            actual_head = _read_only_head_revision(cloned_path)
            if actual_head != expected_revision:
                parser.error(
                    f"--resume {args.resume}: cloned repo at {cloned} has HEAD "
                    f"{actual_head or 'unresolved'} but the run recorded "
                    f"revision {expected_revision}. The cached clone changed "
                    "between runs; refusing to resume from altered source. "
                    "Pick a fresh --run-name to re-clone."
                )
        cloned_repo_paths.add(cloned_path)

    args.targets_info = targets_info

    # Restore the run's attachment inputs. The public run.json manifest is
    # sanitized (no host paths), so re-staging requires the private resume
    # record; a run that declared attachments but cannot re-stage them fails
    # closed rather than scanning without its input evidence.
    recorded_attachments = resume_state.get("attachments")
    if not isinstance(recorded_attachments, list):
        recorded_attachments = []
    try:
        args.attachments = restore_attachments(recorded_attachments)
    except AttachmentInputError as e:
        parser.error(f"--resume {args.resume}: {e}")
    state_attachments = state.get("attachments")
    if not args.attachments and isinstance(state_attachments, list) and state_attachments:
        parser.error(
            f"--resume {args.resume}: the run declared {len(state_attachments)} "
            "attachment(s), but resume.json does not preserve their host paths. "
            "The input evidence cannot be re-staged; start a fresh run instead."
        )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if local_sources_source:
        args.local_sources = local_sources_source
    elif state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if is_lyrashield_product() and load_settings().runtime.backend == "docker":
        for source in getattr(args, "local_sources", []):
            if not isinstance(source, dict):
                continue
            source_path = source.get("source_path")
            if (
                isinstance(source_path, str)
                and Path(source_path).expanduser().resolve() in cloned_repo_paths
            ):
                source["mount"] = True
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    # Restore recorded source provenance so a resumed run's run.json keeps the
    # revisions it was launched with rather than overwriting them with None.
    for key in ("scope_mode", "diff_base", "diff_head", "repository_revision"):
        if state.get(key):
            setattr(args, key, state.get(key))
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
