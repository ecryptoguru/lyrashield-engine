# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Facade for the split source-acquisition modules (E2.4).

The coherent responsibilities live in ``git_command`` (controlled Git
subprocess boundary, object-id validation, deadline caps), ``diff_scope``
(diff-scope resolution and provenance) and ``repo_clone`` (cloning,
revision pinning, checkout assertion). This module re-exports every
historical name so downstream imports and the stable facades keep
working unchanged.
"""

from __future__ import annotations

import subprocess  # noqa: F401
import tempfile  # noqa: F401

from lyrashield.interface import diff_scope as _diff_scope
from lyrashield.interface import git_command as _git_command
from lyrashield.interface import repo_clone as _repo_clone
from lyrashield.lifecycle.deadline import (  # noqa: F401
    RunDeadline,
    RunDeadlineExceededError,
)


# git_command: controlled subprocess boundary and shared vocabulary
SourcePreflightError = _git_command.SourcePreflightError
_GIT_OBJECT_ID_RE = _git_command._GIT_OBJECT_ID_RE
_is_git_object_id = _git_command._is_git_object_id
_raise_if_deadline_exhausted = _git_command._raise_if_deadline_exhausted
_bounded_timeout = _git_command._bounded_timeout
validate_git_object_id = _git_command.validate_git_object_id
_git_executable = _git_command._git_executable
_run_git_command = _git_command._run_git_command
_run_git_command_raw = _git_command._run_git_command_raw
_git_ref_exists = _git_command._git_ref_exists
_is_full_git_commit_sha = _git_command._is_full_git_commit_sha

# diff_scope: diff-scope resolution and provenance
_SUPPORTED_SCOPE_MODES = _diff_scope._SUPPORTED_SCOPE_MODES
_MAX_FILES_PER_SECTION = _diff_scope._MAX_FILES_PER_SECTION
DiffEntry = _diff_scope.DiffEntry
RepoDiffScope = _diff_scope.RepoDiffScope
DiffScopeResult = _diff_scope.DiffScopeResult
_is_ci_environment = _diff_scope._is_ci_environment
_is_pr_environment = _diff_scope._is_pr_environment
_is_git_repo = _diff_scope._is_git_repo
_is_repo_shallow = _diff_scope._is_repo_shallow
_resolve_origin_head_ref = _diff_scope._resolve_origin_head_ref
_extract_branch_name = _diff_scope._extract_branch_name
_extract_github_base_sha = _diff_scope._extract_github_base_sha
_resolve_default_branch_name = _diff_scope._resolve_default_branch_name
_resolve_base_ref = _diff_scope._resolve_base_ref
_get_current_branch_name = _diff_scope._get_current_branch_name
_parse_name_status_z = _diff_scope._parse_name_status_z
_append_unique = _diff_scope._append_unique
_classify_diff_entries = _diff_scope._classify_diff_entries
_truncate_file_list = _diff_scope._truncate_file_list
build_diff_scope_instruction = _diff_scope.build_diff_scope_instruction
_resolve_commit_sha = _diff_scope._resolve_commit_sha
_worktree_snapshot_state = _diff_scope._worktree_snapshot_state
_should_activate_auto_scope = _diff_scope._should_activate_auto_scope
_resolve_repo_diff_scope = _diff_scope._resolve_repo_diff_scope
resolve_diff_scope_context = _diff_scope.resolve_diff_scope_context

# repo_clone: cloning, revision pinning, checkout assertion
_GIT_CLONE_TIMEOUT_SECONDS = _repo_clone._GIT_CLONE_TIMEOUT_SECONDS
_GIT_FETCH_TIMEOUT_SECONDS = _repo_clone._GIT_FETCH_TIMEOUT_SECONDS
_GIT_CHECKOUT_TIMEOUT_SECONDS = _repo_clone._GIT_CHECKOUT_TIMEOUT_SECONDS
_print_clone_error = _repo_clone._print_clone_error
_print_source_preflight_error = _repo_clone._print_source_preflight_error
_commit_available = _repo_clone._commit_available
_ensure_commit_available = _repo_clone._ensure_commit_available
_read_only_head_revision = _repo_clone._read_only_head_revision
_assert_checkout_revision = _repo_clone._assert_checkout_revision
clone_repository = _repo_clone.clone_repository
