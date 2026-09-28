from __future__ import annotations

from importlib import import_module

import pytest


main_module = import_module("lyrashield.interface.main")


@pytest.mark.parametrize(
    ("export_name", "module_name", "implementation_name"),
    [
        ("validate_environment", "environment_gate", "validate_environment"),
        ("warm_up_llm", "warmup", "warm_up_llm"),
        ("parse_arguments", "arg_parser", "parse_arguments"),
        ("_load_resume_state", "resume_state", "_load_resume_state"),
        ("_normalize_digest", "image_pull", "_normalize_digest"),
        ("_verify_image_digest", "image_pull", "_verify_image_digest"),
        ("pull_docker_image", "image_pull", "pull_docker_image"),
        ("process_pull_line", "image_pull", "process_pull_line"),
    ],
)
def test_main_reexports_split_helpers(
    export_name: str, module_name: str, implementation_name: str
) -> None:
    implementation = getattr(
        import_module(f"lyrashield.interface.{module_name}"), implementation_name
    )

    assert getattr(main_module, export_name) is implementation
