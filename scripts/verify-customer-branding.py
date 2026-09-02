"""Reject new upstream branding, including within rebuilt minified assets."""
# ruff: noqa: INP001, T201

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCOPES = ("lyrashield/interface", "lyrashield/tui", "lyrashield/skills")
# Exact non-visible compatibility strings; never exempt a bundle or an entire line.
STATIC_IDENTIFIERS = (
    '"strix_viewer_sidebar_width"',
    '"strix_viewer_sidebar_collapsed"',
    '"strix_viewer_trust_dismissed"',
    r"/^\[STRIX_\d+\]\$\s*/",
)


def violations(root: Path, allowed: dict[str, list[str]]) -> list[str]:
    errors = []
    for scope in SCOPES:
        for path in sorted((root / scope).rglob("*")):
            if not path.is_file() or {"node_modules", "__pycache__"} & set(path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue  # Binary images are reviewed separately; no blanket text exemptions.
            relative = path.relative_to(root).as_posix()
            if "/static/" in relative:
                for identifier in STATIC_IDENTIFIERS:
                    content = content.replace(identifier, "")
            for number, line in enumerate(content.splitlines(), 1):
                if re.search("strix", line, re.IGNORECASE) and line not in allowed.get(
                    relative, []
                ):
                    errors.append(f"{relative}:{number}: unapproved upstream branding")
    return errors


def main() -> int:
    allowed = json.loads((ROOT / "scripts/customer-branding-allowlist.json").read_text())
    errors = violations(ROOT, allowed["source_lines"])
    for error in errors:
        print(error)
    if not errors:
        print("Customer branding gate passed (exact compatibility allowlist).")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
