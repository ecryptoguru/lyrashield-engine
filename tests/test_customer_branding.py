"""Customer-visible branding must not regress through source or bundled output."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "customer_branding", ROOT / "scripts/verify-customer-branding.py"
)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def test_owned_customer_branding() -> None:
    allowed = json.loads((ROOT / "scripts/customer-branding-allowlist.json").read_text())
    assert GATE.violations(ROOT, allowed["source_lines"]) == []
    assert not (ROOT / "scripts/install.sh").exists()
    source = (ROOT / "lyrashield/interface/viewer/frontend/src").rglob("*.tsx")
    for path in source:
        assert "UpgradeModal" not in path.read_text() or path.name == "AgentDetailModal.tsx"
    frontend = ROOT / "lyrashield/interface/viewer/frontend/src"
    export = (frontend / "components/EmailReportView.tsx").read_text()
    assert 'download="lyrashield-report.md"' in export
    assert "encodeURIComponent(markdown)" in export
    assert "sendReport" not in export and "otp" not in export
    assert "FeedbackView" not in (frontend / "App.tsx").read_text()
    assert "EmailVerifyInline" not in (frontend / "components/PastRunsView.tsx").read_text()


@pytest.mark.parametrize("visible", ['"Strix Cloud"', '"https://app.strix.ai/signup"'])
@pytest.mark.parametrize("location", ["frontend/src/new.tsx", "static/assets/new.js"])
def test_injected_brand_or_link_fails(tmp_path: Path, visible: str, location: str) -> None:
    path = tmp_path / "lyrashield/interface/viewer" / location
    path.parent.mkdir(parents=True)
    path.write_text('const key = "strix_viewer_sidebar_width"; const label = ' + visible)
    assert GATE.violations(tmp_path, {})


def test_compatibility_allowlist_does_not_hide_same_line_injection(tmp_path: Path) -> None:
    path = tmp_path / "lyrashield/interface/example.py"
    path.parent.mkdir(parents=True)
    allowed_line = "from strix.config import load_settings"
    allowed = {"lyrashield/interface/example.py": [allowed_line]}
    path.write_text(allowed_line)
    assert GATE.violations(tmp_path, allowed) == []
    path.write_text(allowed_line + '; print("Strix Cloud")')
    assert GATE.violations(tmp_path, allowed)
