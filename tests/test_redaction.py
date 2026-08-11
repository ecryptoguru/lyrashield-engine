# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""Tests for the cross-cutting redaction utility and DLP integration."""

from __future__ import annotations

from lyrashield.artifacts.state import ReportState
from lyrashield.utils.redaction import redact_internal_paths, redact_secrets, redact_text


def test_redact_secrets_strips_api_keys() -> None:
    text = "Using api_key=sk-1234567890abcdef for the request"
    redacted = redact_secrets(text)
    assert "sk-1234567890abcdef" not in redacted
    assert "[SECRET]" in redacted


def test_redact_secrets_strips_passwords() -> None:
    text = "password=hunter2 please"
    redacted = redact_secrets(text)
    assert "hunter2" not in redacted
    assert "[SECRET]" in redacted


def test_redact_secrets_strips_bearer_tokens() -> None:
    text = "Authorization: Bearer abc123def456"
    redacted = redact_secrets(text)
    assert "abc123def456" not in redacted
    assert "[TOKEN]" in redacted


def test_redact_secrets_strips_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f"
    redacted = redact_secrets(f"Using {jwt} for auth")
    assert jwt not in redacted
    assert "[JWT]" in redacted


def test_redact_secrets_strips_aws_keys() -> None:
    text = "Credentials: AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[AWS_KEY]" in redacted


def test_redact_secrets_strips_private_keys() -> None:
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----"
    redacted = redact_secrets(f"Found: {key}")
    assert "MIIEowIBAAKCAQEAtest" not in redacted
    assert "[PRIVATE_KEY]" in redacted


def test_redact_secrets_strips_emails() -> None:
    text = "Contact alice@example.com for details"
    redacted = redact_secrets(text)
    assert "alice@example.com" not in redacted
    assert "[PII]" in redacted


def test_redact_secrets_strips_ipv4_without_keyword() -> None:
    """IPv4 addresses must be redacted even with no keyword trigger present.

    Regression test for P1-3: the fast-path keyword pre-check used to skip the
    entire regex suite when no secret marker was found, but ipv4/ipv6/uuid
    patterns have no corresponding trigger keyword.
    """
    text = "Connected to internal host 10.0.5.23"
    redacted = redact_secrets(text)
    assert "10.0.5.23" not in redacted
    assert "[PII]" in redacted


def test_redact_secrets_strips_ipv6_without_keyword() -> None:
    """IPv6 addresses must be redacted even with no keyword trigger present."""
    text = "Assigned address 2001:0db8:85a3:0000:0000:8a2e:0370:7334 to host"
    redacted = redact_secrets(text)
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in redacted
    assert "[PII]" in redacted


def test_redact_secrets_strips_compressed_ipv6_loopback() -> None:
    """Compressed IPv6 loopback ``::1`` must be redacted (RFC 4291 compressed form)."""
    text = "Connecting to ::1 for the health check"
    redacted = redact_secrets(text)
    assert "::1" not in redacted
    assert "[PII]" in redacted


def test_redact_secrets_strips_compressed_ipv6_interior() -> None:
    """Compressed IPv6 with interior ``::`` (e.g. ``2001:db8::1``) must be redacted."""
    text = "Resolved 2001:db8::1 via DNS"
    redacted = redact_secrets(text)
    assert "2001:db8::1" not in redacted
    assert "[PII]" in redacted


def test_redact_secrets_strips_uuid_without_keyword() -> None:
    """UUIDs must be redacted even with no keyword trigger present."""
    text = "Request id 550e8400-e29b-41d4-a716-446655440000 logged"
    redacted = redact_secrets(text)
    assert "550e8400-e29b-41d4-a716-446655440000" not in redacted
    assert "[PII]" in redacted


def test_redact_internal_paths_strips_workspace() -> None:
    text = "Found at /workspace/src/app.py and /workspace/.strix/tool-output/abc123.txt"
    redacted = redact_internal_paths(text)
    assert "/workspace/src/app.py" not in redacted
    assert "[INTERNAL_PATH]" in redacted
    assert "/workspace/.strix/tool-output/abc123.txt" not in redacted
    assert "[SPILL_PATH]" in redacted


def test_redact_text_combines_both() -> None:
    text = "Found at /workspace/secret.py with api_key=sk-test123 contact bob@test.com"
    redacted = redact_text(text)
    assert "/workspace/secret.py" not in redacted
    assert "sk-test123" not in redacted
    assert "bob@test.com" not in redacted


def test_redact_text_preserves_normal_content() -> None:
    text = "SQL injection in the login form via parameter 'username'"
    assert redact_text(text) == text


def test_vulnerability_report_redacts_secrets() -> None:
    """Secrets in vulnerability report free-text fields are redacted at storage."""
    state = ReportState(run_name="test-dlp")
    state.add_vulnerability_report(
        title="SSRF with leaked credentials",
        severity="high",
        description="Found api_key=sk-1234567890abcdef in the response",
        impact="password=admin123 could be used to access the panel",
        technical_analysis="Request to /workspace/internal/api exposed Bearer xyz789abc",
        poc_description="Sent payload with token=secret_token_abc",
        poc_script_code="curl -H 'Authorization: Bearer abc123def456' /workspace/target",
        remediation_steps="Rotate the secret=supersecret value",
        evidence="Response contained AKIAIOSFODNN7EXAMPLE",
        assumptions="Assumed email admin@target.com was compromised",
    )
    report = state.vulnerability_reports[0]
    assert "sk-1234567890abcdef" not in report["description"]
    assert "[SECRET]" in report["description"]
    assert "admin123" not in report["impact"]
    assert "[SECRET]" in report["impact"]
    assert "xyz789abc" not in report["technical_analysis"]
    assert "[TOKEN]" in report["technical_analysis"]
    assert "/workspace/internal/api" not in report["technical_analysis"]
    assert "secret_token_abc" not in report["poc_description"]
    assert "abc123def456" not in report["poc_script_code"]
    assert "[TOKEN]" in report["poc_script_code"]
    assert "/workspace/target" in report["poc_script_code"]
    assert "supersecret" not in report["remediation_steps"]
    assert "AKIAIOSFODNN7EXAMPLE" not in report["evidence"]
    assert "admin@target.com" not in report["assumptions"]


def test_final_report_redacts_secrets() -> None:
    """Secrets in final scan narrative sections are redacted at storage."""
    state = ReportState(run_name="test-dlp-final")
    state.update_scan_final_fields(
        executive_summary="Critical: api_key=sk-leaked123 exposed",
        methodology="Tested /workspace/app with password=admin123",
        technical_analysis="Found Bearer xyz789abc in responses",
        recommendations="Rotate secret=mysecret and check /workspace/config",
    )
    results = state.scan_results
    assert results is not None
    assert "sk-leaked123" not in results["executive_summary"]
    assert "[SECRET]" in results["executive_summary"]
    assert "/workspace/app" not in results["methodology"]
    assert "admin123" not in results["methodology"]
    assert "xyz789abc" not in results["technical_analysis"]
    assert "mysecret" not in results["recommendations"]
    assert "/workspace/config" not in results["recommendations"]


def test_whitebox_report_preserves_internal_paths() -> None:
    """In whitebox mode, internal target paths are preserved in report fields.

    Spill paths (/workspace/.strix/tool-output/) are always redacted since they
    are internal infrastructure, not target code.
    """
    state = ReportState(run_name="test-whitebox")
    state.set_scan_config({"targets": [{"type": "local_code"}], "scan_mode": "deep"})
    state.add_vulnerability_report(
        title="Path traversal in file handler",
        severity="high",
        description="Found traversal at /workspace/app/src/handler.py",
        technical_analysis="Code at /workspace/app/src/handler.py is vulnerable",
        evidence="Output from /workspace/.strix/tool-output/scan.txt",
        poc_script_code="curl http://target/api?file=../../etc/passwd",
    )
    report = state.vulnerability_reports[0]
    assert "/workspace/app/src/handler.py" in report["description"]
    assert "/workspace/app/src/handler.py" in report["technical_analysis"]
    assert "/workspace/.strix/tool-output/scan.txt" not in report["evidence"]
    assert "[SPILL_PATH]" in report["evidence"]


def test_whitebox_final_report_preserves_paths() -> None:
    """In whitebox mode, internal paths in final report sections are preserved."""
    state = ReportState(run_name="test-whitebox-final")
    state.set_scan_config({"targets": [{"type": "local_code"}], "scan_mode": "deep"})
    state.update_scan_final_fields(
        executive_summary="Critical issues found in /workspace/app",
        methodology="Tested /workspace/app with semgrep and dynamic validation",
        technical_analysis="SQLi at /workspace/app/api/users endpoint",
        recommendations="Fix /workspace/app/api/users parameterized queries",
    )
    results = state.scan_results
    assert results is not None
    assert "/workspace/app" in results["executive_summary"]
    assert "/workspace/app" in results["methodology"]
    assert "/workspace/app/api/users" in results["technical_analysis"]
    assert "/workspace/app/api/users" in results["recommendations"]


def test_poc_script_preserves_paths_in_blackbox() -> None:
    """PoC script code preserves internal paths even in blackbox mode for reproducibility."""
    state = ReportState(run_name="test-blackbox-poc")
    state.set_scan_config({"targets": [{"type": "url"}], "scan_mode": "deep"})
    state.add_vulnerability_report(
        title="SSRF",
        severity="critical",
        poc_script_code="python3 /workspace/exploit.py --target http://example.com",
    )
    report = state.vulnerability_reports[0]
    assert "/workspace/exploit.py" in report["poc_script_code"]
