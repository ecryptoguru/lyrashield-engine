# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
"""LyraShield Local — engine TUI.

A desktop-friendly terminal UI that shells into the existing engine CLI
(``lyrashield``) without expanding the thin-fork boundary in
``lyrashield_adapter/`` or ``strix/**``. Flows:

* pick a target (repo path/URL)
* pick a scan mode (SAFE/QUICK/STANDARD/DEEP/CUSTOM — all available locally,
  no Cloud-style depth gating and no agent-minute metering)
* connect BYOK (ChatGPT subscription OAuth or Azure OpenAI)
* run with streamed progress
* view findings + fix suggestions
* export SARIF/report

Credentials live in the OS keychain (never plaintext). Results persist in a
local SQLite store encrypted at rest.
"""

from lyrashield.tui.app import LyraShieldLocalApp, run_tui


__all__ = ["LyraShieldLocalApp", "run_tui"]
