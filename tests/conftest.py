import pytest


_LLM_ENV_KEYS = [
    "STRIX_LLM",
    "LYRASHIELD_LLM",
    "STRIX_DELEGATE_LLM",
    "LYRASHIELD_DELEGATE_LLM",
    "STRIX_REASONING_EFFORT",
    "LYRASHIELD_REASONING_EFFORT",
    "STRIX_DELEGATE_REASONING_EFFORT",
    "LYRASHIELD_DELEGATE_REASONING_EFFORT",
    "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    "LYRASHIELD_FORCE_REQUIRED_TOOL_CHOICE",
    "STRIX_LLM_TIMEOUT",
    "LYRASHIELD_LLM_TIMEOUT",
    "STRIX_IMAGE",
    "LYRASHIELD_IMAGE",
    "STRIX_RUNTIME_BACKEND",
    "LYRASHIELD_RUNTIME_BACKEND",
    "STRIX_MAX_LOCAL_COPY_MB",
    "LYRASHIELD_MAX_LOCAL_COPY_MB",
    "STRIX_MAX_CONTEXT_IMAGES",
    "LYRASHIELD_MAX_CONTEXT_IMAGES",
    "STRIX_MAX_OUTPUT_TOKENS",
    "LYRASHIELD_MAX_OUTPUT_TOKENS",
    "STRIX_MAX_INPUT_TOKENS",
    "LYRASHIELD_MAX_INPUT_TOKENS",
    "STRIX_TELEMETRY",
    "LYRASHIELD_TELEMETRY",
    # Credential / endpoint aliases
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_AI_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_BASE",
    "AZURE_AI_API_BASE",
    "AZURE_API_BASE",
    "LLM_API_VERSION",
    "AZURE_API_VERSION",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_AI_API_VERSION",
    # Web search credentials and toggles
    "PARALLEL_API_KEY",
    "LYRASHIELD_WEB_SEARCH_API_KEY",
    "STRIX_WEB_SEARCH_API_KEY",
    "LYRASHIELD_WEB_SEARCH_ENABLED",
    "STRIX_WEB_SEARCH_ENABLED",
    "LYRASHIELD_WEB_SEARCH_MODE",
    "STRIX_WEB_SEARCH_MODE",
]


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear LLM-related env vars so tests don't inherit leaked Azure endpoints."""
    for key in _LLM_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the suite from reading a real MCP config.

    Upstream parity fixture: ``run_strix_scan`` connects the MCP servers listed
    in ``~/.strix/mcp-servers.json``. Point the loader at a path that does not
    exist so it resolves to "no connections". Tests that exercise the loader
    itself set their own ``STRIX_MCP_CONFIG`` after this runs.
    """
    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(missing))
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every machine (upstream parity fixture)."""
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_wallet_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real mppx wallet out of substrate top-up tests."""
    for name in ("MPPX_ACCOUNT", "MPPX_STRIPE_SECRET_KEY", "MPPX_STRIPE_PAYMENT_METHOD"):
        monkeypatch.delenv(name, raising=False)
