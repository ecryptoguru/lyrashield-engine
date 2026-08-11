### Overview

LyraShield Engine is a controlled derivative of upstream Strix. The inherited telemetry stack (PostHog and Scarf clients in `posthog.py` / `scarf.py`) is **forced off** by the `lyrashield` product entry point (`lyrashield_adapter`), which sets `STRIX_TELEMETRY=0` before the upstream CLI runs. No remote analytics are sent in production. The code is retained only so the upstream substrate remains reviewable and so the bare `strix` dev CLI keeps its upstream behavior.

### What the adapter does

`lyrashield_adapter.cli.prepare_environment` unconditionally sets:

- `STRIX_TELEMETRY=0` — disables PostHog and Scarf event emission.
- `STRIX_NO_UPDATE_CHECK=1` — disables the upstream self-update network check.
- `LYRASHIELD_PRODUCT_BOUNDARY=1` — marks the process as running behind the product boundary so configuration is re-validated after `--config` is applied.

It also rejects `chatgpt/` subscription-backed models, which would bypass the GPT-5.6 Terra/Luna deployment gate and record runs with zero metered cost.

### Inherited clients (disabled in production)

The retained clients are [PostHog](https://posthog.com) and [Scarf](https://scarf.sh). Their source is reviewable here: [`posthog.py`](posthog.py), [`scarf.py`](scarf.py). When telemetry is disabled (the LyraShield default and forced state), each client logs a debug message and sends nothing.

### What is never collected

Even when the inherited clients were active upstream, they never collected:

- Usernames or identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### Local operator override (non-production)

The bare upstream `strix` dev CLI (not shipped in this distribution) honors `STRIX_TELEMETRY=0` to opt out. The `lyrashield` entry point sets this for you; there is no supported way to re-enable remote telemetry through the product boundary, and re-enabling it would violate the LyraShield production contract.
