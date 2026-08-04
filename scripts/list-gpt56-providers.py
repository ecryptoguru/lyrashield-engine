#!/usr/bin/env python3
"""List LiteLLM providers that have cost-map entries for GPT-5.6 models.

Run this script to refresh the provider allow-list in
``strix/config/models.py`` when a new provider starts carrying GPT-5.6
Terra/Luna deployments in LiteLLM's bundled model cost map.
"""

import sys

import litellm


def main() -> None:
    providers: set[str] = set()
    for name, info in litellm.model_cost.items():
        if isinstance(info, dict) and "gpt-5.6" in str(name).lower():
            providers.add(str(info.get("litellm_provider", "unknown")))

    for provider in sorted(providers):
        sys.stdout.write(f"{provider}\n")


if __name__ == "__main__":
    main()
