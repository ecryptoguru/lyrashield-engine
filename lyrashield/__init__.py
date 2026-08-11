"""LyraShield product package.

Prefer LiteLLM's bundled model metadata so imports never depend on GitHub
availability. LyraShield owns its billable GPT-5.6 rate table separately.
"""

from __future__ import annotations

import os


os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
