# Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import os

from . import posthog, scarf


# LyraShield product boundary: telemetry is always disabled for this
# controlled derivative, regardless of which entry point is used.
os.environ["STRIX_TELEMETRY"] = "0"


__all__ = [
    "posthog",
    "scarf",
]
