"""One monotonic runtime allowance shared by a non-interactive scan."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class RunDeadline:
    hard_at: float
    wrap_at: float
    clock: Callable[[], float]

    @classmethod
    def start(cls, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> RunDeadline:
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("runtime budget must be a finite positive number of seconds")
        started = clock()
        reserve = min(120.0, seconds * 0.2)
        return cls(hard_at=started + seconds, wrap_at=started + seconds - reserve, clock=clock)

    def remaining_seconds(self) -> float:
        return max(0.0, self.hard_at - self.clock())

    def until_wrap_seconds(self) -> float:
        return max(0.0, self.wrap_at - self.clock())

    def wrapping_up(self) -> bool:
        return self.clock() >= self.wrap_at
