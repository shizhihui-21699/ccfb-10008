"""Injectable clock.

Every part of the application takes wall-clock time from this module instead of
calling ``time.time()`` directly, which lets tests freeze, fast-forward and
*roll back* the clock deterministically (the roll-back case is a core MFA
requirement: users sometimes end up with a phone whose clock moved backwards).
"""

from __future__ import annotations

import time as _time


class Clock:
    def __init__(self) -> None:
        self._fixed: float | None = None

    def now(self) -> float:
        """Current Unix timestamp, or the frozen timestamp in tests."""
        if self._fixed is None:
            return _time.time()
        return self._fixed

    def freeze(self, timestamp: float) -> None:
        self._fixed = float(timestamp)

    def advance(self, seconds: float) -> None:
        if self._fixed is None:
            raise RuntimeError("advance() is only valid while the clock is frozen")
        self._fixed += seconds

    def reset(self) -> None:
        self._fixed = None


clock = Clock()
