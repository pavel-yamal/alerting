"""Time as an injected dependency.

``core`` never reads the system clock. Callers pass a ``Clock``; tests pass a
``FixedClock``. That keeps TTL and skew behaviour deterministic without monkeypatching.
"""

from __future__ import annotations

import time
from typing import Protocol

#: Orders are rejected as not-yet-valid, and flagged as skewed, outside this tolerance.
#: Two minutes covers ordinary NTP drift on a phone without opening a replay window.
SKEW_TOLERANCE_S = 120


class Clock(Protocol):
    """Source of Unix seconds."""

    def now(self) -> int:  # pragma: no cover - protocol definition
        ...


class SystemClock:
    """Wall clock. Requires NTP on every node; see docs/06-runbook.md."""

    def now(self) -> int:
        return int(time.time())


class FixedClock:
    """Deterministic clock for tests and replay of recorded incidents."""

    def __init__(self, at: int) -> None:
        self._at = int(at)

    def now(self) -> int:
        return self._at

    def advance(self, seconds: int) -> None:
        self._at += int(seconds)
