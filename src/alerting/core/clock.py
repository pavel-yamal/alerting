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

#: How far a *transport authentication* signature may be from the server's clock.
#: Tighter than the order tolerance above on purpose: an order carries its own
#: validity window and degrades open on skew, while transport auth is a gate and
#: degrades closed. Shared by the WebSocket handshake and by signed HTTP requests so
#: an operator has one number to know, not two.
#:
#: Operationally this is the reason `chronyd` is a hard dependency of the unit: a node
#: whose clock drifts starts refusing valid clients while looking perfectly healthy.
TRANSPORT_AUTH_WINDOW_S = 60


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
