"""Anti-replay: a sliding window, not a bare high-water mark.

The obvious design — "reject any ``seq`` not greater than the highest seen" — is wrong
here, and wrong in a dangerous direction. Two orders dispatched seconds apart can
arrive out of order across WebSocket and push. Under a bare counter the second one to
arrive is silently dropped, and an attacker who can nudge delivery order gets a
suppression primitive for free.

So: an IPsec-style window. A duplicate inside the window is a true replay and is
rejected. Something *below* the window is ambiguous, so it is surfaced as a warning and
the human decides — delivery never degrades closed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol


class ReplayVerdict(StrEnum):
    FRESH = "fresh"
    DUPLICATE = "duplicate"  # reject: we have provably seen this exact seq
    OUT_OF_WINDOW = "out_of_window"  # warn: too old to judge, show it anyway


class ReplayChecker(Protocol):
    """What verification needs from a replay window: one question, no mutation.

    ``ReplayWindow`` below satisfies this and is what a client device uses. The
    server implements it over a table instead, because a window held in one
    process's memory is not a window at all once a second process exists: the same
    replayed order is rejected by the worker that has seen it and accepted by the
    one that has not, and whoever can pick the worker gets replay for free.
    """

    def check(self, stream_id: str, seq: int) -> ReplayVerdict: ...


class ReplayWindow:
    """Per-stream sliding bitmap of recently seen sequence numbers.

    State is small (one int per stream) and is expected to be persisted by the caller
    alongside the pinned bundles.
    """

    WINDOW = 1024

    def __init__(self, window: int = WINDOW) -> None:
        self._window = window
        self._high: dict[str, int] = {}
        self._bitmap: dict[str, int] = {}

    def state(self) -> dict[str, dict[str, int]]:
        """Serializable state, for persisting across client restarts."""
        return {
            stream: {"high": high, "bitmap": self._bitmap.get(stream, 0)}
            for stream, high in self._high.items()
        }

    def restore(self, state: dict[str, dict[str, int]]) -> None:
        for stream, entry in state.items():
            self._high[stream] = int(entry["high"])
            self._bitmap[stream] = int(entry["bitmap"])

    def check(self, stream_id: str, seq: int) -> ReplayVerdict:
        high = self._high.get(stream_id)
        if high is None or seq > high:
            return ReplayVerdict.FRESH
        if seq <= high - self._window:
            return ReplayVerdict.OUT_OF_WINDOW
        offset = high - seq
        if self._bitmap.get(stream_id, 0) >> offset & 1:
            return ReplayVerdict.DUPLICATE
        return ReplayVerdict.FRESH

    def commit(self, stream_id: str, seq: int) -> None:
        """Record ``seq`` as seen. Idempotent; safe to call after ``check``."""
        high = self._high.get(stream_id)
        if high is None:
            self._high[stream_id] = seq
            self._bitmap[stream_id] = 1
            return
        if seq > high:
            shift = seq - high
            bitmap = self._bitmap.get(stream_id, 0)
            bitmap = 0 if shift >= self._window else bitmap << shift
            self._bitmap[stream_id] = (bitmap | 1) & ((1 << self._window) - 1)
            self._high[stream_id] = seq
            return
        offset = high - seq
        if offset < self._window:
            self._bitmap[stream_id] = self._bitmap.get(stream_id, 0) | (1 << offset)
