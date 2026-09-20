"""The sliding window, and why it is not a bare high-water mark."""

from __future__ import annotations

from alerting.core.replay import ReplayVerdict, ReplayWindow


def accept(window: ReplayWindow, stream: str, seq: int) -> ReplayVerdict:
    verdict = window.check(stream, seq)
    if verdict is ReplayVerdict.FRESH:
        window.commit(stream, seq)
    return verdict


def test_monotonic_sequence_is_fresh():
    window = ReplayWindow()
    for seq in range(1, 10):
        assert accept(window, "primary", seq) is ReplayVerdict.FRESH


def test_exact_replay_is_rejected():
    window = ReplayWindow()
    accept(window, "primary", 5)
    assert window.check("primary", 5) is ReplayVerdict.DUPLICATE


def test_out_of_order_arrival_is_accepted():
    """Two orders seconds apart can arrive WS-before-push. A bare counter would drop
    the second one silently, handing an attacker a suppression primitive."""
    window = ReplayWindow()
    accept(window, "primary", 12)
    assert accept(window, "primary", 11) is ReplayVerdict.FRESH
    assert window.check("primary", 11) is ReplayVerdict.DUPLICATE


def test_below_the_window_is_a_warning_not_a_rejection():
    window = ReplayWindow(window=8)
    accept(window, "primary", 100)
    assert window.check("primary", 90) is ReplayVerdict.OUT_OF_WINDOW


def test_window_edges():
    window = ReplayWindow(window=8)
    accept(window, "primary", 100)
    assert window.check("primary", 93) is ReplayVerdict.FRESH  # inside
    assert window.check("primary", 92) is ReplayVerdict.OUT_OF_WINDOW  # exactly out


def test_large_jump_clears_the_bitmap_without_false_duplicates():
    window = ReplayWindow(window=8)
    accept(window, "primary", 1)
    accept(window, "primary", 1000)
    assert window.check("primary", 999) is ReplayVerdict.FRESH


def test_streams_are_independent():
    window = ReplayWindow()
    accept(window, "hq", 5)
    assert window.check("plant", 5) is ReplayVerdict.FRESH


def test_state_survives_a_restart():
    window = ReplayWindow()
    for seq in (1, 2, 3):
        accept(window, "primary", seq)
    restored = ReplayWindow()
    restored.restore(window.state())
    assert restored.check("primary", 2) is ReplayVerdict.DUPLICATE
    assert restored.check("primary", 4) is ReplayVerdict.FRESH


def test_commit_is_idempotent():
    window = ReplayWindow()
    window.commit("primary", 7)
    window.commit("primary", 7)
    assert window.check("primary", 7) is ReplayVerdict.DUPLICATE
