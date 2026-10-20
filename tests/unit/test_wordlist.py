"""The wake-code wordlist must fail loudly, not quietly.

Returning `[]` for a missing file was the last silent degradation in the
configuration path: a node started with the wrong working directory came up
reporting healthy and only failed when a real order needed a wake code.
"""

from __future__ import annotations

import pathlib

import pytest

from alerting.wordlist import MIN_WORDLIST_SIZE, load_wordlist

REAL = pathlib.Path("config/wordlist.ru.txt")


def test_the_shipped_wordlist_loads_and_is_long_enough():
    words = load_wordlist(REAL)
    assert len(words) >= MIN_WORDLIST_SIZE
    assert all(word == word.strip() for word in words)
    assert not any(word.startswith("#") for word in words)


def test_a_missing_file_raises_instead_of_returning_nothing(tmp_path):
    with pytest.raises(FileNotFoundError, match="wake-code wordlist not found"):
        load_wordlist(tmp_path / "absent.txt")


def test_a_short_list_is_refused(tmp_path):
    """Each word carries 10 bits, so a short list weakens every code silently."""
    path = tmp_path / "short.txt"
    path.write_text("\n".join(f"СЛОВО{i}" for i in range(100)), encoding="utf-8")

    with pytest.raises(ValueError, match="need at least"):
        load_wordlist(path)


def test_a_comment_only_file_is_refused(tmp_path):
    path = tmp_path / "comments.txt"
    path.write_text("# only a header\n# and another\n", encoding="utf-8")

    with pytest.raises(ValueError, match="holds 0 words"):
        load_wordlist(path)


def test_the_check_can_be_waived_for_callers_that_want_best_effort(tmp_path):
    assert load_wordlist(tmp_path / "absent.txt", required=False) == []


def test_org_state_no_longer_loads_a_wordlist_behind_the_callers_back():
    """The old implicit load resolved a path relative to __file__ assuming a src
    layout, which pointed at a non-existent directory once installed from a wheel."""
    import inspect

    from alerting.server.services import registry

    assert not hasattr(registry, "WORDLIST_PATH")
    source = inspect.getsource(registry.OrgState.__init__)
    assert "load_wordlist" not in source
