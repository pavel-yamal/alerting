"""Loading the wake-code wordlist.

Lives at the top level rather than in ``core`` because it touches the filesystem, and
``core`` is required to be free of I/O (``tests/unit/test_core_is_pure.py`` enforces
that). It is not in ``server`` either: the executor client needs it to verify the
words from an SMS, and a client must not have to import the server package to do so.
"""

from __future__ import annotations

import pathlib

#: Each word carries 10 bits, so a short list silently weakens every wake code.
MIN_WORDLIST_SIZE = 1024


def load_wordlist(path: pathlib.Path, *, required: bool = True) -> list[str]:
    """Load the wake-code wordlist, skipping comments.

    ``required`` exists because the old behaviour — return ``[]`` for a missing file,
    no error, no log line — was the last silent degradation in the configuration path.
    A node started with the wrong working directory came up reporting healthy and only
    failed when a real order needed a wake code. SMS now refuses to send without one
    (see ``channels/base.NoWakeCode``), so the consequence is a failed channel rather
    than a codeless message — but the right place to notice is startup.

    There is deliberately no fallback path. The previous module-level default resolved
    relative to ``__file__`` assuming a ``src`` layout, which pointed at a
    non-existent directory once the package was installed from a wheel.

    Raises:
        FileNotFoundError: the file is missing and ``required``.
        ValueError: the list is too short to carry a full-entropy code.
    """
    if not path.exists():
        if required:
            raise FileNotFoundError(
                f"wake-code wordlist not found: {path}. Set ALERTING_WORDLIST to an "
                "absolute path; without it no SMS or voice wake-up can be sent."
            )
        return []

    words = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if required and len(words) < MIN_WORDLIST_SIZE:
        raise ValueError(
            f"wake-code wordlist {path} holds {len(words)} words, need at least "
            f"{MIN_WORDLIST_SIZE}: each word carries 10 bits and a short list weakens "
            "every code without saying so."
        )
    return words
