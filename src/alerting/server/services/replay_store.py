"""Anti-replay for the server: a table, not a window in one process's memory.

``ReplayWindow`` in the core is right for a client device -- one process, one
person, state small enough to keep in a file. On the server it was a liability the
moment a second process could exist: each worker holds its own window, so the same
replayed order is rejected by the worker that has seen it and accepted by the one
that has not. Whoever can influence which worker answers gets replay for free, and
nothing in the logs says so.

The primary key on ``stream_seq`` does the work instead. Claiming a sequence number
is one atomic insert, so the loser of a race learns that it lost.

Note the split between :meth:`DatabaseReplayWindow.check` and
:meth:`DatabaseReplayWindow.claim`. The check feeds verification, which must report
reasons and warnings without changing anything. The claim is the decision, and it
happens at the moment the order is recorded -- because anything between a check and
a write is a window another process can dispatch through.
"""

from __future__ import annotations

import logging

from alerting.core.replay import ReplayVerdict, ReplayWindow
from alerting.server.db.repo import Repo

log = logging.getLogger("alerting.replay")


class DatabaseReplayWindow:
    """Satisfies ``ReplayChecker`` over ``stream_seq``, with the same three verdicts."""

    #: Same width as the in-memory window, so client and server agree on what is
    #: "too old to judge" rather than each drawing the line somewhere else.
    WINDOW = ReplayWindow.WINDOW

    def __init__(self, repo: Repo, window: int = WINDOW) -> None:
        self.repo = repo
        self._window = window

    def check(self, stream_id: str, seq: int) -> ReplayVerdict:
        high = self.repo.stream_high(stream_id)
        if high is None or seq > high:
            return ReplayVerdict.FRESH
        if seq <= high - self._window:
            # Too old to judge. Rejecting here would be a suppression primitive.
            return ReplayVerdict.OUT_OF_WINDOW
        if self.repo.stream_seq_seen(stream_id, seq):
            return ReplayVerdict.DUPLICATE
        return ReplayVerdict.FRESH

    def claim(self, stream_id: str, seq: int, order_id: str, at: int) -> bool:
        """Take ``(stream_id, seq)`` for this order. False means somebody else has it.

        A retry of the *same* order succeeds: a process that crashed between claiming
        and recording would otherwise have burned that number for good, and the
        retry would be reported as a replay -- a genuine order refused because of a
        crash, which is the worst way to fail here.
        """
        holder = self.repo.claim_stream_seq(stream_id, seq, order_id, at)
        if holder is None or holder == order_id:
            return True
        log.warning(
            "refused %s: stream %s seq %d already dispatched as %s",
            order_id,
            stream_id,
            seq,
            holder,
        )
        return False


class KnownOrders:
    """``order_id in known`` as one indexed query.

    Verification only ever asks ``in``. It used to be handed a set built from the
    thousand most recent orders, which cost a full row scan per dispatch and, worse,
    stopped detecting a duplicate once a thousand orders had gone by.
    """

    def __init__(self, repo: Repo) -> None:
        self.repo = repo

    def __contains__(self, order_id: object) -> bool:
        return isinstance(order_id, str) and self.repo.order_exists(order_id)
