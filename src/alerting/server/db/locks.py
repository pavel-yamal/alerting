"""Advisory lock keys.

PostgreSQL advisory locks are keyed by a bare integer with no namespace, so two
unrelated parts of a system that pick the same number deadlock against each other
for reasons that are invisible in both. Keeping every key this project takes in one
short file is the cheapest way to keep that from happening.
"""

from __future__ import annotations

from typing import Final

#: Held for the duration of a migration run, so two nodes starting at once do not
#: both try to create the same table.
MIGRATION: Final = 0x41_4C_52_01

#: Held for the length of the transaction that appends one audit entry. Every
#: appender serializes on this: the entry's index and its ``prev`` hash are read and
#: written as one step, which is what makes the chain a chain.
AUDIT_CHAIN: Final = 0x41_4C_52_02

#: Held for the lifetime of whichever process is climbing escalation ladders. Unlike
#: the two above this one is *session* scoped, so it needs a connection of its own:
#: a pooled connection is handed back after each statement, which would drop it.
ESCALATION_LEADER: Final = 0x41_4C_52_03

#: Held by whichever process runs the delivery canary. A separate key from the
#: escalation lock: the two are different jobs, and a node that is fit to climb a
#: ladder is not automatically the one that should be probing the delivery path.
CANARY: Final = 0x41_4C_52_04
