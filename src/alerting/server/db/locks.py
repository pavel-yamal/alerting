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
