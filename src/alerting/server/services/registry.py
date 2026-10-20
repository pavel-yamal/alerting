"""Org state: the verified bundles, the roster, and audience resolution.

The server verifies bundles against the same pinned root key the clients use. It gains
the server nothing security-wise — a compromised server could skip the check — but it
means a misconfigured deployment fails at startup rather than during an incident.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from alerting.core.directory import Directory
from alerting.core.envelope import OrderPayload
from alerting.core.policy import Policy
from alerting.core.signing import b64u_decode
from alerting.server.channels.base import Recipient
from alerting.server.db.repo import Repo


class OrgState:
    def __init__(
        self,
        repo: Repo,
        *,
        org_id: str,
        root_public_key: Ed25519PublicKey,
        wordlist: list[str] | None = None,
        drill_enabled_sites: frozenset[str] = frozenset(),
    ) -> None:
        self.repo = repo
        self.org_id = org_id
        self.root_public_key = root_public_key
        # No implicit load: the caller owns the path, so a missing file is a startup
        # failure at a place that can report it, not a quiet empty list in here.
        self.wordlist = wordlist if wordlist is not None else []
        self.drill_enabled_sites = drill_enabled_sites

    @property
    def directory_bundle(self) -> dict[str, Any]:
        bundle = self.repo.latest_bundle("directory")
        if bundle is None:
            raise RuntimeError("no directory bundle published")
        return bundle

    @property
    def policy_bundle(self) -> dict[str, Any]:
        bundle = self.repo.latest_bundle("policy")
        if bundle is None:
            raise RuntimeError("no policy bundle published")
        return bundle

    @property
    def revocations_bundle(self) -> dict[str, Any] | None:
        return self.repo.latest_bundle("revocations")

    def directory(self) -> Directory:
        """The root-signed directory with the fast-path revocation list applied.

        Every gate reads this -- signed requests, the socket handshake and its
        periodic re-check, order verification -- so a published revocation list
        takes effect on the next request without a restart.
        """
        return Directory.load(
            self.directory_bundle,
            root_public_key=self.root_public_key,
            org_id=self.org_id,
        ).with_revocations(self.revocations_bundle)

    def policy(self) -> Policy:
        return Policy.load(
            self.policy_bundle, root_public_key=self.root_public_key, org_id=self.org_id
        )

    def recipients_for(self, order: OrderPayload) -> list[Recipient]:
        """Resolve the audience to people.

        Over-inclusion is the safe direction here: a person matched by site, group, or
        name all get the order once.
        """
        wanted_sites = set(order.audience.sites)
        wanted_groups = set(order.audience.groups)
        wanted_persons = set(order.audience.persons)

        out: list[Recipient] = []
        for row in self.repo.contacts():
            groups = tuple(g for g in row["groups_csv"].split(",") if g)
            matched = (
                row["person_id"] in wanted_persons
                or (row["site"] and row["site"] in wanted_sites)
                or bool(wanted_groups & set(groups))
            )
            if not matched:
                continue
            out.append(
                Recipient(
                    person_id=row["person_id"],
                    name=row["name"],
                    phone=row["phone"],
                    site=row["site"],
                    groups=groups,
                    wake_key=b64u_decode(row["wake_key"]) if row["wake_key"] else b"",
                )
            )
        return out
