"""Publish an organisation into a server database.

Real enrollment is an in-person procedure (docs/02-trust-and-approval.md). This is the
one-command version so a reviewer can get a working system, and it is also what the
tests use, which keeps the demo honest: it exercises the same code path.
"""

from __future__ import annotations

from alerting.core.audit_chain import Event
from alerting.core.signing import b64u_encode
from alerting.orgkit import Org
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService

#: Who is in which group. Groups drive audience resolution and escalation reassignment.
DEFAULT_GROUPS: dict[str, tuple[str, ...]] = {
    "x-101": ("fire-wardens",),
    "x-102": ("fire-wardens",),
    "x-103": ("alternates",),
}


def publish_org(
    repo: Repo,
    org: Org,
    *,
    audit: AuditService | None = None,
    site: str = "hq",
    groups: dict[str, tuple[str, ...]] | None = None,
) -> None:
    """Store the signed bundles and the (personal-data) contact rows."""
    group_map = DEFAULT_GROUPS if groups is None else groups

    repo.put_bundle(
        "directory",
        org.directory_bundle["payload"]["version"],
        org.directory_bundle,
        org.issued_at,
    )
    repo.put_bundle(
        "policy",
        org.policy_bundle["payload"]["version"],
        org.policy_bundle,
        org.issued_at,
    )

    for person in org.people.values():
        repo.upsert_contact(
            person.person_id,
            name=person.name,
            phone=person.phone,
            site=site,
            groups=group_map.get(person.person_id, ()),
            wake_key=b64u_encode(person.wake_key),
            role=person.role,
        )

    if audit is None:
        return
    audit.append(
        Event.DIRECTORY_PUBLISHED,
        {
            "version": org.directory_bundle["payload"]["version"],
            "key_count": len(org.directory_bundle["payload"]["keys"]),
        },
    )
    audit.append(
        Event.POLICY_PUBLISHED,
        {
            "policy_id": org.policy_bundle["payload"]["policy_id"],
            "version": org.policy_bundle["payload"]["version"],
        },
    )
    for person in org.people.values():
        # Pseudonym and role only — no name, no phone. The chain is undeletable.
        audit.append(
            Event.KEY_ENROLLED,
            {"person_id": person.person_id, "key_id": person.key_id, "role": person.role},
        )
