"""Build a complete, self-consistent organisation: root key, people, directory, policy.

Used by ``scripts/org_init.py`` for the demo and by the test suite. Keeping one
implementation means the demo exercises the same bundle construction the tests assert
on, rather than a parallel fixture that can drift.

Real enrollment is nothing like this: keys are generated on each person's device and
the public key is read back in person against photo ID (see docs/02-trust-and-approval.md).
This module exists so that a reviewer can get a working org in one command.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alerting.core.directory import DirectoryPayload, KeyEntry
from alerting.core.envelope import (
    Action,
    Audience,
    OrderPayload,
    Severity,
    Signature,
    SignedEnvelope,
)
from alerting.core.policy import PolicyPayload, QuorumRule, ScenarioRule, SeverityRules
from alerting.core.signing import (
    ALG_ED25519,
    DOMAIN_DIRECTORY,
    DOMAIN_ORDER,
    DOMAIN_POLICY,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)

DEFAULT_POLICY_ID = "demo-policy-2026-01"
DEFAULT_ORG = "acme"


@dataclass
class Person:
    person_id: str
    name: str
    role: str
    private_key: Ed25519PrivateKey
    key_id: str
    wake_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    phone: str = ""


@dataclass
class Org:
    org_id: str
    root_private_key: Ed25519PrivateKey
    people: dict[str, Person]
    directory_bundle: dict[str, Any]
    policy_bundle: dict[str, Any]
    issued_at: int

    @property
    def root_public_key(self) -> Any:
        return self.root_private_key.public_key()

    def person(self, person_id: str) -> Person:
        return self.people[person_id]

    def approvers(self) -> list[Person]:
        return [p for p in self.people.values() if p.role in _APPROVER_ROLES]

    def executors(self) -> list[Person]:
        return [p for p in self.people.values() if p.role == "executor"]


#: Roles that may approve orders. Executors are deliberately absent: their device
#: keys exist to sign ACKs, and counting them toward a quorum would let two executors
#: launch a critical evacuation.
APPROVER_ROLES: tuple[str, ...] = ("director", "deputy", "duty_officer")

_APPROVER_ROLES = frozenset(APPROVER_ROLES)

#: The codebook. The scenario code is the actionable unit; free text is advisory.
DEFAULT_SCENARIOS: dict[str, ScenarioRule] = {
    "EVAC.BUILDING": ScenarioRule(
        min_severity=Severity.CRITICAL,
        description="Полная эвакуация здания",
        card="Выйти по ближайшему маршруту, пункт сбора по схеме на карточке. "
        "Вернуться только по отбою.",
        until_cancelled=True,
    ),
    "SHELTER.IN.PLACE": ScenarioRule(
        min_severity=Severity.CRITICAL,
        description="Укрытие на месте, не выходить",
        card="Закрыть окна, остаться внутри, ждать отбоя.",
        until_cancelled=True,
    ),
    "MUSTER": ScenarioRule(
        min_severity=Severity.WARNING,
        description="Сбор на пункте сбора",
        card="Прибыть на пункт сбора, доложить старшему.",
    ),
    "STAND.BY": ScenarioRule(
        max_severity=Severity.WARNING,
        description="Повышенная готовность",
        card="Быть на связи, не покидать площадку.",
        until_cancelled=True,
    ),
    "TEST.PING": ScenarioRule(
        max_severity=Severity.INFO,
        description="Технический тест канала",
        card="Действий не требуется. Подтвердить получение.",
    ),
}

#: Cancel quorum is deliberately one below launch: the safe direction is stopping.
#: See docs/adr/0003-cancel-quorum.md for the argument and its four guardrails.
DEFAULT_SEVERITIES: dict[Severity, SeverityRules] = {
    Severity.INFO: SeverityRules(launch=QuorumRule(m=1), cancel=QuorumRule(m=1)),
    Severity.WARNING: SeverityRules(launch=QuorumRule(m=1), cancel=QuorumRule(m=1)),
    Severity.CRITICAL: SeverityRules(
        launch=QuorumRule(m=2, max_signature_spread_s=300, distinct_persons=True),
        cancel=QuorumRule(m=1),
    ),
    Severity.CATASTROPHIC: SeverityRules(
        launch=QuorumRule(
            m=3,
            max_signature_spread_s=600,
            distinct_persons=True,
            min_from_role={"director": 1},
        ),
        cancel=QuorumRule(m=2),
    ),
}

DEFAULT_ROSTER: list[tuple[str, str, str]] = [
    ("p-001", "Смирнов А. В.", "director"),
    ("p-002", "Кузнецова Е. П.", "deputy"),
    ("p-003", "Орлов Д. С.", "duty_officer"),
    ("p-004", "Белова М. И.", "duty_officer"),
    ("x-101", "Иванов И. И.", "executor"),
    ("x-102", "Петрова О. Н.", "executor"),
    ("x-103", "Сидоров П. А.", "executor"),
    # docs/02-trust-and-approval.md §1 has listed the auditor as a directory role
    # since the beginning; it simply had no entry. Reading the chain over HTTP is a
    # signed request like any other, so the role had to become real.
    ("a-001", "Ковалёва Н. Т.", "auditor"),
]


def build_org(
    *,
    org_id: str = DEFAULT_ORG,
    issued_at: int = 1_700_000_000,
    roster: list[tuple[str, str, str]] | None = None,
    policy_id: str = DEFAULT_POLICY_ID,
    policy_ttl_s: int = 365 * 24 * 3600,
    directory_version: int = 1,
    policy_version: int = 1,
    approver_roles: tuple[str, ...] = APPROVER_ROLES,
) -> Org:
    """Create an organisation with a fresh root key and a signed directory and policy."""
    root_private, _ = generate_keypair()
    people: dict[str, Person] = {}
    entries: list[KeyEntry] = []

    for index, (person_id, name, role) in enumerate(roster or DEFAULT_ROSTER):
        private, public = generate_keypair()
        kid = key_id(public)
        people[person_id] = Person(
            person_id=person_id,
            name=name,
            role=role,
            private_key=private,
            key_id=kid,
            phone=f"+7900000{index:04d}",
        )
        entries.append(
            KeyEntry(
                key_id=kid,
                public_key=public_key_to_b64u(public),
                person_id=person_id,
                name=name,
                role=role,
                valid_from=issued_at - 3600,
            )
        )

    directory = DirectoryPayload(
        v=1,
        type="directory",
        org_id=org_id,
        version=directory_version,
        issued_at=issued_at,
        keys=tuple(entries),
    )
    policy = PolicyPayload(
        v=1,
        type="policy",
        org_id=org_id,
        policy_id=policy_id,
        version=policy_version,
        issued_at=issued_at,
        not_valid_after=issued_at + policy_ttl_s,
        approver_roles=approver_roles,
        severities=dict(DEFAULT_SEVERITIES),
        scenarios=dict(DEFAULT_SCENARIOS),
    )

    return Org(
        org_id=org_id,
        root_private_key=root_private,
        people=people,
        directory_bundle=sign_bundle(directory, DOMAIN_DIRECTORY, root_private),
        policy_bundle=sign_bundle(policy, DOMAIN_POLICY, root_private),
        issued_at=issued_at,
    )


def sign_bundle(
    payload: DirectoryPayload | PolicyPayload,
    domain: bytes,
    root_private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Wrap a bundle payload with its root signature."""
    raw = payload.to_payload()
    return {"payload": raw, "signature": sign_payload(domain, raw, root_private_key)}


def make_order(
    org: Org,
    *,
    scenario: str = "EVAC.BUILDING",
    severity: Severity = Severity.CRITICAL,
    drill: bool = False,
    seq: int = 1,
    issued_at: int | None = None,
    ttl_s: int = 900,
    action: Action = Action.START,
    audience: Audience | None = None,
    text: str = "",
    order_type: str = "order",
    cancels: str | None = None,
    stream_id: str = "primary",
    order_id: str | None = None,
    policy_id: str | None = None,
) -> OrderPayload:
    """Build an unsigned order payload with demo-sensible defaults."""
    at = org.issued_at if issued_at is None else issued_at
    return OrderPayload(
        v=1,
        type=order_type,  # type: ignore[arg-type]
        order_id=order_id or str(uuid.uuid4()),
        org_id=org.org_id,
        stream_id=stream_id,
        seq=seq,
        nonce=secrets.token_urlsafe(16),
        issued_at=at,
        not_valid_after=at + ttl_s,
        severity=severity,
        drill=drill,
        scenario=scenario,
        action=action,
        audience=audience or Audience(sites=("hq",), groups=("fire-wardens",)),
        text=text,
        policy_id=policy_id or org.policy_bundle["payload"]["policy_id"],
        cancels=cancels,
    )


def sign_order(
    payload: OrderPayload, signers: list[Person], org: Org | None = None
) -> SignedEnvelope:
    """Attach detached approver signatures to a payload."""
    raw = payload.to_payload()
    signatures = tuple(
        Signature(
            key_id=person.key_id,
            alg=ALG_ED25519,
            sig=sign_payload(DOMAIN_ORDER, raw, person.private_key),
        )
        for person in signers
    )
    return SignedEnvelope(payload=raw, signatures=signatures)
