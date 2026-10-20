"""The org key directory: who may sign, in what role, and who has been revoked.

This bundle is signed by the **org root key**, which every client pins at enrollment.
That pinning is what makes client-side verification real rather than decorative: without
it a compromised server would simply serve a directory containing its own key.

The root key signs directories and policies. It never signs orders.

Revocation has a second, narrower path. The root key lives offline with two custodians,
which no 60-second revocation target survives. So the directory may name **revocation
keys**: each can sign a revocation list -- key ids to stop trusting, nothing else. It
cannot enroll a key, extend one, or touch the policy; the worst a stolen one can do is
revoke people, which is loud, and the root ends it by dropping that key from the next
directory. See docs/02-trust-and-approval.md §4.
"""

from __future__ import annotations

from typing import Any, Literal, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictInt, StrictStr, model_validator

from alerting.core.envelope import CanonicalModel, Identifier, Seq
from alerting.core.errors import Reason
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_REVOCATIONS,
    key_id,
    public_key_from_b64u,
    verify_signature,
)

#: Past this age a directory is still used, but the client shows a "stale roster"
#: banner. Refusing to verify would hand an attacker a suppression primitive.
STALE_DIRECTORY_S = 7 * 24 * 3600


class KeyEntry(CanonicalModel):
    """One enrolled signing key belonging to one person on one device."""

    key_id: Identifier
    public_key: Identifier
    person_id: Identifier
    name: StrictStr = Field(max_length=200)
    role: Identifier
    valid_from: StrictInt = Field(ge=0)
    valid_until: StrictInt | None = Field(default=None, ge=0)

    def public(self) -> Ed25519PublicKey:
        return public_key_from_b64u(self.public_key)

    def is_valid_at(self, when: int) -> bool:
        if when < self.valid_from:
            return False
        return self.valid_until is None or when <= self.valid_until


class Revocation(CanonicalModel):
    key_id: Identifier
    revoked_at: StrictInt = Field(ge=0)
    reason: StrictStr = Field(default="", max_length=500)


class Revoker(CanonicalModel):
    """A key that may sign revocation lists and nothing else."""

    key_id: Identifier
    public_key: Identifier
    label: StrictStr = Field(max_length=200)

    def public(self) -> Ed25519PublicKey:
        return public_key_from_b64u(self.public_key)

    @model_validator(mode="after")
    def _key_id_matches(self) -> Self:
        if key_id(public_key_from_b64u(self.public_key)) != self.key_id:
            raise ValueError("revoker key_id does not match its public key")
        return self


class DirectoryPayload(CanonicalModel):
    v: Literal[1]
    type: Literal["directory"]
    org_id: Identifier
    version: StrictInt = Field(ge=1)
    issued_at: StrictInt = Field(ge=0)
    keys: Seq[KeyEntry]
    revoked: Seq[Revocation] = ()
    #: Absent rather than empty in directories that never had one, so bundles signed
    #: before this field existed stay byte-for-byte canonical.
    revokers: Seq[Revoker] | None = None

    @model_validator(mode="after")
    def _unique_key_ids(self) -> Self:
        ids = [entry.key_id for entry in self.keys]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate key_id in directory")
        return self


class RevocationListPayload(CanonicalModel):
    """Key ids to stop trusting, signed by a revocation key the directory names.

    Cumulative: each version carries every entry of the one before, so the newest
    list is the whole answer and a device that refuses lower versions cannot be
    rolled back to a list without yesterday's revocation.
    """

    v: Literal[1]
    type: Literal["revocations"]
    org_id: Identifier
    version: StrictInt = Field(ge=1)
    issued_at: StrictInt = Field(ge=0)
    signer: Identifier
    entries: Seq[Revocation] = ()


class Directory:
    """A verified directory, ready to answer 'may this key_id sign, right now?'."""

    def __init__(
        self, payload: DirectoryPayload, revocations: RevocationListPayload | None = None
    ) -> None:
        self.payload = payload
        self.revocations = revocations
        self._by_key_id = {entry.key_id: entry for entry in payload.keys}
        extra = revocations.entries if revocations else ()
        self._revoked = {rev.key_id: rev for rev in (*extra, *payload.revoked)}

    @property
    def org_id(self) -> str:
        return self.payload.org_id

    @property
    def version(self) -> int:
        return self.payload.version

    @property
    def issued_at(self) -> int:
        return self.payload.issued_at

    def lookup(self, key_id: str) -> KeyEntry | None:
        return self._by_key_id.get(key_id)

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

    def revocation(self, key_id: str) -> Revocation | None:
        return self._revoked.get(key_id)

    @property
    def revokers(self) -> dict[str, Revoker]:
        return {r.key_id: r for r in self.payload.revokers or ()}

    def with_revocations(self, bundle: dict[str, Any] | None, *, min_version: int = 0) -> Directory:
        """This directory, plus the revocation list if a current revocation key signed it.

        A list whose signer this directory no longer names is ignored, not refused: the
        root dropped that key, and the root's word is the newer one. Custodians fold
        what they want to keep into ``revoked`` when they drop it (``alerting-org
        directory revoker --remove``). Anything else wrong with the list -- forged,
        another org, lower than a version already seen -- raises.
        """
        if not bundle:
            return self
        signature = bundle.get("signature")
        payload_raw = bundle.get("payload")
        if not isinstance(payload_raw, dict) or not isinstance(signature, str):
            raise DirectoryRejected(Reason.MALFORMED)
        payload = RevocationListPayload.model_validate(payload_raw)
        if payload.to_payload() != payload_raw:
            raise DirectoryRejected(Reason.NOT_CANONICAL)
        if payload.org_id != self.org_id:
            raise DirectoryRejected(Reason.ORG_MISMATCH)
        if payload.version < min_version:
            raise DirectoryRejected(Reason.REVOCATIONS_ROLLBACK)
        revoker = self.revokers.get(payload.signer)
        if revoker is None:
            return Directory(self.payload)
        if not verify_signature(DOMAIN_REVOCATIONS, payload_raw, signature, revoker.public()):
            raise DirectoryRejected(Reason.REVOCATIONS_UNSIGNED)
        return Directory(self.payload, payload)

    def signer_status(self, key_id: str, when: int) -> Reason | None:
        """``None`` means the key may sign. Otherwise the reason it may not."""
        entry = self._by_key_id.get(key_id)
        if entry is None:
            return Reason.UNKNOWN_SIGNER
        if key_id in self._revoked:
            return Reason.REVOKED_SIGNER
        if not entry.is_valid_at(when):
            return Reason.REVOKED_SIGNER
        return None

    def is_stale(self, now: int) -> bool:
        return now - self.payload.issued_at > STALE_DIRECTORY_S

    @classmethod
    def load(
        cls,
        bundle: dict[str, Any],
        *,
        root_public_key: Ed25519PublicKey,
        org_id: str,
        min_version: int = 0,
    ) -> Directory:
        """Verify a bundle against the pinned root key and return it.

        Raises ``DirectoryRejected`` with a typed reason; callers turn that into a
        ``Decision``. Version monotonicity is enforced here so that a server cannot
        roll a client back to a directory that still contains a revoked key.
        """
        signature = bundle.get("signature")
        payload_raw = bundle.get("payload")
        if not isinstance(payload_raw, dict) or not isinstance(signature, str):
            raise DirectoryRejected(Reason.MALFORMED)

        payload = DirectoryPayload.model_validate(payload_raw)
        if payload.to_payload() != payload_raw:
            raise DirectoryRejected(Reason.NOT_CANONICAL)
        if payload.org_id != org_id:
            raise DirectoryRejected(Reason.ORG_MISMATCH)
        if not verify_signature(DOMAIN_DIRECTORY, payload_raw, signature, root_public_key):
            raise DirectoryRejected(Reason.DIRECTORY_UNSIGNED)
        if payload.version < min_version:
            raise DirectoryRejected(Reason.DIRECTORY_ROLLBACK)
        return cls(payload)


class DirectoryRejected(Exception):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason
