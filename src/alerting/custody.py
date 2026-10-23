"""The custodians' side: the root key in a two-person vault, and signing requests.

The root key signs who may sign (the directory) and what may be ordered (the policy).
It lives on a laptop that never touches a network, opened by two custodians together
(docs/adr/0013-offline-root-custody.md). Everything crosses the air gap as a file:

* a **request**, made by the duty officer in the panel: the current signed bundles
  and a list of changes -- enrol this key, retire that one, a new codebook;
* an **answer**, made here: the next bundles, signed by the root.

Nothing in a request is trusted for arriving on a USB stick. The bundles in it are
verified against the root key in the vault before anything is shown, and every
change is displayed in full for the custodians to confirm.

A request whose bundles are signed by a *different* root is a migration: the
organisation moving to this vault's key. The custodians see that in red and must
confirm it on purpose; the answer then carries the people over unchanged.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from alerting.core.directory import (
    Directory,
    DirectoryPayload,
    Revocation,
    RevocationListPayload,
)
from alerting.core.policy import Policy, PolicyPayload
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_POLICY,
    b64u_decode,
    b64u_encode,
    generate_keypair,
    key_id,
    private_key_from_b64u,
    private_key_to_b64u,
    public_key_from_b64u,
    public_key_to_b64u,
)
from alerting.orgadmin import (
    DEFAULT_TTL_DAYS,
    _next,
    add_key,
    add_revoker,
    remove_revoker,
    retire_keys,
    revoke_keys,
)
from alerting.orgkit import sign_bundle

REQUEST_TYPE = "alerting-custody-request"
ANSWER_TYPE = "alerting-custody-answer"
VAULT_TYPE = "alerting-root-vault"

#: Per custodian. Each passphrase is stretched on its own, so neither alone narrows
#: the search for the other.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1
MIN_PASSPHRASE = 12
HKDF_INFO = b"alerting.root-vault.v1"

ROLES = ("executor", "duty_officer", "deputy", "director", "auditor")


class CustodyError(ValueError):
    """Something the custodians must see and decide on; never a crash."""


# --- the vault ------------------------------------------------------------------------


def _stretch(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _vault_key(passphrases: tuple[str, str], salts: tuple[bytes, bytes]) -> bytes:
    material = _stretch(passphrases[0], salts[0]) + _stretch(passphrases[1], salts[1])
    return HKDF(hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(material)


def _aad(org_id: str, public_key: str) -> bytes:
    return f"{VAULT_TYPE}|{org_id}|{public_key}".encode()


def create_vault(
    org_id: str, passphrases: tuple[str, str], names: tuple[str, str]
) -> tuple[dict[str, Any], Ed25519PrivateKey]:
    """A new root key, sealed so that it opens only with both passphrases."""
    if not org_id:
        raise CustodyError("укажите идентификатор организации")
    if any(len(p) < MIN_PASSPHRASE for p in passphrases):
        raise CustodyError(f"пароль каждого хранителя — не короче {MIN_PASSPHRASE} символов")
    if passphrases[0] == passphrases[1]:
        raise CustodyError("пароли хранителей должны различаться")
    if not all(n.strip() for n in names) or names[0].strip() == names[1].strip():
        raise CustodyError("укажите двух разных хранителей")
    private, public = generate_keypair()
    public_b64u = public_key_to_b64u(public)
    salts = (os.urandom(16), os.urandom(16))
    nonce = os.urandom(12)
    sealed = AESGCM(_vault_key(passphrases, salts)).encrypt(
        nonce, private_key_to_b64u(private).encode("ascii"), _aad(org_id, public_b64u)
    )
    vault = {
        "type": VAULT_TYPE,
        "v": 1,
        "org_id": org_id,
        "public_key": public_b64u,
        "key_id": key_id(public),
        "custodians": [names[0].strip(), names[1].strip()],
        "created_at": int(time.time()),
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salts": [b64u_encode(salts[0]), b64u_encode(salts[1])],
        "nonce": b64u_encode(nonce),
        "sealed": b64u_encode(sealed),
    }
    return vault, private


def check_vault(vault: Any) -> None:
    """The whole structure of a sealed vault, before it is trusted as one.

    Checked on restore, so a damaged backup is refused at the door instead of being
    written as the only vault and breaking the custodians' screen until someone edits
    the filesystem by hand. Says nothing about the passphrases -- only both can.
    """
    try:
        if not isinstance(vault, dict) or vault.get("type") != VAULT_TYPE or vault.get("v") != 1:
            raise ValueError("не файл корневого ключа")
        if not isinstance(vault.get("org_id"), str) or not vault["org_id"]:
            raise ValueError("нет организации")
        public = public_key_from_b64u(vault["public_key"])
        if key_id(public) != vault.get("key_id"):
            raise ValueError("идентификатор ключа не совпадает с ключом")
        names = vault.get("custodians")
        if not isinstance(names, list) or len(names) != 2 or not all(names):
            raise ValueError("должно быть два хранителя")
        if not isinstance(vault.get("created_at"), int):
            raise ValueError("нет даты создания")
        kdf = vault["kdf"]
        if (kdf.get("name"), kdf.get("n"), kdf.get("r"), kdf.get("p")) != (
            "scrypt",
            SCRYPT_N,
            SCRYPT_R,
            SCRYPT_P,
        ):
            raise ValueError("параметры шифрования не поддерживаются")
        salts = vault["salts"]
        if not (isinstance(salts, list) and len(salts) == 2):
            raise ValueError("нужны две соли")
        if any(len(b64u_decode(x)) != 16 for x in salts) or len(b64u_decode(vault["nonce"])) != 12:
            raise ValueError("повреждены параметры шифрования")
        if len(b64u_decode(vault["sealed"])) < 32:
            raise ValueError("нет зашифрованного ключа")
    except CustodyError:
        raise
    except Exception as exc:
        raise CustodyError(f"резервная копия повреждена: {exc}") from None


def open_vault(vault: dict[str, Any], passphrases: tuple[str, str]) -> Ed25519PrivateKey:
    """Both passphrases, or nothing. Which one was wrong is not said."""
    if vault.get("type") != VAULT_TYPE or vault.get("v") != 1:
        raise CustodyError("это не файл корневого ключа")
    kdf = vault["kdf"]
    if (kdf["n"], kdf["r"], kdf["p"]) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise CustodyError("параметры шифрования файла не поддерживаются")
    salts = (b64u_decode(vault["salts"][0]), b64u_decode(vault["salts"][1]))
    try:
        raw = AESGCM(_vault_key(passphrases, salts)).decrypt(
            b64u_decode(vault["nonce"]),
            b64u_decode(vault["sealed"]),
            _aad(vault["org_id"], vault["public_key"]),
        )
    except Exception:
        raise CustodyError("пароли не подходят") from None
    private = private_key_from_b64u(raw.decode("ascii"))
    if public_key_to_b64u(private.public_key()) != vault["public_key"]:
        raise CustodyError("файл корневого ключа повреждён")
    return private


def fingerprint(public_key: str) -> str:
    """The root key as the custodians' card prints it: the key id, in groups of four."""
    kid = key_id(public_key_from_b64u(public_key)).removeprefix("ed25519:")
    return " ".join(kid[i : i + 4] for i in range(0, len(kid), 4))


# --- requests -------------------------------------------------------------------------


class _Change(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AddKey(_Change):
    op: Literal["add_key"]
    person_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    name: str = Field(min_length=1, max_length=200)
    role: Literal["executor", "duty_officer", "deputy", "director", "auditor"]
    public_key: str = Field(min_length=40, max_length=64)
    valid_days: int | None = Field(default=None, ge=1, le=3650)


class _Selects(_Change):
    person_id: str | None = None
    key_id: str | None = None

    @model_validator(mode="after")
    def _one(self) -> _Selects:
        if bool(self.person_id) == bool(self.key_id):
            raise ValueError("name exactly one of person_id or key_id")
        return self


class Retire(_Selects):
    op: Literal["retire"]


class Revoke(_Selects):
    op: Literal["revoke"]
    reason: str = Field(min_length=1, max_length=500)


class AddRevoker(_Change):
    op: Literal["add_revoker"]
    public_key: str = Field(min_length=40, max_length=64)
    label: str = Field(min_length=1, max_length=200)


class RemoveRevoker(_Change):
    op: Literal["remove_revoker"]
    key_id: str
    #: ``absorb``: its revocations move into the directory. ``discard``: it was stolen
    #: and its list is not trusted -- genuine revocations are re-done by hand.
    fate: Literal["absorb", "discard"]


class AbsorbRevocations(_Change):
    """Fold the fast-path list into the directory, keeping the revocation key."""

    op: Literal["absorb_revocations"]


class PolicyChange(_Change):
    op: Literal["policy"]
    #: The whole new codebook; absent to only renew the policy's validity.
    scenarios: dict[str, Any] | None = None
    renew_days: int = Field(default=DEFAULT_TTL_DAYS, ge=1, le=3650)


Change = Annotated[
    AddKey | Retire | Revoke | AddRevoker | RemoveRevoker | AbsorbRevocations | PolicyChange,
    Field(discriminator="op"),
]
_CHANGES = TypeAdapter(list[Change])


def parse_changes(raw: Any) -> list[Any]:
    try:
        return list(_CHANGES.validate_python(raw))
    except Exception as exc:
        raise CustodyError(f"заявка содержит неверное изменение: {exc}") from None


def build_request(
    *,
    org_id: str,
    root_public_key: str,
    directory: dict[str, Any],
    policy: dict[str, Any],
    revocations: dict[str, Any] | None,
    changes: list[dict[str, Any]],
    created_by: str,
    created_at: int,
) -> dict[str, Any]:
    """What the duty officer carries to the custodians."""
    parsed = parse_changes(changes)
    if not parsed:
        raise CustodyError("в заявке нет изменений")
    return {
        "type": REQUEST_TYPE,
        "v": 1,
        "org_id": org_id,
        # The root the panel trusts today. Used only to recognise a migration.
        "root_public_key": root_public_key,
        "created_by": created_by,
        "created_at": created_at,
        "directory": directory,
        "policy": policy,
        "revocations": revocations or None,
        "changes": [c.model_dump(exclude_none=True) for c in parsed],
    }


# --- review and signing ---------------------------------------------------------------


@dataclass
class Review:
    org_id: str
    migrating: bool
    previous_root: str | None
    directory_version: int
    policy_version: int
    created_by: str
    created_at: int
    changes: list[str]
    people: list[dict[str, Any]] = field(default_factory=list)


def _load(request: dict[str, Any], vault: dict[str, Any]) -> tuple[Directory, Policy, bool, str]:
    if request.get("type") != REQUEST_TYPE or request.get("v") != 1:
        raise CustodyError("это не заявка для хранителей")
    if request.get("org_id") != vault["org_id"]:
        raise CustodyError(
            f"заявка организации {request.get('org_id')!r}, а ключ — {vault['org_id']!r}"
        )
    own = vault["public_key"]
    claimed = str(request.get("root_public_key") or "")
    migrating = claimed != own
    root = public_key_from_b64u(claimed if migrating else own)
    try:
        directory = Directory.load(
            request["directory"], root_public_key=root, org_id=vault["org_id"]
        ).with_revocations(request.get("revocations") or None)
        policy = Policy.load(request["policy"], root_public_key=root, org_id=vault["org_id"])
    except Exception as exc:
        raise CustodyError(
            "справочник или политика в заявке не подписаны "
            + ("прежним корневым ключом" if migrating else "этим корневым ключом")
            + f": {exc}. Файл подменён или заявка не от этой организации."
        ) from None
    return directory, policy, migrating, claimed


def describe(change: Any, directory: Directory) -> str:
    names = {e.person_id: e.name for e in directory.payload.keys}

    def who(c: Any) -> str:
        if c.person_id:
            return f"{c.person_id} ({names.get(c.person_id, 'нет в справочнике')})"
        return f"ключ {c.key_id}"

    if isinstance(change, AddKey):
        kid = key_id(public_key_from_b64u(change.public_key))
        term = f", на {change.valid_days} дн." if change.valid_days else ""
        return f"ДОБАВИТЬ {change.person_id} «{change.name}», роль {change.role}, ключ {kid}{term}"
    if isinstance(change, Retire):
        return f"ВЫВЕСТИ {who(change)}: прежние подписи в силе, новых нет"
    if isinstance(change, Revoke):
        return f"ОТОЗВАТЬ {who(change)}: недействительны все подписи. Причина: {change.reason}"
    if isinstance(change, AddRevoker):
        kid = key_id(public_key_from_b64u(change.public_key))
        return f"КЛЮЧ ОТЗЫВА: добавить {kid} «{change.label}» — сможет только отзывать"
    if isinstance(change, RemoveRevoker):
        fate = (
            "его отзывы переносятся в справочник"
            if change.fate == "absorb"
            else "его список отзывов отбрасывается (ключ украден)"
        )
        return f"КЛЮЧ ОТЗЫВА: убрать {change.key_id}; {fate}"
    if isinstance(change, AbsorbRevocations):
        listed = directory.revocations.entries if directory.revocations else ()
        return f"ПЕРЕНЕСТИ быстрые отзывы в справочник: {len(listed)} шт."
    if isinstance(change, PolicyChange):
        return (
            "ПОЛИТИКА: "
            + (
                f"новая кодовая книга ({len(change.scenarios)} событий), "
                if change.scenarios is not None
                else ""
            )
            + f"срок действия {change.renew_days} дн."
        )
    raise CustodyError(f"неизвестное изменение {change!r}")


def review(request: dict[str, Any], vault: dict[str, Any]) -> Review:
    directory, policy, migrating, claimed = _load(request, vault)
    changes = parse_changes(request.get("changes"))
    lines = [describe(c, directory) for c in changes]
    revoked = {r.key_id for r in directory.payload.revoked} | {
        r.key_id for r in (directory.revocations.entries if directory.revocations else ())
    }
    people = [
        {
            "person_id": e.person_id,
            "name": e.name,
            "role": e.role,
            "key_id": e.key_id,
            "state": "отозван" if e.key_id in revoked else ("выведен" if e.valid_until else ""),
        }
        for e in sorted(directory.payload.keys, key=lambda e: (e.person_id, e.valid_from))
    ]
    return Review(
        org_id=vault["org_id"],
        migrating=migrating,
        previous_root=claimed if migrating else None,
        directory_version=directory.version,
        policy_version=policy.version,
        created_by=str(request.get("created_by", "")),
        created_at=int(request.get("created_at", 0)),
        changes=lines,
        people=people,
    )


def sign_answer(
    request: dict[str, Any],
    vault: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    now: int,
    confirm_migration: bool = False,
) -> dict[str, Any]:
    """Apply the changes and sign the next bundles with the root key."""
    if public_key_to_b64u(private_key.public_key()) != vault["public_key"]:
        raise CustodyError("открыт не тот корневой ключ")
    directory, policy, migrating, claimed = _load(request, vault)
    if migrating and not confirm_migration:
        raise CustodyError("это перенос на новый корневой ключ — подтвердите его явно")
    changes = parse_changes(request.get("changes"))

    current: DirectoryPayload = directory.payload
    listed: RevocationListPayload | None = directory.revocations
    directory_changed = False
    new_policy: PolicyPayload | None = None
    for change in changes:
        directory_changed |= not isinstance(change, PolicyChange)
        try:
            current = _apply(current, change, listed, request, now)
        except CustodyError:
            raise
        except Exception as exc:
            raise CustodyError(f"{describe(change, directory)} — невозможно: {exc}") from None
        if isinstance(change, PolicyChange):
            new_policy = _next_policy(new_policy or policy.payload, change, now)

    bundles: dict[str, Any] = {}
    if directory_changed or migrating:
        if not directory_changed:
            current = _next(current, keys=current.keys, revoked=current.revoked, issued_at=now)
        bundles["directory"] = sign_bundle(current, DOMAIN_DIRECTORY, private_key)
    if new_policy is None and migrating:
        # Re-signed under the new root, unchanged otherwise: the old root's signature
        # stops counting once devices pin the new one.
        new_policy = policy.payload.model_copy(
            update={"version": policy.version + 1, "issued_at": now}
        )
    if new_policy is not None:
        bundles["policy"] = sign_bundle(new_policy, DOMAIN_POLICY, private_key)

    return {
        "type": ANSWER_TYPE,
        "v": 1,
        "org_id": vault["org_id"],
        "root_public_key": vault["public_key"],
        "root_fingerprint": fingerprint(vault["public_key"]),
        "migration": migrating,
        **({"previous_root": claimed} if migrating else {}),
        "signed_at": now,
        "summary": [describe(c, directory) for c in changes],
        "bundles": bundles,
    }


def _apply(
    current: DirectoryPayload,
    change: Any,
    listed: RevocationListPayload | None,
    request: dict[str, Any],
    now: int,
) -> DirectoryPayload:
    fast = frozenset(r.key_id for r in (listed.entries if listed else ()))
    if isinstance(change, AddKey):
        payload, _ = add_key(
            current,
            person_id=change.person_id,
            name=change.name,
            role=change.role,
            public_key=change.public_key,
            issued_at=now,
            valid_days=change.valid_days,
        )
        return payload
    if isinstance(change, Retire):
        payload, _ = retire_keys(current, person_id=change.person_id, kid=change.key_id, at=now)
        return payload
    if isinstance(change, Revoke):
        if change.key_id and change.key_id in fast:
            raise CustodyError(
                f"ключ {change.key_id} уже отозван быстрым путём — перенесите отзывы"
            )
        payload, _ = revoke_keys(
            current, person_id=change.person_id, kid=change.key_id, at=now, reason=change.reason
        )
        return payload
    if isinstance(change, AddRevoker):
        payload, _ = add_revoker(
            current, public_key=change.public_key, label=change.label, issued_at=now
        )
        return payload
    if isinstance(change, RemoveRevoker):
        absorb = request.get("revocations") if change.fate == "absorb" else None
        if change.fate == "absorb" and listed is not None and listed.signer != change.key_id:
            absorb = None  # the list belongs to another revocation key; nothing to fold
        payload, _ = remove_revoker(current, kid=change.key_id, absorb=absorb, issued_at=now)
        return payload
    if isinstance(change, AbsorbRevocations):
        already = {r.key_id for r in current.revoked}
        folded = [
            Revocation(key_id=r.key_id, revoked_at=r.revoked_at, reason=r.reason)
            for r in (listed.entries if listed else ())
            if r.key_id not in already
        ]
        if not folded:
            raise CustodyError("быстрых отзывов, которых нет в справочнике, нет")
        return _next(current, keys=current.keys, revoked=(*current.revoked, *folded), issued_at=now)
    return current  # a policy change does not touch the directory


def _next_policy(base: PolicyPayload, change: PolicyChange, now: int) -> PolicyPayload:
    body = base.to_payload()
    if change.scenarios is not None:
        body["scenarios"] = change.scenarios
    body.update(
        version=base.version + 1,
        issued_at=now,
        not_valid_after=now + change.renew_days * 86400,
    )
    try:
        return PolicyPayload.model_validate(body)
    except Exception as exc:
        raise CustodyError(f"новая политика неверна: {exc}") from None


# --- answers, on the networked side ---------------------------------------------------


def read_answer(answer: dict[str, Any], *, org_id: str) -> dict[str, Any]:
    """The bundles in an answer, after the shape checks. Signatures are checked by
    whoever publishes them -- the server, against the root it trusts."""
    if answer.get("type") != ANSWER_TYPE or answer.get("v") != 1:
        raise CustodyError("это не ответ хранителей")
    if answer.get("org_id") != org_id:
        raise CustodyError(f"ответ для организации {answer.get('org_id')!r}")
    bundles = answer.get("bundles")
    if not isinstance(bundles, dict) or not bundles:
        raise CustodyError("в ответе нет подписанных пакетов")
    unknown = set(bundles) - {"directory", "policy"}
    if unknown:
        raise CustodyError(f"в ответе неизвестные пакеты: {sorted(unknown)}")
    return bundles
