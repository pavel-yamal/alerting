"""Revocation keys: a fast path that can only revoke.

The root key is offline with two custodians; a stolen phone cannot wait for them. A
revocation key named in the directory signs revocation lists and nothing else.
"""

from __future__ import annotations

import pytest

from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.core.directory import (
    Directory,
    DirectoryPayload,
    DirectoryRejected,
    RevocationListPayload,
    Revoker,
)
from alerting.core.errors import Reason
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_REVOCATIONS,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgadmin import (
    add_key,
    add_revoker,
    next_revocations,
    remove_revoker,
    verified_current,
)
from alerting.orgkit import Org, sign_bundle
from tests.conftest import ISSUED_AT

AT = ISSUED_AT + 100


def with_revoker(org: Org):
    """The org's directory v2, naming one revocation key. Returns (bundle, private)."""
    private, public = generate_keypair()
    current = verified_current(org.directory_bundle, public_key_to_b64u(org.root_public_key))
    payload, _ = add_revoker(
        current, public_key=public_key_to_b64u(public), label="смена", issued_at=AT
    )
    return sign_bundle(payload, DOMAIN_DIRECTORY, org.root_private_key), private


def load(org: Org, bundle) -> Directory:
    return Directory.load(bundle, root_public_key=org.root_public_key, org_id=org.org_id)


def revocation_list(directory: Directory, private, latest=None, *, person="x-101", at=AT):
    payload, _ = next_revocations(
        directory, latest, signer=key_id(private.public_key()), person_id=person, kid=None,
        at=at, reason="утерян",
    )  # fmt: skip
    raw = payload.to_payload()
    return {"payload": raw, "signature": sign_payload(DOMAIN_REVOCATIONS, raw, private)}


def test_a_list_from_a_named_revocation_key_revokes(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    kid = org.person("x-101").key_id
    assert directory.signer_status(kid, AT) is None

    applied = directory.with_revocations(revocation_list(directory, private))
    assert applied.signer_status(kid, AT) == Reason.REVOKED_SIGNER
    assert applied.signer_status(kid, AT - 3000) == Reason.REVOKED_SIGNER, "every signature"
    assert applied.revocation(kid).reason == "утерян"


def test_a_forged_or_foreign_list_is_refused(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    good = revocation_list(directory, private)

    forged = {**good, "signature": revocation_list(directory, private, person="x-102")["signature"]}
    with pytest.raises(DirectoryRejected) as refused:
        directory.with_revocations(forged)
    assert refused.value.reason == Reason.REVOCATIONS_UNSIGNED

    foreign = {**good, "payload": {**good["payload"], "org_id": "other"}}
    with pytest.raises(DirectoryRejected) as refused:
        directory.with_revocations(foreign)
    assert refused.value.reason == Reason.ORG_MISMATCH


def test_a_list_cannot_be_rolled_back(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    first = revocation_list(directory, private)
    with pytest.raises(DirectoryRejected) as refused:
        directory.with_revocations(first, min_version=2)
    assert refused.value.reason == Reason.REVOCATIONS_ROLLBACK


def test_a_key_the_directory_does_not_name_revokes_nothing(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    stranger, _ = generate_keypair()
    payload = RevocationListPayload(
        v=1, type="revocations", org_id=org.org_id, version=1, issued_at=AT,
        signer=key_id(stranger.public_key()),
        entries=revocation_list(directory, private)["payload"]["entries"],
    ).to_payload()  # fmt: skip
    listed = {"payload": payload, "signature": sign_payload(DOMAIN_REVOCATIONS, payload, stranger)}
    applied = directory.with_revocations(listed)
    assert applied.revocations is None
    assert applied.signer_status(org.person("x-101").key_id, AT) is None


def test_old_directories_without_the_field_stay_canonical(org):
    assert "revokers" not in org.directory_bundle["payload"]
    assert load(org, org.directory_bundle).revokers == {}


def test_a_revoker_entry_must_match_its_key():
    _, public = generate_keypair()
    _, other = generate_keypair()
    with pytest.raises(ValueError, match="does not match"):
        Revoker(key_id=key_id(other), public_key=public_key_to_b64u(public), label="x")


def test_later_root_changes_keep_the_revocation_key(org):
    bundle, _ = with_revoker(org)
    current = DirectoryPayload.model_validate(bundle["payload"])
    _, public = generate_keypair()
    payload, _ = add_key(
        current, person_id="x-104", name="Новиков", role="executor",
        public_key=public_key_to_b64u(public), issued_at=AT,
    )  # fmt: skip
    assert payload.revokers == current.revokers


def test_lists_are_cumulative(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    first = revocation_list(directory, private)
    second = revocation_list(directory.with_revocations(first), private, first, person="x-102")
    assert second["payload"]["version"] == 2
    revoked = {e["key_id"] for e in second["payload"]["entries"]}
    assert revoked == {org.person("x-101").key_id, org.person("x-102").key_id}
    with pytest.raises(ValueError, match="no live key"):
        revocation_list(directory.with_revocations(first), private, first, person="x-101")


def test_removing_a_revocation_key_absorbs_or_discards_its_list(org):
    bundle, private = with_revoker(org)
    directory = load(org, bundle)
    listed = revocation_list(directory, private)
    kid = key_id(private.public_key())

    absorbed, folded = remove_revoker(directory.payload, kid=kid, absorb=listed, issued_at=AT)
    assert [r.key_id for r in folded] == [org.person("x-101").key_id]
    assert absorbed.revokers == ()
    kept = Directory(absorbed).with_revocations(listed)
    assert kept.is_revoked(org.person("x-101").key_id), "kept by the root itself now"

    discarded, _ = remove_revoker(directory.payload, kid=kid, absorb=None, issued_at=AT)
    assert (
        not Directory(discarded).with_revocations(listed).is_revoked(org.person("x-101").key_id)
    ), "a stolen revocation key's list stops counting"

    tampered = {
        **listed,
        "signature": revocation_list(directory, private, person="x-102")["signature"],
    }
    with pytest.raises(ValueError, match="does not verify"):
        remove_revoker(directory.payload, kid=kid, absorb=tampered, issued_at=AT)


# --- the device side ------------------------------------------------------------------


@pytest.fixture
def cache(tmp_path, org) -> BundleCache:
    pin = PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), tmp_path / "home")
    pin.save()
    return BundleCache(pin)


def test_a_device_applies_the_list_and_keeps_it(cache, org):
    bundle, private = with_revoker(org)
    cache.accept("directory", bundle)
    listed = revocation_list(load(org, bundle), private)
    kid = org.person("x-101").key_id

    assert cache.accept("revocations", listed).is_revoked(kid)
    assert cache.accept("revocations", {}).is_revoked(kid), "withheld: keep what we hold"
    assert cache.directory().is_revoked(kid), "and offline"
    assert cache.accept("directory", bundle).is_revoked(kid), "a re-fetched directory too"


def test_a_device_refuses_an_older_list(cache, org):
    bundle, private = with_revoker(org)
    cache.accept("directory", bundle)
    directory = load(org, bundle)
    first = revocation_list(directory, private)
    second = revocation_list(directory.with_revocations(first), private, first, person="x-102")
    cache.accept("revocations", second)
    with pytest.raises(DirectoryRejected):
        cache.accept("revocations", first)
