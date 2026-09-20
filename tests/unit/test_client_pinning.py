"""Client-side pinning: the root key never moves, and versions only go up."""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidTag

from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.keystore import load_key, save_key
from alerting.core.directory import DirectoryPayload, DirectoryRejected, Revocation
from alerting.core.errors import Reason
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    generate_keypair,
    key_id,
    public_key_to_b64u,
)
from alerting.orgkit import sign_bundle
from tests.conftest import ISSUED_AT


@pytest.fixture
def cache(tmp_path, org) -> BundleCache:
    pin = PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), tmp_path / "home")
    pin.save()
    return BundleCache(pin)


def bump(org, version: int, revoked=()):
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    updated = payload.model_copy(update={"version": version, "revoked": tuple(revoked)})
    return sign_bundle(updated, DOMAIN_DIRECTORY, org.root_private_key)


def test_pin_survives_a_restart(tmp_path, org):
    home = tmp_path / "home"
    PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), home).save()
    restored = PinnedOrg.load(home)
    assert restored.org_id == org.org_id
    assert key_id(restored.root_public_key) == key_id(org.root_public_key)


def test_accepting_a_bundle_caches_it(cache, org):
    directory = cache.accept("directory", org.directory_bundle)
    assert directory.version == 1
    assert cache.directory().version == 1


def test_a_newer_version_is_accepted(cache, org):
    cache.accept("directory", org.directory_bundle)
    assert cache.accept("directory", bump(org, 5)).version == 5
    assert cache.seen_version("directory") == 5


def test_rollback_after_a_revocation_is_refused(cache, org):
    """The attack this exists for: serving yesterday's directory to resurrect a key
    that has since been revoked."""
    revoked_key = org.person("p-002").key_id
    cache.accept(
        "directory",
        bump(org, 2, [Revocation(key_id=revoked_key, revoked_at=ISSUED_AT)]),
    )
    assert cache.directory().is_revoked(revoked_key)

    with pytest.raises(DirectoryRejected) as exc:
        cache.accept("directory", org.directory_bundle)  # version 1
    assert exc.value.reason is Reason.DIRECTORY_ROLLBACK
    assert cache.directory().is_revoked(revoked_key), "cache untouched by the attempt"


def test_a_bundle_from_the_wrong_root_is_refused(cache, org):
    evil_root, _ = generate_keypair()
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    forged = sign_bundle(payload.model_copy(update={"version": 9}), DOMAIN_DIRECTORY, evil_root)
    with pytest.raises(DirectoryRejected) as exc:
        cache.accept("directory", forged)
    assert exc.value.reason is Reason.DIRECTORY_UNSIGNED


def test_cached_bundles_work_without_the_server(cache, org):
    """A device must be able to verify an order while the server is unreachable —
    which is the state it is most likely to be in during the incident that matters."""
    cache.accept("directory", org.directory_bundle)
    cache.accept("policy", org.policy_bundle)
    reopened = BundleCache(PinnedOrg.load(cache.home))
    assert reopened.directory().version == 1
    assert reopened.policy().policy_id == org.policy_bundle["payload"]["policy_id"]


def test_replay_state_survives_a_restart(cache):
    window = cache.replay_window()
    window.commit("primary", 7)
    cache.save_replay(window)
    reopened = BundleCache(PinnedOrg.load(cache.home))
    assert reopened.replay_window().check("primary", 7).value == "duplicate"


def test_seen_order_ids_persist(cache):
    cache.remember_order("o-1")
    assert "o-1" in BundleCache(PinnedOrg.load(cache.home)).seen_order_ids()


def test_key_file_roundtrip_and_wrong_passphrase(tmp_path):
    private, public = generate_keypair()
    path = save_key("p-001", private, "correct horse", role="director", directory=tmp_path)
    assert path.stat().st_mode & 0o077 == 0, "key file must not be group/world readable"

    loaded = load_key("p-001", "correct horse", directory=tmp_path)
    assert loaded.key_id == key_id(public)
    assert loaded.role == "director"

    with pytest.raises(InvalidTag):
        load_key("p-001", "wrong", directory=tmp_path)


def test_key_file_never_contains_the_private_key_in_the_clear(tmp_path):
    from alerting.core.signing import private_key_to_b64u

    private, _ = generate_keypair()
    path = save_key("p-001", private, "pass", directory=tmp_path)
    blob = json.loads(path.read_text(encoding="utf-8"))
    assert private_key_to_b64u(private) not in path.read_text(encoding="utf-8")
    assert blob["kdf"]["name"] == "scrypt"


def test_missing_key_file_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="no key for"):
        load_key("nobody", "pass", directory=tmp_path)


def test_reinspecting_an_order_the_device_already_holds_is_not_a_replay(cache, org):
    """The SMS wake-code check runs *after* the listener received the order.

    Judging that local re-inspection as a duplicate made the anti-phishing comparison
    unavailable in exactly the flow it exists for. Reported by an automated review on
    PR #1.
    """
    from alerting.clients.executor_cli import verify_one
    from alerting.core.errors import Reason
    from alerting.orgkit import make_order, sign_order

    cache.accept("directory", org.directory_bundle)
    cache.accept("policy", org.policy_bundle)

    order = make_order(org, issued_at=ISSUED_AT)
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")]).model_dump(mode="json")

    class _Clock:
        def now(self) -> int:
            return ISSUED_AT + 10

    import alerting.clients.executor_cli as cli

    original, cli.CLOCK = cli.CLOCK, _Clock()
    try:
        first = verify_one(cache, envelope)
        assert first.accepted, first.reasons

        # As delivery, the same envelope is now correctly a replay...
        again = verify_one(cache, envelope)
        assert again.rejected
        assert Reason.DUPLICATE_ORDER_ID in again.reasons

        # ...but re-inspecting what we already hold must still verify.
        reinspected = verify_one(cache, envelope, reinspect=True)
        assert reinspected.accepted, reinspected.reasons
        assert reinspected.payload is not None
        assert reinspected.payload.order_id == order.order_id
    finally:
        cli.CLOCK = original


def test_reinspection_leaves_replay_state_untouched(cache, org):
    from alerting.clients.executor_cli import verify_one
    from alerting.orgkit import make_order, sign_order

    cache.accept("directory", org.directory_bundle)
    cache.accept("policy", org.policy_bundle)
    order = make_order(org, issued_at=ISSUED_AT)
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")]).model_dump(mode="json")

    before = cache.replay_window().state()
    verify_one(cache, envelope, reinspect=True)
    assert cache.replay_window().state() == before
    assert order.order_id not in cache.seen_order_ids()
