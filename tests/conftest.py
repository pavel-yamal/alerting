"""Shared fixtures: one demo organisation, verified bundles, a fixed clock."""

from __future__ import annotations

import pytest

from alerting.core.clock import FixedClock
from alerting.core.directory import Directory
from alerting.core.policy import Policy
from alerting.core.replay import ReplayWindow
from alerting.orgkit import Org, build_org

ISSUED_AT = 1_700_000_000


@pytest.fixture
def org() -> Org:
    return build_org(issued_at=ISSUED_AT)


@pytest.fixture
def directory(org: Org) -> Directory:
    return Directory.load(
        org.directory_bundle, root_public_key=org.root_public_key, org_id=org.org_id
    )


@pytest.fixture
def policy(org: Org) -> Policy:
    return Policy.load(
        org.policy_bundle, root_public_key=org.root_public_key, org_id=org.org_id
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(ISSUED_AT + 10)


@pytest.fixture
def replay() -> ReplayWindow:
    return ReplayWindow()


@pytest.fixture
def verify_kwargs(org, directory, policy, clock, replay) -> dict:
    """Everything ``verify_envelope`` needs, so tests vary one thing at a time."""
    return {
        "directory": directory,
        "policy": policy,
        "clock": clock,
        "replay": replay,
        "org_id": org.org_id,
    }
