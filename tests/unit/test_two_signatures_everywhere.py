"""Every order, drill or real, needs two different decision-makers.

People choose only drill or real; the level is the scenario's. A quorum that
differed by level would be a difference nobody chose.
"""

from __future__ import annotations

import pathlib

import yaml

from alerting.orgkit import DEFAULT_SEVERITIES

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_the_default_policy_asks_two_people_for_every_level() -> None:
    for level, rules in DEFAULT_SEVERITIES.items():
        assert rules.launch.m == 2, level
        assert rules.launch.distinct_persons, level
        assert rules.cancel.m <= rules.launch.m, level


def test_the_example_policy_says_the_same() -> None:
    policy = yaml.safe_load((ROOT / "config" / "policy.example.yaml").read_text())
    for level, rules in policy["severities"].items():
        assert rules["launch"]["m"] == 2, level
        assert rules["launch"]["distinct_persons"] is True, level
