"""RFC 8785 conformance and the schema narrowings we add on top of it."""

from __future__ import annotations

import pytest

from alerting.core.canonical import MAX_SAFE_INTEGER, canonicalize
from alerting.core.errors import CanonicalizationError


def test_keys_sorted_by_utf16_code_unit_not_code_point():
    # U+1F600 is a surrogate pair in UTF-16 (D83D DE00), so it sorts *before* U+FFFD
    # by code unit but *after* it by code point. RFC 8785 mandates code-unit order.
    out = canonicalize({"�": 1, "\U0001f600": 2}).decode()
    assert out == '{"\U0001f600":2,"�":1}'


def test_no_whitespace_and_sorted_keys():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_nested_structures():
    value = {"z": [1, {"b": False, "a": True}], "a": {}}
    assert canonicalize(value) == b'{"a":{},"z":[1,{"a":true,"b":false}]}'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\nb", b'{"k":"a\\nb"}'),
        ('q"q', b'{"k":"q\\"q"}'),
        ("back\\slash", b'{"k":"back\\\\slash"}'),
        ("\x00\x1f", b'{"k":"\\u0000\\u001f"}'),
        ("tab\there", b'{"k":"tab\\there"}'),
    ],
)
def test_string_escaping_is_minimal(text, expected):
    assert canonicalize({"k": text}) == expected


def test_nfc_normalization_makes_equivalent_strings_identical():
    composed = canonicalize({"k": "é"})  # é
    decomposed = canonicalize({"k": "é"})  # e + combining acute
    assert composed == decomposed, "otherwise two 'identical' orders sign differently"


def test_nfc_collision_in_keys_is_rejected():
    with pytest.raises(CanonicalizationError, match="collide"):
        canonicalize({"é": 1, "é": 2})


@pytest.mark.parametrize("bad", [1.0, 0.1, float("nan"), float("inf")])
def test_floats_are_rejected(bad):
    with pytest.raises(CanonicalizationError, match="float"):
        canonicalize({"k": bad})


def test_null_is_rejected_because_absent_means_absent():
    with pytest.raises(CanonicalizationError, match="null"):
        canonicalize({"k": None})


def test_non_string_keys_are_rejected():
    with pytest.raises(CanonicalizationError, match="non-string"):
        canonicalize({1: "a"})


def test_unsupported_types_are_rejected():
    with pytest.raises(CanonicalizationError, match="unsupported type"):
        canonicalize({"k": {1, 2}})


def test_integers_beyond_the_ecmascript_safe_range_are_rejected():
    assert canonicalize({"k": MAX_SAFE_INTEGER})
    with pytest.raises(CanonicalizationError, match="safe range"):
        canonicalize({"k": MAX_SAFE_INTEGER + 1})


def test_top_level_must_be_an_object():
    with pytest.raises(CanonicalizationError, match="object"):
        canonicalize([1, 2])  # type: ignore[arg-type]


def test_booleans_are_not_treated_as_integers():
    assert canonicalize({"k": True}) == b'{"k":true}'
    assert canonicalize({"k": 1}) == b'{"k":1}'
