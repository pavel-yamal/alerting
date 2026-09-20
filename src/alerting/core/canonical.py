"""RFC 8785 (JCS) canonicalization, narrowed by schema constraints.

Why JCS and not deterministic CBOR: the bytes that were signed stay readable by a
human. An auditor, a support engineer, or an expert in a courtroom can look at the
audit log and read the exact order that was approved, with no tooling. For a system
whose whole purpose is provable authorship, that outweighs CBOR's compactness.

JCS's sharp edges are removed here by refusing to canonicalize the dangerous cases
rather than by guessing at them:

* **No floats.** ECMAScript number formatting is where JCS implementations disagree.
  Every number in this protocol is a count or a Unix second, so floats are a bug.
* **No ``None``.** ``{"a": null}`` and ``{}`` are different signed bytes; allowing both
  invites a signer and a verifier to disagree about which one they meant. Absent means
  absent: models serialize with ``exclude_none``.
* **NFC everywhere.** Two visually identical strings with different Unicode
  normalization would produce two different signatures over the "same" order.
* **Bounded integers.** Beyond 2**53-1 an ECMAScript reader silently loses precision,
  so a conforming verifier on another stack would hash different bytes.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from alerting.core.errors import CanonicalizationError

#: Beyond this an ECMAScript JSON reader loses precision and would disagree with us.
MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _sort_key(key: str) -> bytes:
    """RFC 8785 orders object keys by UTF-16 code unit, not by code point.

    Python's native string ordering is by code point, which differs for astral
    characters, so sort on the big-endian UTF-16 encoding instead.
    """
    return key.encode("utf-16-be", errors="surrogatepass")


def _encode_string(value: str) -> str:
    out = ['"']
    for ch in _nfc(value):
        point = ord(ch)
        escape = _ESCAPES.get(point)
        if escape is not None:
            out.append(escape)
        elif point < 0x20:
            out.append(f"\\u{point:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(value: int) -> str:
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(
            f"integer {value} exceeds the ECMAScript safe range; "
            "a conforming verifier on another stack would read different bytes"
        )
    return str(value)


def _encode(value: Any, path: str) -> str:
    if value is None:
        raise CanonicalizationError(
            f"null at {path}: absent means absent in this protocol, "
            "so serialize with exclude_none instead of emitting null"
        )
    if isinstance(value, bool):
        # Checked before int: bool is a subclass of int in Python.
        return "true" if value else "false"
    if isinstance(value, float):
        raise CanonicalizationError(
            f"float at {path}: every number in this protocol is a count or a Unix "
            "second; floats are the main source of JCS implementation disagreement"
        )
    if isinstance(value, int):
        return _encode_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, Mapping):
        return _encode_object(value, path)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        items = [_encode(item, f"{path}[{i}]") for i, item in enumerate(value)]
        return "[" + ",".join(items) + "]"
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def _encode_object(mapping: Mapping[Any, Any], path: str) -> str:
    normalized: dict[str, Any] = {}
    for raw_key, value in mapping.items():
        if not isinstance(raw_key, str):
            raise CanonicalizationError(
                f"non-string object key {raw_key!r} at {path}: JSON objects are "
                "string-keyed and any coercion would be implementation-defined"
            )
        key = _nfc(raw_key)
        if key in normalized:
            raise CanonicalizationError(
                f"keys {raw_key!r} collide at {path} after NFC normalization"
            )
        normalized[key] = value

    parts = [
        f"{_encode_string(key)}:{_encode(normalized[key], f'{path}.{key}')}"
        for key in sorted(normalized, key=_sort_key)
    ]
    return "{" + ",".join(parts) + "}"


def canonicalize(value: Mapping[str, Any]) -> bytes:
    """Return the canonical UTF-8 bytes of ``value``, ready to be signed or hashed.

    Raises:
        CanonicalizationError: if the value contains anything that two conforming
            implementations could serialize differently.
    """
    if not isinstance(value, Mapping):
        raise CanonicalizationError("top-level value must be a JSON object")
    return _encode_object(value, "$").encode("utf-8")
