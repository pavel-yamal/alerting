"""The browser's signing code produces the same bytes as the Python core.

The panel page signs orders and session delegations in JavaScript. A one-character
difference in canonical JSON would make every browser signature fail -- or, worse,
make the page show one thing and sign another. Run with Node (WebCrypto has Ed25519
since Node 20); skipped where Node is not installed.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from alerting.core.canonical import canonicalize
from alerting.core.signing import (
    DOMAIN_ORDER,
    DOMAIN_SESSION_DELEGATION,
    b64u_encode,
    generate_keypair,
    key_id,
    verify_signature,
)
from alerting.orgkit import build_org, make_order

SCRIPT = pathlib.Path("src/alerting/clients/panel/static/devicekey.js")
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

DRIVER = """
const fs = require("fs");
eval(fs.readFileSync(process.argv[process.argv.length - 1], "utf8"));
const input = JSON.parse(fs.readFileSync(0, "utf8"));
(async () => {
  const D = globalThis.DeviceKey;
  const key = await crypto.subtle.importKey(
    "pkcs8", D.fromB64u(input.pkcs8), { name: "Ed25519" }, false, ["sign"]);
  const out = { canonical: [], signatures: [], digests: [], refused: [] };
  for (const payload of input.payloads) {
    out.canonical.push(D.canonicalize(payload));
    out.signatures.push(await D.sign(key, input.domain, payload));
    out.digests.push(await D.digestHex(input.domain, payload));
  }
  for (const bad of input.bad) {
    try { D.canonicalize(bad); out.refused.push(false); } catch (_) { out.refused.push(true); }
  }
  out.key_id = await D.keyId(D.fromB64u(input.raw_public));
  out.unexpected = D.unexpectedFields(Object.assign({}, input.payloads[0], { sneaky: 1 }));
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def run(domain: str, payloads: list, bad: list) -> tuple[dict, object]:
    private, public = generate_keypair()
    from cryptography.hazmat.primitives.serialization import PublicFormat

    raw_public = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pkcs8 = private.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    result = subprocess.run(
        [NODE, "-e", DRIVER, str(SCRIPT)],
        input=json.dumps({
            "pkcs8": b64u_encode(pkcs8), "raw_public": b64u_encode(raw_public),
            "domain": domain, "payloads": payloads, "bad": bad,
        }),
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout), public


def tricky_payloads() -> list[dict]:
    org = build_org()
    order = make_order(org, issued_at=1_700_000_000).to_payload()
    return [
        order,
        dict(order, text='Ёлка́ — «кавычки» "и" \\ \n\t\u0001 😀 é'),
        {"b": 1, "a": [True, False, 0, -5, 9007199254740991], "é": {"z": "", "éa": "x"}},
        {"😀": 1, "￿": 2, "a": 3},  # UTF-16 order differs from code points
    ]


def test_canonical_bytes_signatures_and_digests_match_python():
    payloads = tricky_payloads()
    out, public = run("order", payloads, bad=[])
    for payload, canonical, signature, digest in zip(
        payloads, out["canonical"], out["signatures"], out["digests"], strict=True
    ):
        assert canonical.encode("utf-8") == canonicalize(payload)
        assert verify_signature(DOMAIN_ORDER, payload, signature, public)
        import hashlib

        assert digest == hashlib.sha256(DOMAIN_ORDER + canonicalize(payload)).hexdigest()
    assert out["key_id"] == key_id(public)
    assert out["unexpected"] == ["sneaky"]


def test_a_delegation_signed_in_the_browser_verifies():
    delegation = {
        "v": 1, "type": "session-delegation", "org_id": "acme", "key_id": "ed25519:x",
        "person_id": "p-001", "session_key": "abc", "not_before": 1, "not_after": 2,
    }  # fmt: skip
    out, public = run("delegation", [delegation], bad=[])
    assert verify_signature(DOMAIN_SESSION_DELEGATION, delegation, out["signatures"][0], public)


def test_what_python_refuses_the_browser_refuses():
    _, _ = generate_keypair()
    out, _ = run("order", [{"a": 1}], bad=[{"a": None}, {"a": 1.5}, {"a": 2**53}])
    assert out["refused"] == [True, True, True]
