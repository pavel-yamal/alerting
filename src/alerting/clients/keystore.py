"""Local key storage for the prototype.

**This is the seam, not the answer.** In production the private key is generated on the
device and never leaves its secure storage — iOS Keychain with Secure Enclave, Android
Keystore with StrongBox, a TPM, or a hardware token for the org root. Signing happens
inside that boundary, behind a biometric or PIN unlock, and this module is replaced by
a thin call into it.

What is here is a scrypt-derived AES-GCM file, which is honest about what it is: good
enough for a reference implementation and a demo, not good enough for a decision-maker's
launch key.
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from alerting.core.signing import (
    b64u_decode,
    b64u_encode,
    key_id,
    private_key_from_b64u,
    private_key_to_b64u,
)

DEFAULT_DIR = pathlib.Path(os.environ.get("ALERTING_HOME", "~/.alerting")).expanduser()
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass(frozen=True)
class StoredKey:
    person_id: str
    key_id: str
    role: str
    private_key: Ed25519PrivateKey


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def key_path(person_id: str, directory: pathlib.Path | None = None) -> pathlib.Path:
    return (directory or DEFAULT_DIR) / "keys" / f"{person_id}.json"


def save_key(
    person_id: str,
    private_key: Ed25519PrivateKey,
    passphrase: str,
    *,
    role: str = "executor",
    directory: pathlib.Path | None = None,
) -> pathlib.Path:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(_derive(passphrase, salt)).encrypt(
        nonce, private_key_to_b64u(private_key).encode("ascii"), None
    )
    path = key_path(person_id, directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "person_id": person_id,
                "key_id": key_id(private_key.public_key()),
                "role": role,
                "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
                "salt": b64u_encode(salt),
                "nonce": b64u_encode(nonce),
                "sealed": b64u_encode(sealed),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def load_key(
    person_id: str, passphrase: str, *, directory: pathlib.Path | None = None
) -> StoredKey:
    path = key_path(person_id, directory)
    if not path.exists():
        raise FileNotFoundError(f"no key for {person_id} at {path}")
    blob = json.loads(path.read_text(encoding="utf-8"))
    plain = AESGCM(_derive(passphrase, b64u_decode(blob["salt"]))).decrypt(
        b64u_decode(blob["nonce"]), b64u_decode(blob["sealed"]), None
    )
    return StoredKey(
        person_id=blob["person_id"],
        key_id=blob["key_id"],
        role=blob.get("role", "executor"),
        private_key=private_key_from_b64u(plain.decode("ascii")),
    )
