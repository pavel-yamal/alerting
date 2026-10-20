"""Pinned trust anchors on the client side.

Two things make client-side verification real rather than decorative:

1. The org **root public key is pinned at enrollment**, in person, and never fetched.
2. Bundle **versions only go up**. A client that has seen directory version 7 refuses
   version 6 forever, so a server cannot roll it back to a directory that still
   contains a key the org has since revoked. The same holds for the revocation list
   signed on the fast path.

The cache also lets a client verify an order while the server is unreachable, which is
the state it is most likely to be in during the incident that matters.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import tempfile
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from alerting.core.directory import Directory
from alerting.core.policy import Policy
from alerting.core.replay import ReplayWindow
from alerting.core.signing import public_key_from_b64u


def write_atomically(path: pathlib.Path, text: str) -> None:
    """Replace ``path`` with ``text`` so that no reader ever sees half of it.

    ``write_text`` truncates and then writes. Two processes holding the same key
    home -- the CLI and the phone client, say, both mounted on one volume -- interleave
    that and leave a shorter JSON written over a longer one with the old tail still
    attached. That file then fails to parse, and the device refuses to verify
    anything: a corrupted replay window looks like tampering, as it should. Writing a
    sibling file and renaming it over the original is atomic on POSIX.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


@dataclass
class PinnedOrg:
    """What an enrolled device holds locally."""

    org_id: str
    root_public_key_b64u: str
    home: pathlib.Path

    @property
    def root_public_key(self) -> Ed25519PublicKey:
        return public_key_from_b64u(self.root_public_key_b64u)

    @property
    def pin_path(self) -> pathlib.Path:
        return self.home / "pin.json"

    def save(self) -> None:
        write_atomically(
            self.pin_path,
            json.dumps(
                {"org_id": self.org_id, "root_public_key": self.root_public_key_b64u},
                indent=2,
            ),
        )

    @classmethod
    def load(cls, home: pathlib.Path) -> PinnedOrg:
        blob = json.loads((home / "pin.json").read_text(encoding="utf-8"))
        return cls(blob["org_id"], blob["root_public_key"], home)


class BundleCache:
    def __init__(self, pin: PinnedOrg) -> None:
        self.pin = pin
        self.home = pin.home

    def _path(self, kind: str) -> pathlib.Path:
        return self.home / f"{kind}.json"

    def _state_path(self) -> pathlib.Path:
        return self.home / "state.json"

    def seen_version(self, kind: str) -> int:
        state = self._state()
        return int(state.get(f"{kind}_version", 0))

    def _state(self) -> dict[str, Any]:
        path = self._state_path()
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_state(self, **updates: Any) -> None:
        state = self._state()
        state.update(updates)
        write_atomically(self._state_path(), json.dumps(state, indent=2))

    def accept(self, kind: str, bundle: dict[str, Any]) -> Directory | Policy:
        """Verify a freshly fetched bundle and cache it if it is not a rollback.

        A directory comes back with the cached revocation list applied, and
        ``revocations`` returns the directory with the new list applied: a key
        revoked on the fast path is never trusted again just because the root-signed
        directory does not mention it yet.
        """
        if kind == "revocations":
            return self._accept_revocations(bundle)
        loader = Directory.load if kind == "directory" else Policy.load
        loaded = loader(
            bundle,
            root_public_key=self.pin.root_public_key,
            org_id=self.pin.org_id,
            min_version=self.seen_version(kind),
        )
        write_atomically(self._path(kind), json.dumps(bundle, ensure_ascii=False, indent=2))
        self._write_state(**{f"{kind}_version": loaded.version})
        if isinstance(loaded, Directory):
            return loaded.with_revocations(self._cached_revocations())
        return loaded

    def _accept_revocations(self, bundle: dict[str, Any]) -> Directory:
        base = self._root_directory()
        if not bundle:
            # Withheld or none yet: keep what we hold. Dropping it would un-revoke.
            return base.with_revocations(self._cached_revocations())
        applied = base.with_revocations(
            bundle,
            min_version=self.seen_version("revocations"),
            previous=self._cached_revocations(),
        )
        if applied.revocations is None:
            # Signed by a key this directory no longer names; the root's word is newer.
            return applied
        path = self._path("revocations")
        write_atomically(path, json.dumps(bundle, ensure_ascii=False, indent=2))
        self._write_state(revocations_version=applied.revocations.version)
        return applied

    def _cached_revocations(self) -> dict[str, Any] | None:
        path = self._path("revocations")
        if not path.exists():
            return None
        blob: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return blob

    def _root_directory(self) -> Directory:
        bundle = json.loads(self._path("directory").read_text(encoding="utf-8"))
        return Directory.load(
            bundle, root_public_key=self.pin.root_public_key, org_id=self.pin.org_id
        )

    def cached(self, kind: str) -> Directory | Policy:
        """Load from disk. Used when the server is unreachable."""
        if kind == "directory":
            return self._root_directory().with_revocations(self._cached_revocations())
        bundle = json.loads(self._path(kind).read_text(encoding="utf-8"))
        return Policy.load(bundle, root_public_key=self.pin.root_public_key, org_id=self.pin.org_id)

    def directory(self) -> Directory:
        result = self.cached("directory")
        assert isinstance(result, Directory)
        return result

    def policy(self) -> Policy:
        result = self.cached("policy")
        assert isinstance(result, Policy)
        return result

    # --- replay window ------------------------------------------------------
    def replay_window(self) -> ReplayWindow:
        window = ReplayWindow()
        window.restore(self._state().get("replay", {}))
        return window

    def save_replay(self, window: ReplayWindow) -> None:
        self._write_state(replay=window.state())

    def seen_order_ids(self) -> set[str]:
        return set(self._state().get("seen_order_ids", []))

    def remember_order(self, order_id: str) -> None:
        seen = self.seen_order_ids()
        seen.add(order_id)
        self._write_state(seen_order_ids=sorted(seen)[-5000:])
