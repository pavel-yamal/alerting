"""Pinned trust anchors on the client side.

Two things make client-side verification real rather than decorative:

1. The org **root public key is pinned at enrollment**, in person, and never fetched.
2. Bundle **versions only go up**. A client that has seen directory version 7 refuses
   version 6 forever, so a server cannot roll it back to a directory that still
   contains a key the org has since revoked.

The cache also lets a client verify an order while the server is unreachable, which is
the state it is most likely to be in during the incident that matters.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from alerting.core.directory import Directory
from alerting.core.policy import Policy
from alerting.core.replay import ReplayWindow
from alerting.core.signing import public_key_from_b64u


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
        self.home.mkdir(parents=True, exist_ok=True)
        self.pin_path.write_text(
            json.dumps(
                {"org_id": self.org_id, "root_public_key": self.root_public_key_b64u},
                indent=2,
            ),
            encoding="utf-8",
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
        self.home.mkdir(parents=True, exist_ok=True)
        self._state_path().write_text(json.dumps(state, indent=2), encoding="utf-8")

    def accept(self, kind: str, bundle: dict[str, Any]) -> Directory | Policy:
        """Verify a freshly fetched bundle and cache it if it is not a rollback."""
        loader = Directory.load if kind == "directory" else Policy.load
        loaded = loader(
            bundle,
            root_public_key=self.pin.root_public_key,
            org_id=self.pin.org_id,
            min_version=self.seen_version(kind),
        )
        self.home.mkdir(parents=True, exist_ok=True)
        self._path(kind).write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self._write_state(**{f"{kind}_version": loaded.version})
        return loaded

    def cached(self, kind: str) -> Directory | Policy:
        """Load from disk. Used when the server is unreachable."""
        bundle = json.loads(self._path(kind).read_text(encoding="utf-8"))
        loader = Directory.load if kind == "directory" else Policy.load
        return loader(bundle, root_public_key=self.pin.root_public_key, org_id=self.pin.org_id)

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
