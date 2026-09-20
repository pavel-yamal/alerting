"""Server settings.

Two rules this module enforces rather than documents:

* **Every setting is reachable from the environment.** Five of these used to be
  code-only, which meant a deployed node could not be configured at all — and two of
  them degraded *silently* when their file was missing.
* **The server signing key is never an environment variable.** It is an Ed25519
  private key; via the environment it lands in ``/proc/PID/environ``, ``systemctl
  show`` and — as the old runbook line ``ALERTING_SERVER_KEY=$(cat …)`` did — in
  ``ps`` for every user on the box. Whoever reads it can forge audit heads and the
  tamper-evidence dies silently. It is read from a file with checked permissions.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field


def _env_path(name: str, default: str) -> pathlib.Path:
    return pathlib.Path(os.environ.get(name, default))


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    org_id: str = "acme"
    db_path: str = "var/alerting.db"

    #: The pinned org root public key, base64url. Without it the server cannot verify
    #: its own bundles and refuses to start.
    root_public_key: str = ""
    org_label: str = "ACME"

    #: Path to the Ed25519 private key that signs published audit heads. Never the key
    #: itself — see the module docstring. Empty means heads are published unsigned,
    #: which the server warns loudly about but does not refuse: alerting outranks a
    #: perfect log.
    server_key_file: str = ""

    #: Set directly in tests and by ``org_init``; production goes through
    #: ``server_key_file``.
    server_private_key: str = ""

    escalation_config: str = "config/escalation.example.yaml"
    wordlist_path: str = "config/wordlist.ru.txt"
    drill_enabled_sites: frozenset[str] = field(default_factory=frozenset)
    heads_dir: pathlib.Path = pathlib.Path("var/heads")
    spool_dir: pathlib.Path = pathlib.Path("var/spool")

    #: The ladder is measured in minutes, so one-second resolution bought nothing and
    #: cost a full scan of recent orders every second.
    escalation_interval_s: float = 5.0

    #: Permits a node whose escalation ladder names a channel with no provider behind
    #: it. Required for the demo and for tests; a production node must not set it.
    allow_stub_channels: bool = False

    #: Shared secret for the interim ``Alerting-Api-Key`` gate, read from a file with
    #: checked permissions. Empty means the HTTP surface is unauthenticated, which the
    #: server refuses unless ``allow_unauthenticated`` is set.
    api_key_file: str = ""
    allow_unauthenticated: bool = False

    log_level: str = "INFO"
    log_json: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        sites = os.environ.get("ALERTING_DRILL_SITES", "")
        return cls(
            org_id=os.environ.get("ALERTING_ORG", "acme"),
            db_path=os.environ.get("ALERTING_DB", "var/alerting.db"),
            root_public_key=os.environ.get("ALERTING_ROOT_PUBKEY", ""),
            server_key_file=os.environ.get("ALERTING_SERVER_KEY_FILE", ""),
            org_label=os.environ.get("ALERTING_ORG_LABEL", "ACME"),
            escalation_config=os.environ.get(
                "ALERTING_ESCALATION_CONFIG", "config/escalation.example.yaml"
            ),
            wordlist_path=os.environ.get("ALERTING_WORDLIST", "config/wordlist.ru.txt"),
            drill_enabled_sites=frozenset(s for s in sites.split(",") if s),
            heads_dir=_env_path("ALERTING_HEADS_DIR", "var/heads"),
            spool_dir=_env_path("ALERTING_SPOOL_DIR", "var/spool"),
            escalation_interval_s=_env_float("ALERTING_ESCALATION_INTERVAL_S", 5.0),
            allow_stub_channels=_env_flag("ALERTING_ALLOW_STUB_CHANNELS"),
            api_key_file=os.environ.get("ALERTING_API_KEY_FILE", ""),
            allow_unauthenticated=_env_flag("ALERTING_ALLOW_UNAUTHENTICATED"),
            log_level=os.environ.get("ALERTING_LOG_LEVEL", "INFO"),
            log_json=_env_flag("ALERTING_LOG_JSON"),
        )

    # --- secrets read from disk, with the permission check that makes it worthwhile --

    def load_server_key(self) -> str:
        """Base64url private key, or ``""`` when none is configured."""
        if self.server_private_key:
            return self.server_private_key
        if not self.server_key_file:
            return ""
        return read_secret_file(pathlib.Path(self.server_key_file), "server key")

    def load_api_key(self) -> str:
        if not self.api_key_file:
            return ""
        return read_secret_file(pathlib.Path(self.api_key_file), "API key")


def read_secret_file(path: pathlib.Path, label: str) -> str:
    """Read a secret, refusing a file anyone else on the box can read.

    A private key readable by every local user is not a secret, and silently using it
    anyway is how a deployment ends up believing it has tamper-evidence it does not.
    """
    if not path.exists():
        raise FileNotFoundError(f"{label} file not found: {path}")
    mode = path.stat().st_mode
    if mode & 0o077:
        raise PermissionError(
            f"{label} file {path} is readable by group or others "
            f"(mode {mode & 0o777:04o}); refusing to use it. Expected 0600 or 0400."
        )
    return path.read_text(encoding="utf-8").strip()
