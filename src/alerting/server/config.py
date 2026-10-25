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
import socket
from dataclasses import dataclass, field

from alerting.server.mobilepush import (
    ApnsConfig,
    FcmConfig,
    build_apns_jwt,
    build_fcm_assertion,
    parse_service_account,
)


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


#: See ``Settings.delivery``.
DELIVERY_MODES = frozenset({"channels", "rss"})


@dataclass
class Settings:
    org_id: str = "acme"

    #: PostgreSQL connection string. It carries a password, so the supported path is
    #: ``dsn_file`` under systemd ``LoadCredential=``; ``dsn`` set directly is for the
    #: demo and for tests, and the server says so at startup.
    dsn: str = ""
    dsn_file: str = ""

    #: The pinned org root public key, base64url. Without it the server cannot verify
    #: its own bundles and refuses to start.
    root_public_key: str = ""
    org_label: str = "ACME"

    #: Where people reach this node from outside, e.g. ``https://alert.example.org``:
    #: the RSS channel links to its feed there. Behind nginx in a container the node
    #: sees neither the public name nor https, so it is set rather than guessed; left
    #: empty, the link is built from the request's own host.
    public_url: str = ""

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

    #: Which node this is, in the heartbeat table. Defaults to the hostname, which is
    #: right on a VM and wrong in a container -- set it explicitly there, or every
    #: replica overwrites one row and a partial channel failure becomes invisible.
    node_id: str = ""

    #: How often each channel is asked whether it is still there.
    heartbeat_interval_s: float = 60.0

    #: How often the delivery canary sends a drill order to the canary contact.
    #: Hourly: frequent enough that a broken delivery path is found the same working
    #: day, rare enough that the audit chain stays a record of events rather than of
    #: probes. Zero disables it.
    canary_interval_s: float = 3600.0

    #: Permits a node whose escalation ladder names a channel with no provider behind
    #: it. Required for the demo and for tests; a production node must not set it.
    allow_stub_channels: bool = False

    #: What happens to an order once its quorum is met. ``rss``: it is recorded and
    #: published in the feed, and nothing is sent to anyone -- no sockets, push, SMS,
    #: siren, escalation or canary; drills go to the feed too, marked. ``channels``:
    #: the full delivery path with acknowledgements and the escalation ladder.
    delivery: str = "channels"

    #: Push to the decision-makers' app (alerting.server.mobilepush). iOS goes
    #: straight to APNs with the .p8 key from Apple Developer, Android through FCM
    #: with a Firebase service account. Either left empty switches that side off.
    apns_team_id: str = ""
    apns_key_id: str = ""
    apns_key_file: str = ""
    #: The app's bundle id.
    apns_topic: str = "me.yamal.alert"
    fcm_service_account_file: str = ""
    #: Overrides the project in the service-account file, when one account serves
    #: several Firebase projects.
    fcm_project_id: str = ""

    log_level: str = "INFO"
    log_json: bool = False

    def __post_init__(self) -> None:
        if self.delivery not in DELIVERY_MODES:
            raise ValueError(
                f"ALERTING_DELIVERY must be one of {sorted(DELIVERY_MODES)}, not {self.delivery!r}"
            )

    @property
    def rss_only(self) -> bool:
        return self.delivery == "rss"

    @classmethod
    def from_env(cls) -> Settings:
        sites = os.environ.get("ALERTING_DRILL_SITES", "")
        return cls(
            org_id=os.environ.get("ALERTING_ORG", "acme"),
            dsn=os.environ.get("ALERTING_DSN", ""),
            dsn_file=os.environ.get("ALERTING_DSN_FILE", ""),
            root_public_key=os.environ.get("ALERTING_ROOT_PUBKEY", ""),
            server_key_file=os.environ.get("ALERTING_SERVER_KEY_FILE", ""),
            org_label=os.environ.get("ALERTING_ORG_LABEL", "ACME"),
            public_url=os.environ.get("ALERTING_PUBLIC_URL", "").rstrip("/"),
            escalation_config=os.environ.get(
                "ALERTING_ESCALATION_CONFIG", "config/escalation.example.yaml"
            ),
            wordlist_path=os.environ.get("ALERTING_WORDLIST", "config/wordlist.ru.txt"),
            drill_enabled_sites=frozenset(s for s in sites.split(",") if s),
            heads_dir=_env_path("ALERTING_HEADS_DIR", "var/heads"),
            spool_dir=_env_path("ALERTING_SPOOL_DIR", "var/spool"),
            escalation_interval_s=_env_float("ALERTING_ESCALATION_INTERVAL_S", 5.0),
            node_id=os.environ.get("ALERTING_NODE_ID", "") or socket.gethostname(),
            heartbeat_interval_s=_env_float("ALERTING_HEARTBEAT_INTERVAL_S", 60.0),
            canary_interval_s=_env_float("ALERTING_CANARY_INTERVAL_S", 3600.0),
            allow_stub_channels=_env_flag("ALERTING_ALLOW_STUB_CHANNELS"),
            delivery=os.environ.get("ALERTING_DELIVERY", "channels") or "channels",
            apns_team_id=os.environ.get("ALERTING_APNS_TEAM_ID", "").strip(),
            apns_key_id=os.environ.get("ALERTING_APNS_KEY_ID", "").strip(),
            apns_key_file=os.environ.get("ALERTING_APNS_KEY_FILE", "").strip(),
            apns_topic=os.environ.get("ALERTING_APNS_TOPIC", "").strip() or "me.yamal.alert",
            fcm_service_account_file=os.environ.get(
                "ALERTING_FCM_SERVICE_ACCOUNT_FILE", ""
            ).strip(),
            fcm_project_id=os.environ.get("ALERTING_FCM_PROJECT_ID", "").strip(),
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

    def load_push(self) -> tuple[ApnsConfig | None, FcmConfig | None]:
        """The push keys, each side ``None`` when not configured.

        A configured key that cannot be read or parsed stops the node from starting,
        like the server key: a deployment that believes it pushes and silently does
        not is the failure this project is built against.
        """
        apns = None
        if self.apns_key_file:
            if not (self.apns_team_id and self.apns_key_id):
                raise RuntimeError(
                    "ALERTING_APNS_KEY_FILE is set without ALERTING_APNS_TEAM_ID and "
                    "ALERTING_APNS_KEY_ID"
                )
            apns = ApnsConfig(
                team_id=self.apns_team_id,
                key_id=self.apns_key_id,
                private_key_pem=read_secret_file(pathlib.Path(self.apns_key_file), "APNs key"),
                topic=self.apns_topic,
            )
            build_apns_jwt(apns, 0)  # refuses a key that is not the .p8 one, now
        fcm = None
        if self.fcm_service_account_file:
            fcm = parse_service_account(
                read_secret_file(pathlib.Path(self.fcm_service_account_file), "FCM account"),
                self.fcm_project_id,
            )
            build_fcm_assertion(fcm, 0)
        return apns, fcm

    def load_dsn(self) -> str:
        """The connection string, from a file when one is configured.

        ``ALERTING_DSN_FILE`` wins over ``ALERTING_DSN``: a DSN holds a password, and
        a password in the environment is visible in ``/proc/PID/environ`` and
        ``systemctl show`` to anyone who can read them.
        """
        if self.dsn_file:
            return read_secret_file(pathlib.Path(self.dsn_file), "database DSN")
        if not self.dsn:
            raise RuntimeError(
                "no database configured. Set ALERTING_DSN_FILE to a file holding the "
                "PostgreSQL connection string (0600, via systemd LoadCredential), or "
                "ALERTING_DSN directly for a demo."
            )
        return self.dsn


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
