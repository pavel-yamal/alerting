"""Server settings."""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field


@dataclass
class Settings:
    org_id: str = "acme"
    db_path: str = "var/alerting.db"
    #: The pinned org root public key, base64url. Without it the server cannot verify
    #: its own bundles and refuses to start.
    root_public_key: str = ""
    org_label: str = "ACME"
    escalation_config: str = "config/escalation.example.yaml"
    wordlist_path: str = "config/wordlist.ru.txt"
    drill_enabled_sites: frozenset[str] = field(default_factory=frozenset)
    heads_dir: pathlib.Path = pathlib.Path("var/heads")
    spool_dir: pathlib.Path = pathlib.Path("var/spool")
    escalation_interval_s: float = 1.0

    @classmethod
    def from_env(cls) -> Settings:
        sites = os.environ.get("ALERTING_DRILL_SITES", "")
        return cls(
            org_id=os.environ.get("ALERTING_ORG", "acme"),
            db_path=os.environ.get("ALERTING_DB", "var/alerting.db"),
            root_public_key=os.environ.get("ALERTING_ROOT_PUBKEY", ""),
            org_label=os.environ.get("ALERTING_ORG_LABEL", "ACME"),
            drill_enabled_sites=frozenset(s for s in sites.split(",") if s),
        )
