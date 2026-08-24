"""
config.py — Încărcare și validare configurație IDS.

Citește config.yaml și expune un obiect tipizat folosit de toți detectorii
și de modulul de alertare. Valorile implicite sunt definite în DEFAULT_CONFIG
și sunt suprascrise de valorile din fișier.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Sub-configurații per modul
# ---------------------------------------------------------------------------

@dataclass
class SynScanConfig:
    port_threshold: int = 20
    time_window: float = 10.0


@dataclass
class SynFloodConfig:
    packet_threshold: int = 100
    time_window: float = 5.0


@dataclass
class SshBruteforceConfig:
    connection_threshold: int = 10
    time_window: float = 30.0


@dataclass
class ArpSpoofConfig:
    alert_on_first_seen: bool = False


@dataclass
class LoggingConfig:
    console: bool = True
    file: str = "logs/alerts.json"
    min_severity: str = "LOW"


@dataclass
class IDSConfig:
    syn_scan: SynScanConfig = field(default_factory=SynScanConfig)
    syn_flood: SynFloodConfig = field(default_factory=SynFloodConfig)
    ssh_bruteforce: SshBruteforceConfig = field(default_factory=SshBruteforceConfig)
    arp_spoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


# ---------------------------------------------------------------------------
# Funcție de încărcare
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> IDSConfig:
    """
    Încarcă configurația din *path* (YAML) și returnează un obiect IDSConfig.

    Dacă fișierul nu există, returnează configurația cu valorile implicite
    și afișează un avertisment.
    """
    if not os.path.exists(path):
        print(f"[WARN] Fișierul de configurare '{path}' nu a fost găsit. "
              "Se folosesc valorile implicite.")
        return IDSConfig()

    with open(path, "r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    def get(section: str, key: str, default: Any) -> Any:
        return raw.get(section, {}).get(key, default)

    return IDSConfig(
        syn_scan=SynScanConfig(
            port_threshold=get("syn_scan", "port_threshold", 20),
            time_window=get("syn_scan", "time_window", 10.0),
        ),
        syn_flood=SynFloodConfig(
            packet_threshold=get("syn_flood", "packet_threshold", 100),
            time_window=get("syn_flood", "time_window", 5.0),
        ),
        ssh_bruteforce=SshBruteforceConfig(
            connection_threshold=get("ssh_bruteforce", "connection_threshold", 10),
            time_window=get("ssh_bruteforce", "time_window", 30.0),
        ),
        arp_spoof=ArpSpoofConfig(
            alert_on_first_seen=get("arp_spoof", "alert_on_first_seen", False),
        ),
        logging=LoggingConfig(
            console=get("logging", "console", True),
            file=get("logging", "file", "logs/alerts.json"),
            min_severity=get("logging", "min_severity", "LOW"),
        ),
    )
