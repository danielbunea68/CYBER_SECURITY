"""
alerter.py — Definirea structurii Alert și logarea acesteia.

Fiecare detector produce obiecte Alert. Modulul Alerter le afișează
în consolă (cu culori ANSI) și le scrie în fișierul JSON de log.

Structura unui Alert:
    timestamp   — ISO-8601, momentul detecției
    src_ip      — IP sursă (atacator probabil)
    dst_ip      — IP destinație (țintă)
    attack_type — identificator text (ex. "TCP_SYN_SCAN")
    severity    — LOW | MEDIUM | HIGH | CRITICAL
    explanation — propoziție umană care descrie ce s-a detectat
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from ids.config import IDSConfig, LoggingConfig

# ---------------------------------------------------------------------------
# Niveluri de severitate cu ordine numerică pentru filtrare
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Culori ANSI pentru consolă
_COLORS = {
    "LOW":      "\033[94m",   # albastru
    "MEDIUM":   "\033[93m",   # galben
    "HIGH":     "\033[91m",   # roșu deschis
    "CRITICAL": "\033[95m",   # magenta
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
}


# ---------------------------------------------------------------------------
# Dataclass Alert
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    src_ip: str
    dst_ip: str
    attack_type: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    explanation: str
    timestamp: str = ""    # completat automat de Alerter dacă e gol

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Clasa Alerter
# ---------------------------------------------------------------------------

class Alerter:
    """
    Primește alerte de la motor și le distribuie către consolă și/sau fișier.

    Parametri
    ---------
    config : LoggingConfig
        Secțiunea [logging] din configurație.
    """

    def __init__(self, config: LoggingConfig) -> None:
        self._cfg = config
        self._min_level: int = SEVERITY_ORDER.get(config.min_severity.upper(), 0)
        self._log_file: Optional[object] = None

        if config.file:
            # Asigurăm că directorul există
            os.makedirs(os.path.dirname(config.file) or ".", exist_ok=True)
            # Deschidem în mod append — nu ștergem log-urile existente
            self._log_file = open(config.file, "a", encoding="utf-8")

    # ------------------------------------------------------------------
    # API public
    # ------------------------------------------------------------------

    def emit(self, alert: Alert) -> None:
        """Procesează o singură alertă: timestamp, filtrare, output."""
        # Adăugăm timestamp dacă detectorul nu l-a completat
        if not alert.timestamp:
            alert.timestamp = datetime.now(timezone.utc).isoformat()

        level = SEVERITY_ORDER.get(alert.severity.upper(), 0)
        if level < self._min_level:
            return  # sub pragul de severitate configurat

        if self._cfg.console:
            self._print_console(alert)

        if self._log_file:
            self._write_json(alert)

    def close(self) -> None:
        """Închide fișierul de log (apelat la finalul procesării)."""
        if self._log_file:
            self._log_file.close()

    # ------------------------------------------------------------------
    # Metode private
    # ------------------------------------------------------------------

    def _print_console(self, alert: Alert) -> None:
        color = _COLORS.get(alert.severity.upper(), "")
        reset = _COLORS["RESET"]
        bold  = _COLORS["BOLD"]

        print(
            f"{bold}{color}"
            f"[{alert.timestamp}] "
            f"[{alert.severity}] "
            f"{alert.attack_type}"
            f"{reset}"
            f"  {alert.src_ip} -> {alert.dst_ip}"
            f"\n    {alert.explanation}"
        )

    def _write_json(self, alert: Alert) -> None:
        # Fiecare alertă = o linie JSON (newline-delimited JSON / NDJSON)
        self._log_file.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
        self._log_file.flush()  # scrie imediat pe disk, nu la buffer
