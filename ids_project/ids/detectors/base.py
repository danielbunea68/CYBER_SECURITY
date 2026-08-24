"""
base.py — Clasa abstractă de bază pentru toți detectorii IDS.

Fiecare detector trebuie să implementeze:
    - process_packet(packet) -> List[Alert]
        Analizează un pachet și returnează zero sau mai multe alerte.
    - reset()
        Reinițializează starea internă (util pentru teste).

Detectorul are acces la timestamp-ul real al pachetului prin
`packet.time` (float Unix timestamp, furnizat de Scapy).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from scapy.packet import Packet

from ids.alerter import Alert


class BaseDetector(ABC):
    """
    Interfață comună pentru toți detectorii de atacuri.

    Subclasele trebuie să implementeze `process_packet` și `reset`.
    """

    @abstractmethod
    def process_packet(self, packet: Packet) -> List[Alert]:
        """
        Procesează un pachet și returnează lista de alerte detectate.

        Returnează o listă goală dacă nu se detectează nimic.
        """
        ...

    @abstractmethod
    def reset(self) -> None:
        """Resetează starea internă a detectorului."""
        ...

    # ------------------------------------------------------------------
    # Utilitar comun: extrage timestamp-ul pachetului ca float
    # ------------------------------------------------------------------

    @staticmethod
    def get_timestamp(packet: Packet) -> float:
        """
        Returnează timestamp-ul pachetului (secunde Unix, float).

        Scapy stochează `packet.time` ca EDecimal; conversia la float
        este necesară pentru comparații aritmetice.
        """
        return float(packet.time)
