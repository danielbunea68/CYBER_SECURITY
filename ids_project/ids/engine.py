"""
engine.py — Motorul central IDS.

Rolul motorului:
    1. Primește pachetele de la parser (generator).
    2. Pasează fiecare pachet tuturor detectorilor înregistrați.
    3. Colectează alertele returnate și le trimite la Alerter.
    4. Afișează statistici la final (pachete procesate, alerte generate).

Arhitectura este extensibilă: adăugarea unui nou detector
se face printr-un singur apel la `engine.register(detector)`.
"""

from __future__ import annotations

from typing import Generator, List

from scapy.packet import Packet

from ids.alerter import Alert, Alerter
from ids.detectors.base import BaseDetector


class Engine:
    """
    Motor central al sistemului IDS.

    Parametri
    ---------
    alerter : Alerter
        Modulul de alertare care va primi și va loga alertele.
    """

    def __init__(self, alerter: Alerter) -> None:
        self._alerter = alerter
        self._detectors: List[BaseDetector] = []
        self._packet_count = 0
        self._alert_count = 0

    # ------------------------------------------------------------------
    # Înregistrare detectori
    # ------------------------------------------------------------------

    def register(self, detector: BaseDetector) -> None:
        """Adaugă un detector în lista de detectori activi."""
        self._detectors.append(detector)

    # ------------------------------------------------------------------
    # Procesare flux de pachete
    # ------------------------------------------------------------------

    def run(self, packets: Generator[Packet, None, None]) -> None:
        """
        Iterează un flux de pachete și rulează toți detectorii pe fiecare.

        Parametri
        ---------
        packets : Generator[Packet, None, None]
            Generator de pachete Scapy (ex. de la parser.read_pcap).
        """
        try:
            for packet in packets:
                self._packet_count += 1
                self._process_packet(packet)
        finally:
            self._alerter.close()
            self._print_summary()

    # ------------------------------------------------------------------
    # Procesare pachet individual
    # ------------------------------------------------------------------

    def _process_packet(self, packet: Packet) -> None:
        """Trimite pachetul la fiecare detector și emite alertele rezultate."""
        for detector in self._detectors:
            alerts: List[Alert] = detector.process_packet(packet)
            for alert in alerts:
                self._alert_count += 1
                self._alerter.emit(alert)

    # ------------------------------------------------------------------
    # Statistici finale
    # ------------------------------------------------------------------

    def _print_summary(self) -> None:
        print("\n" + "=" * 60)
        print(f"  Pachete procesate : {self._packet_count}")
        print(f"  Alerte generate   : {self._alert_count}")
        print("=" * 60)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def alert_count(self) -> int:
        return self._alert_count
