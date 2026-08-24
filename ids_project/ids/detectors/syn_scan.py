"""
syn_scan.py — Detector pentru TCP SYN Port Scan (Nmap-style).

==============================================================================
CUM FUNCȚIONEAZĂ ATACUL (nivel protocol)
==============================================================================
Un port scan SYN (cunoscut și ca "half-open scan" sau "stealth scan") este
tehnica de recunoaștere a porturilor deschise cel mai frecvent utilizată.

Mecanismul TCP normal (three-way handshake):
    Client  --[SYN]-->          Server
    Client  <--[SYN+ACK]--      Server   (portul e deschis)
    Client  --[ACK]-->           Server
    (conexiunea e stabilită)

    SAU, dacă portul e închis:
    Client  --[SYN]-->          Server
    Client  <--[RST+ACK]--      Server

Într-un SYN scan, atacatorul trimite SYN la fiecare port pe care vrea
să-l testeze, dar NU trimite niciodată ACK-ul final. Astfel:
    - Dacă primește SYN+ACK → portul este DESCHIS.
    - Dacă primește RST     → portul este ÎNCHIS.
    - Dacă nu primește nimic (timeout) → portul este FILTRAT (firewall).

Atacatorul trimite RST în loc de ACK pentru a "uita" conexiunea la nivel OS,
evitând logarea ei ca o conexiune completă.

==============================================================================
DE CE SEMNĂTURA ALEASĂ ÎL TRĂDEAZĂ
==============================================================================
Comportamentul normal al unui host nu implică contactarea a zeci de porturi
diferite pe același server în câteva secunde. Semnătura noastră:

    O singură adresă IP sursă trimite pachete TCP cu flag SYN SET
    către N porturi DISTINCTE ale aceleiași destinații
    în intervalul T secunde,
    FĂRĂ a finaliza niciodată handshake-ul (nu apare ACK de completare).

Implementarea urmărește:
    - Per pereche (src_ip, dst_ip): setul de porturi destinație SYN-uate.
    - O fereastră glisantă: porturile vechi (> time_window secunde) sunt
      eliminate din fereastră înainte de fiecare verificare.
    - O alertă se generează O SINGURĂ DATĂ per pereche (src, dst) per
      fereastră (flag `_alerted`) pentru a nu inunda log-ul.

==============================================================================
LIMITĂRI ȘI TEHNICI DE EVASION
==============================================================================
1. Scanare lentă (slow scan / low-and-slow):
   Atacatorul trimite câte un SYN la fiecare câteva secunde, sub pragul T.
   → Soluție parțială: mărirea ferestrei de timp (time_window), dar crește
     și rata fals-pozitivelor.

2. Scanare distribuită (distributed scan):
   Atacatorul folosește mai multe IP-uri sursă (botnet, spoofing), astfel
   încât niciun singur IP nu atinge pragul individual.
   → Soluție: corelarea pe baza altor atribute (TTL, window size, etc.).

3. Randomizarea porturilor:
   Dacă atacatorul scanează porturi în ordine aleatoare și cu pauze mari,
   poate fi confundat cu trafic legitim fragmentat.

4. IP Spoofing:
   Pachetele SYN au IP sursă falsificat → alertele vor acuza IP-ul greșit.

5. Encapsulare în tuneluri (VPN, Tor):
   Semnătura SYN e vizibilă doar dacă IDS-ul vede traficul neencriptat.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from ids.alerter import Alert
from ids.config import SynScanConfig
from ids.detectors.base import BaseDetector


class SynScanDetector(BaseDetector):
    """
    Detectează TCP SYN port scan prin monitorizarea numărului de porturi
    distincte contactate de o sursă pe o destinație în fereastra de timp.

    Parametri
    ---------
    config : SynScanConfig
        port_threshold — numărul de porturi distincte care declanșează alertă.
        time_window    — fereastra de timp în secunde.
    """

    def __init__(self, config: SynScanConfig) -> None:
        self._threshold = config.port_threshold
        self._window = config.time_window

        # (src_ip, dst_ip) -> lista de (timestamp, dst_port)
        self._events: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)

        # Perechi pentru care am generat deja o alertă în fereastra curentă
        # (evităm spam de alerte pentru același scan în desfășurare)
        self._alerted: Set[Tuple[str, str]] = set()

    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> List[Alert]:
        """
        Analizează pachetul și returnează o alertă dacă se detectează un scan.

        Condiții necesare:
            - Pachetul are layer IP și TCP.
            - Flag-ul SYN este setat și ACK NU este setat (SYN pur).
        """
        # Verificăm că avem IP + TCP cu SYN pur
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return []

        tcp = packet[TCP]
        flags = tcp.flags

        # SYN=0x02, ACK=0x10 — vrem SYN fără ACK
        if not (flags & 0x02) or (flags & 0x10):
            return []

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst
        dst_port: int = tcp.dport
        ts: float = self.get_timestamp(packet)

        key = (src_ip, dst_ip)
        self._events[key].append((ts, dst_port))

        # Curățăm evenimentele vechi din afara ferestrei de timp
        cutoff = ts - self._window
        self._events[key] = [(t, p) for t, p in self._events[key] if t >= cutoff]

        # Porturile distincte în fereastră
        distinct_ports: Set[int] = {p for _, p in self._events[key]}

        alerts: List[Alert] = []

        if len(distinct_ports) >= self._threshold and key not in self._alerted:
            self._alerted.add(key)
            alerts.append(Alert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type="TCP_SYN_SCAN",
                severity="HIGH",
                explanation=(
                    f"TCP SYN scan detectat: {src_ip} a trimis pachete SYN "
                    f"către {len(distinct_ports)} porturi distincte pe {dst_ip} "
                    f"în ultimele {self._window:.0f}s "
                    f"(prag: {self._threshold} porturi). "
                    f"Porturi: {sorted(distinct_ports)[:10]}{'...' if len(distinct_ports) > 10 else ''}."
                ),
            ))

        # Resetăm flag-ul de alertă dacă fereastra s-a golit sub prag
        # (permite re-detectare la un nou val de scan)
        if len(distinct_ports) < self._threshold and key in self._alerted:
            self._alerted.discard(key)

        return alerts

    def reset(self) -> None:
        """Resetează starea internă (util pentru teste unitare)."""
        self._events.clear()
        self._alerted.clear()
