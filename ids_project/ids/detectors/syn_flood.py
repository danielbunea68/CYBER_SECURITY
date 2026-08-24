"""
syn_flood.py — Detector pentru SYN Flood (atac DoS/DDoS).

==============================================================================
CUM FUNCȚIONEAZĂ ATACUL (nivel protocol)
==============================================================================
SYN Flood este un atac de tip Denial-of-Service care exploatează mecanismul
de gestionare a conexiunilor half-open din stiva TCP a serverului.

Procesul normal TCP (three-way handshake):
    Client --[SYN]-->        Server  (server alocă slot în SYN queue)
    Client <--[SYN+ACK]--    Server  (server trimite SYN-ACK, așteaptă ACK)
    Client --[ACK]-->         Server  (conexiunea e finalizată)

În atacul SYN Flood:
    Atacatorul --[SYN cu IP sursă fals/real]-->  Server
    Server <--[SYN+ACK]-- (trimis la IP fals, nu ajunge)
    Server **AȘTEAPTĂ ACK** timp de ~75 secunde (TCP timeout implicit)
    → slotul din SYN queue rămâne ocupat

Dacă atacatorul trimite mii de SYN-uri pe secundă:
    - SYN queue-ul serverului se umple (backlog epuizat).
    - Conexiunile legitime primesc RST sau timeout.
    - Serverul devine indisponibil (DoS).

RFC 4987 descrie această vulnerabilitate și mecanismele de apărare
(SYN cookies, reducerea timeout-ului, filtrare la firewall).

==============================================================================
DE CE SEMNĂTURA ALEASĂ ÎL TRĂDEAZĂ
==============================================================================
Semnătura SYN Flood diferă de SYN Scan prin:
    - ACELAȘI port destinație (atacul vizează un serviciu specific, ex. 80/443).
    - VOLUM MARE de SYN-uri în timp scurt (nu diversitate de porturi).
    - Lipsa ACK-urilor corespunzătoare.

Implementarea urmărește:
    - Per triplet (src_ip, dst_ip, dst_port): numărul de SYN-uri în fereastră.
    - Alertă dacă numărul depășește packet_threshold în time_window secunde.

Notă: Într-un atac DDoS real, src_ip poate fi spoofat sau distribuit.
Detectorul nostru funcționează optim pentru atacuri cu sursă unică/nefalsificată.

==============================================================================
LIMITĂRI ȘI TEHNICI DE EVASION
==============================================================================
1. IP Spoofing:
   Atacatorul poate falsifica IP-ul sursă (raw sockets). Fiecare pachet
   va părea să provină de la un IP diferit → niciun IP individual nu atinge
   pragul. Soluție: detectare bazată pe rată agregată per (dst_ip, dst_port)
   indiferent de sursă (implementat în varianta avansată cu dst_key).

2. Atac distribuit (DDoS):
   Zeci de mii de surse diferite → același efect ca IP spoofing la nivel
   de detecție per-sursă.

3. Mascarea sub trafic legitim:
   Un serviciu popular (ex. un server de jocuri la lansare) poate genera
   spikes legitime de SYN → fals pozitive. Pragul trebuie calibrat.

4. Slow SYN Flood:
   Rata e sub prag individual, dar cumulativă e suficientă să umple queue-ul.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from ids.alerter import Alert
from ids.config import SynFloodConfig
from ids.detectors.base import BaseDetector


class SynFloodDetector(BaseDetector):
    """
    Detectează SYN Flood prin monitorizarea volumului de pachete SYN
    fără ACK corespunzător, per (sursă, destinație, port destinație).

    Parametri
    ---------
    config : SynFloodConfig
        packet_threshold — numărul de SYN-uri care declanșează alertă.
        time_window      — fereastra de timp în secunde.
    """

    def __init__(self, config: SynFloodConfig) -> None:
        self._threshold = config.packet_threshold
        self._window = config.time_window

        # (src_ip, dst_ip, dst_port) -> listă de timestamps SYN
        self._syn_times: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)

        # (dst_ip, dst_port) -> listă de timestamps SYN (detectare DDoS agregat)
        self._dst_syn_times: Dict[Tuple[str, int], List[float]] = defaultdict(list)

        # Chei pentru care am alertat deja
        self._alerted_src: Set[Tuple[str, str, int]] = set()
        self._alerted_dst: Set[Tuple[str, int]] = set()

    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> List[Alert]:
        """
        Analizează pachetul și returnează alertă dacă se detectează SYN flood.

        Generează alerte la două niveluri:
            1. Per sursă-destinație-port (SYN flood clasic cu IP unic).
            2. Per destinație-port (SYN flood distribuit/DDoS).
        """
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return []

        tcp = packet[TCP]
        flags = tcp.flags

        # SYN pur (fără ACK)
        if not (flags & 0x02) or (flags & 0x10):
            return []

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst
        dst_port: int = tcp.dport
        ts: float = self.get_timestamp(packet)

        src_key = (src_ip, dst_ip, dst_port)
        dst_key = (dst_ip, dst_port)

        # Înregistrăm timestamp-ul
        self._syn_times[src_key].append(ts)
        self._dst_syn_times[dst_key].append(ts)

        alerts: List[Alert] = []

        # --- Detectare per sursă individuală ---
        alerts.extend(self._check_src(src_key, src_ip, dst_ip, dst_port, ts))

        # --- Detectare agregată per destinație (DDoS) ---
        alerts.extend(self._check_dst(dst_key, dst_ip, dst_port, ts))

        return alerts

    # ------------------------------------------------------------------
    # Metode private de verificare
    # ------------------------------------------------------------------

    def _check_src(
        self,
        key: Tuple[str, str, int],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        ts: float,
    ) -> List[Alert]:
        cutoff = ts - self._window
        self._syn_times[key] = [t for t in self._syn_times[key] if t >= cutoff]
        count = len(self._syn_times[key])

        if count >= self._threshold and key not in self._alerted_src:
            self._alerted_src.add(key)
            return [Alert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type="SYN_FLOOD",
                severity="CRITICAL",
                explanation=(
                    f"SYN Flood detectat: {src_ip} a trimis {count} pachete SYN "
                    f"către {dst_ip}:{dst_port} în ultimele {self._window:.0f}s "
                    f"fără ACK de completare (prag: {self._threshold} pachete). "
                    f"Posibil atac DoS."
                ),
            )]

        if count < self._threshold:
            self._alerted_src.discard(key)

        return []

    def _check_dst(
        self,
        key: Tuple[str, int],
        dst_ip: str,
        dst_port: int,
        ts: float,
    ) -> List[Alert]:
        """Verificare agregată — detectează DDoS de la surse multiple."""
        cutoff = ts - self._window
        self._dst_syn_times[key] = [t for t in self._dst_syn_times[key] if t >= cutoff]
        count = len(self._dst_syn_times[key])

        # Pragul agregat este de 5x față de cel per-sursă
        agg_threshold = self._threshold * 5

        if count >= agg_threshold and key not in self._alerted_dst:
            self._alerted_dst.add(key)
            return [Alert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip="MULTIPLE",
                dst_ip=dst_ip,
                attack_type="SYN_FLOOD_DISTRIBUTED",
                severity="CRITICAL",
                explanation=(
                    f"SYN Flood DISTRIBUIT (DDoS) detectat: {count} pachete SYN "
                    f"din surse multiple către {dst_ip}:{dst_port} "
                    f"în ultimele {self._window:.0f}s "
                    f"(prag agregat: {agg_threshold} pachete)."
                ),
            )]

        if count < agg_threshold:
            self._alerted_dst.discard(key)

        return []

    def reset(self) -> None:
        """Resetează starea internă."""
        self._syn_times.clear()
        self._dst_syn_times.clear()
        self._alerted_src.clear()
        self._alerted_dst.clear()
