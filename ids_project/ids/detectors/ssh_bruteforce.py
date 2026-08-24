"""
ssh_bruteforce.py — Detector pentru SSH Brute-Force (port 22).

==============================================================================
CUM FUNCȚIONEAZĂ ATACUL (nivel protocol)
==============================================================================
SSH (Secure Shell, RFC 4253) operează implicit pe portul TCP 22 și furnizează
acces la distanță securizat prin criptare și autentificare.

Procesul de autentificare SSH:
    1. Client --[TCP SYN]--> Server:22          (stabilire conexiune TCP)
    2. Client <--[TCP SYN+ACK]-- Server
    3. Client --[TCP ACK]--> Server
    4. Client <--> Server: SSH Version exchange  (ex. "SSH-2.0-OpenSSH_8.9")
    5. Client <--> Server: Key exchange (Diffie-Hellman sau similar)
    6. Client --> Server: Autentificare (parolă sau cheie publică)
    7. Dacă autentificarea eșuează → server trimite SSH_MSG_USERAUTH_FAILURE
       și poate permite mai multe încercări (configurable în sshd_config).

Scenariul de brute-force:
    Atacatorul încearcă sistematic combinații de username:parolă.
    Fiecare încercare eșuată:
        - Poate reutiliza aceeași conexiune TCP (SSH permite N încercări
          per conexiune, default 6 în OpenSSH).
        - SAU poate deschide o conexiune TCP nouă pentru fiecare încercare
          (mai frecvent în tool-uri moderne ca Hydra, Medusa).

Instrumente comune de atac: Hydra, Medusa, Ncrack, Metasploit auxiliary.

==============================================================================
DE CE SEMNĂTURA ALEASĂ ÎL TRĂDEAZĂ
==============================================================================
La nivel de rețea (fără decriptare SSH), semnătura brute-force este:

    O singură adresă IP sursă inițiază N conexiuni TCP (SYN) sau
    completează N handshake-uri TCP (SYN+ACK+ACK) cu aceeași destinație
    pe portul 22 în intervalul T secunde.

Implementarea urmărește conexiunile TCP complete (SYN SETAT, detectăm
inițierea conexiunii, nu SSH în sine — IDS-ul nu decriptează). Aceasta
e o semnătură de Layer 3/4, nu Layer 7.

Alternativă mai precisă (Layer 7, dar necesită TLS inspection sau SSH proxy):
detectarea SSH_MSG_USERAUTH_FAILURE, imposibilă fără acces la sesiunea SSH.

Avantajul abordării Layer 3/4:
    - Funcționează fără a decripta traficul.
    - Nu necesită acces la cheile SSH.

Dezavantajul:
    - Confundă acces legitim cu brute-force dacă utilizatorul se reconectează
      frecvent (ex. script-uri de deployment).

==============================================================================
LIMITĂRI ȘI TEHNICI DE EVASION
==============================================================================
1. Distribuirea încercărilor (distributed brute-force):
   Atacatorul folosește mai multe IP-uri (botnet) → niciun IP individual
   nu atinge pragul. Soluție: monitorizare per destinație + corelație.

2. Slow brute-force:
   O încercare la câteva minute → sub pragul ferestrei de timp.
   Soluție: mărirea ferestrei, dar cresc și fals-pozitivele.

3. Reutilizarea sesiunii SSH:
   Atacatorul face N încercări pe aceeași conexiune TCP → mai puțini SYN-uri.
   Soluție: Layer 7 analysis sau monitorizarea duratei sesiunii SSH.

4. Port knocking sau port non-standard:
   Dacă SSH rulează pe un port non-standard (ex. 2222), detector trebuie
   reconfigurat. Configurat implicit pe portul 22.

5. Fail2ban și similar:
   Nu e o metodă de evasion față de IDS, ci o contramăsură defensivă care
   blochează IP-ul atacatorului după câteva eșecuri — complement al IDS-ului.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from ids.alerter import Alert
from ids.config import SshBruteforceConfig
from ids.detectors.base import BaseDetector

# Portul SSH default — ar putea fi extins la o listă configurabilă
SSH_PORT = 22


class SshBruteforceDetector(BaseDetector):
    """
    Detectează SSH brute-force prin numărarea conexiunilor TCP inițiate
    (SYN) de aceeași sursă către portul 22 al aceleiași destinații.

    Parametri
    ---------
    config : SshBruteforceConfig
        connection_threshold — numărul de SYN-uri care declanșează alertă.
        time_window          — fereastra de timp în secunde.
    """

    def __init__(self, config: SshBruteforceConfig) -> None:
        self._threshold = config.connection_threshold
        self._window = config.time_window

        # (src_ip, dst_ip) -> lista de timestamps ale conexiunilor SSH
        self._conn_times: Dict[Tuple[str, str], List[float]] = defaultdict(list)

        # Perechi alertate deja
        self._alerted: Set[Tuple[str, str]] = set()

    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> List[Alert]:
        """
        Analizează pachetele TCP SYN destinat portului 22.

        Returnează alertă dacă numărul de conexiuni inițiate depășește pragul.
        """
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return []

        tcp = packet[TCP]
        flags = tcp.flags

        # Vrem SYN pur (conexiune nouă) sau SYN+ACK (răspuns server)?
        # Urmărim SYN-uri de la CLIENT → SERVER (portul destinație = 22).
        # SYN fără ACK = inițierea conexiunii de către client.
        if not (flags & 0x02) or (flags & 0x10):
            return []

        # Verificăm că destinația e portul SSH
        if tcp.dport != SSH_PORT:
            return []

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst
        ts: float = self.get_timestamp(packet)

        key = (src_ip, dst_ip)
        self._conn_times[key].append(ts)

        # Eliminăm intrările vechi din afara ferestrei
        cutoff = ts - self._window
        self._conn_times[key] = [t for t in self._conn_times[key] if t >= cutoff]
        count = len(self._conn_times[key])

        alerts: List[Alert] = []

        if count >= self._threshold and key not in self._alerted:
            self._alerted.add(key)
            alerts.append(Alert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type="SSH_BRUTEFORCE",
                severity="HIGH",
                explanation=(
                    f"SSH Brute-Force detectat: {src_ip} a inițiat {count} conexiuni "
                    f"TCP către {dst_ip}:{SSH_PORT} în ultimele {self._window:.0f}s "
                    f"(prag: {self._threshold} conexiuni). "
                    f"Posibil atac de tip dicționar sau brute-force de credențiale SSH."
                ),
            ))

        # Resetăm flag-ul dacă ne-am întors sub prag (fereastră nouă)
        if count < self._threshold:
            self._alerted.discard(key)

        return alerts

    def reset(self) -> None:
        """Resetează starea internă."""
        self._conn_times.clear()
        self._alerted.clear()
