"""
generate_test_pcap.py — Generator de fișiere .pcap sintetice pentru testarea IDS.

TRAFIC SINTETIC vs. TRAFIC REAL
================================
Pachetele generate de acest script sunt FABRICATE ÎN COD cu Scapy și salvate
direct în fișier .pcap, fără a implica nicio interfață de rețea, nicio VM și
niciun server real.

Diferențele față de traficul capturat cu tcpdump:
- Timestamp-uri manuale (incrementate uniform, nu din ceas real)
- TCP Sequence Numbers fixe (nu aleatoare cum ar genera un OS real)
- Lipsesc pachetele de răspuns (SYN+ACK, RST) ale serverului
- Lipsesc opțiunile TCP reale (MSS, SACK, Window Scaling)
- Zero trafic de fond (DNS, ARP normal, DHCP, ICMP keepalive)
- TTL și Window Size cu valori implicite Scapy

UTILITATE:
- Testarea LOGICII de detecție a IDS-ului (unit tests mai realiste)
- Demonstrații fără mediu de laborator
- CI/CD: testare automată fără infrastructură

LIMITĂRI:
- Nu reflectă zgomotul real al rețelei
- Nu testează robustețea față de evasion real (TTL manipulation etc.)
- Checksumurile TCP/IP sunt corecte (Scapy le calculează), dar restul
  câmpurilor nu sunt reprezentative pentru un OS real

Utilizare:
    python tools/generate_test_pcap.py [--output-dir DIR]

Fișiere generate:
    synthetic_syn_scan.pcap       — TCP SYN port scan
    synthetic_syn_flood.pcap      — SYN Flood DoS
    synthetic_syn_flood_ddos.pcap — SYN Flood distribuit (DDoS)
    synthetic_arp_spoof.pcap      — ARP Spoofing / Poisoning
    synthetic_ssh_bruteforce.pcap — SSH Brute-Force
    synthetic_mixed.pcap          — Toate atacurile combinate
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

# ---------------------------------------------------------------------------
# Constante — adrese folosite în pachetele sintetice
# ---------------------------------------------------------------------------

ATTACKER_IP  = "10.0.0.100"      # IP sursă al "atacatorului"
VICTIM_IP    = "10.0.0.1"        # IP destinație al "victimei"
GATEWAY_IP   = "10.0.0.254"      # IP gateway (pentru scenariul ARP)

ATTACKER_MAC = "aa:bb:cc:00:00:01"
VICTIM_MAC   = "aa:bb:cc:00:00:02"
GATEWAY_MAC  = "aa:bb:cc:00:00:fe"
SPOOF_MAC    = "ee:ee:ee:ee:ee:ee"   # MAC-ul "atacatorului" în ARP spoof

SSH_PORT = 22


# ===========================================================================
# 1. TCP SYN SCAN
# ===========================================================================

def build_syn_scan(
    src_ip: str = ATTACKER_IP,
    dst_ip: str = VICTIM_IP,
    ports: range = range(1, 1001),   # 1000 porturi scanate
    base_ts: float = 0.0,
    interval: float = 0.005,         # 5ms între pachete → ~200 pps
) -> List[Packet]:
    """
    Construiește un SYN scan: pachete TCP SYN de la src_ip
    la dst_ip pe fiecare port din `ports`, la interval de `interval` secunde.

    Semnătura detectată de IDS:
        O sursă trimite SYN la N porturi distincte ale aceleiași destinații
        în T secunde, fără ACK.

    În realitate (nmap -sS):
        - Și pachetele RST trimise după SYN+ACK ar fi prezente
        - Opțiunile TCP (MSS, NOP) ar fi incluse
        - ISN (Initial Sequence Number) ar fi aleatoriu per pachet
    """
    packets: List[Packet] = []
    sport = 60000  # port sursă fix (nmap folosește porturi aleatorii, dar
                   # pentru sintetice e mai simplu)

    for i, dport in enumerate(ports):
        pkt = (
            Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / IP(src=src_ip, dst=dst_ip, ttl=64)
            / TCP(
                sport=sport,
                dport=dport,
                flags="S",           # SYN
                seq=1000 + i,        # secvență incrementală (fix, nu aleatoriu)
                window=8192,
            )
        )
        pkt.time = base_ts + i * interval
        packets.append(pkt)

    return packets


# ===========================================================================
# 2. SYN FLOOD (per sursă)
# ===========================================================================

def build_syn_flood(
    src_ip: str = ATTACKER_IP,
    dst_ip: str = VICTIM_IP,
    dst_port: int = 80,
    count: int = 500,                # număr de pachete SYN
    base_ts: float = 0.0,
    interval: float = 0.002,        # 2ms → 500 pps
) -> List[Packet]:
    """
    Construiește un SYN Flood: `count` pachete SYN de la aceeași sursă
    către același (dst_ip, dst_port).

    Semnătura detectată de IDS:
        N pachete SYN de la același IP sursă pe același port în T secunde.

    În realitate (hping3 --syn --flood):
        - Trimite sute de mii de pachete pe secundă
        - --rand-source schimbă IP-ul sursă per pachet
        - Interfața de rețea poate satura (> 100Mbps pentru SYN mici)
        - SYN queue-ul serverului se umple în câteva secunde
    """
    packets: List[Packet] = []

    for i in range(count):
        pkt = (
            Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / IP(src=src_ip, dst=dst_ip, ttl=64)
            / TCP(
                sport=40000 + (i % 5000),   # port sursă variabil (5000 valori)
                dport=dst_port,
                flags="S",
                seq=i * 100,
                window=65535,
            )
        )
        pkt.time = base_ts + i * interval
        packets.append(pkt)

    return packets


# ===========================================================================
# 3. SYN FLOOD DISTRIBUIT (DDoS simulat)
# ===========================================================================

def build_syn_flood_ddos(
    dst_ip: str = VICTIM_IP,
    dst_port: int = 443,
    num_sources: int = 200,           # 200 IP-uri sursă diferite
    packets_per_source: int = 5,      # 5 pachete per sursă = 1000 total
    base_ts: float = 0.0,
    interval: float = 0.001,
) -> List[Packet]:
    """
    Construiește un SYN Flood distribuit: pachete SYN de la `num_sources`
    IP-uri sursă diferite, simulând un DDoS cu surse multiple.

    Semnătura detectată de IDS:
        Detector SYN_FLOOD_DISTRIBUTED: N pachete agregate per (dst_ip, dst_port)
        din surse multiple în T secunde (pragul agregat = packet_threshold × 5).

    În realitate (hping3 --rand-source):
        - IP-urile sursă sunt spoofate (raw socket) la nivel OS
        - Nu există handshake real (IP-ul sursă nu există sau nu aparține
          atacatorului)
        - Răspunsurile SYN+ACK ale serverului sunt pierdute în Internet
    """
    packets: List[Packet] = []
    ts = base_ts

    for src_idx in range(num_sources):
        # Generăm IP-uri sursă din spații diferite de adrese
        a = 10 + (src_idx // 65536)
        b = (src_idx // 256) % 256
        c = src_idx % 256
        src_ip = f"{a}.{b}.{c}.{(src_idx % 254) + 1}"

        for pkt_idx in range(packets_per_source):
            pkt = (
                Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
                / IP(src=src_ip, dst=dst_ip, ttl=64)
                / TCP(
                    sport=1024 + pkt_idx,
                    dport=dst_port,
                    flags="S",
                    seq=pkt_idx * 100,
                    window=65535,
                )
            )
            pkt.time = ts
            ts += interval
            packets.append(pkt)

    return packets


# ===========================================================================
# 4. ARP SPOOFING
# ===========================================================================

def build_arp_spoof(
    victim_ip: str = VICTIM_IP,
    gateway_ip: str = GATEWAY_IP,
    legitimate_gateway_mac: str = GATEWAY_MAC,
    attacker_mac: str = SPOOF_MAC,
    base_ts: float = 0.0,
) -> List[Packet]:
    """
    Construiește scenariul ARP Spoofing în 3 faze:

    Faza 1 — Trafic ARP normal (baseline):
        Gateway-ul se anunță cu MAC-ul său real.
        IDS-ul înregistrează: gateway_ip → legitimate_gateway_mac.

    Faza 2 — Atacul:
        Atacatorul trimite Gratuitous ARP Reply:
        "gateway_ip are MAC attacker_mac"
        IDS-ul detectează: MAC s-a schimbat → ARP_SPOOFING.

    Faza 3 — Continuare atac:
        Atacatorul continuă să trimită ARP Reply-uri pentru a menține
        otrăvirea cache-ului (ARP cache are TTL de câteva minute).

    În realitate (arpspoof / Gratuitous ARP):
        - Atacatorul trimite ARP Reply la fiecare 1-2 secunde
        - Activează IP forwarding pentru a nu întrerupe traficul (MitM)
        - Victima continuă să comunice, traficul trece prin atacator
        - Atacatorul poate rula tools precum Wireshark sau Burp Suite
          pentru a inspecta/modifica traficul interceptat
    """
    packets: List[Packet] = []

    # ------------------------------------------------------------------
    # Faza 1: ARP normal — gateway se anunță cu MAC legitim (3 pachete)
    # Acestea stabilesc baseline-ul în cache-ul IDS-ului.
    # ------------------------------------------------------------------
    for i in range(3):
        pkt = (
            Ether(src=legitimate_gateway_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,                            # ARP Reply
                hwsrc=legitimate_gateway_mac,    # MAC real al gateway-ului
                psrc=gateway_ip,                 # IP-ul gateway-ului
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=victim_ip,
            )
        )
        pkt.time = base_ts + i * 2.0  # un Reply la 2 secunde (normal)
        packets.append(pkt)

    # ------------------------------------------------------------------
    # Faza 2: ATAC — atacatorul trimite ARP Reply cu MAC falsificat
    # IDS-ul detectează că MAC-ul pentru gateway_ip s-a schimbat.
    # ------------------------------------------------------------------
    attack_start = base_ts + 8.0

    spoof_pkt = (
        Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,                  # ARP Reply (Gratuitous ARP)
            hwsrc=attacker_mac,    # MAC-ul atacatorului — DIFERIT de cel real
            psrc=gateway_ip,       # Se pretinde a fi gateway-ul
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=victim_ip,
        )
    )
    spoof_pkt.time = attack_start
    packets.append(spoof_pkt)

    # ------------------------------------------------------------------
    # Faza 3: Continuare atac — la fiecare 2 secunde
    # Menține otrăvirea (ARP cache se resetează fără reînnoire)
    # ------------------------------------------------------------------
    for i in range(1, 5):
        renewal = (
            Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                hwsrc=attacker_mac,
                psrc=gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=victim_ip,
            )
        )
        renewal.time = attack_start + i * 2.0
        packets.append(renewal)

    return packets


# ===========================================================================
# 5. SSH BRUTE-FORCE
# ===========================================================================

def build_ssh_bruteforce(
    src_ip: str = ATTACKER_IP,
    dst_ip: str = VICTIM_IP,
    num_attempts: int = 30,         # 30 tentative de autentificare
    base_ts: float = 0.0,
    interval: float = 0.3,         # 300ms între tentative (realistic pentru Hydra)
) -> List[Packet]:
    """
    Construiește scenariul SSH Brute-Force la nivel Layer 4 (TCP).

    Fiecare tentativă de autentificare SSH implică:
        1. TCP SYN (conexiune nouă)     ← ce detectăm
        2. TCP SYN+ACK (răspuns server) ← absent în sintetic
        3. TCP ACK (completare handshake)
        4. SSH handshake + autentificare (criptat)
        5. TCP FIN/RST (la eșec)

    Acest generator produce DOAR pachetele SYN (inițierea conexiunii),
    deoarece IDS-ul nostru detectează la nivelul SYN-urilor (Layer 4).

    În realitate (Hydra -l user -P wordlist ssh://ip):
        - Hydra deschide N conexiuni TCP paralele (-t N)
        - Fiecare conexiune face SSH handshake complet (DH key exchange)
        - Dacă autentificarea eșuează → SSH_MSG_USERAUTH_FAILURE (criptat)
        - Hydra închide conexiunea și deschide alta pentru următoarea parolă
        - Serverul SSH logează în /var/log/auth.log:
          "Failed password for user from IP port PORT ssh2"

    Observație sintetică importantă:
        Pachetele de mai jos simulează DOAR SYN-urile (conexiunile inițiate),
        nu și handshake-ul SSH complet. Un pcap real ar conține de ~10-20×
        mai multe pachete per tentativă (TCP handshake + SSH frames).
    """
    packets: List[Packet] = []

    for i in range(num_attempts):
        # Fiecare tentativă = un TCP SYN nou de la un port sursă diferit
        # (sistemul de operare alocă porturi efemere sequential sau aleatoriu)
        sport = 49152 + (i % 16384)   # porturi efemere: 49152-65535

        pkt = (
            Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / IP(src=src_ip, dst=dst_ip, ttl=64)
            / TCP(
                sport=sport,
                dport=SSH_PORT,   # 22
                flags="S",
                seq=i * 1000,
                window=65535,
            )
        )
        pkt.time = base_ts + i * interval
        packets.append(pkt)

    return packets


# ===========================================================================
# 6. MIXED — toate atacurile combinate
# ===========================================================================

def build_mixed_capture() -> List[Packet]:
    """
    Combină toate tipurile de atac într-un singur pcap, cu trafic de fond
    minimal (câteva pachete ARP normale) între atacuri.

    Util pentru testarea că IDS-ul detectează corect în prezența traficului
    mixt și că detectorii nu se interferează între ei.

    Ordinea temporală:
        t=0s     ARP normal (baseline)
        t=5s     SYN Scan (10s durată)
        t=20s    SYN Flood (5s durată)
        t=30s    ARP Spoofing (atac)
        t=45s    SSH Brute-Force (9s durată)
    """
    all_packets: List[Packet] = []

    # Trafic ARP normal pentru a stabili baseline
    normal_arp = (
        Ether(src=GATEWAY_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=GATEWAY_MAC, psrc=GATEWAY_IP,
              hwdst="ff:ff:ff:ff:ff:ff", pdst=VICTIM_IP)
    )
    normal_arp.time = 0.5
    all_packets.append(normal_arp)

    # 1. SYN Scan pe primele 100 porturi (la t=5s, durată ~0.5s)
    all_packets.extend(
        build_syn_scan(ports=range(1, 101), base_ts=5.0, interval=0.005)
    )

    # 2. SYN Flood pe portul 80 (la t=20s, 200 pachete)
    all_packets.extend(
        build_syn_flood(count=200, base_ts=20.0, interval=0.005)
    )

    # 3. ARP Spoofing (la t=30s)
    all_packets.extend(build_arp_spoof(base_ts=30.0))

    # 4. SSH Brute-Force (la t=45s, 20 tentative)
    all_packets.extend(
        build_ssh_bruteforce(num_attempts=20, base_ts=45.0, interval=0.3)
    )

    # Sortăm după timestamp pentru a respecta ordinea temporală
    all_packets.sort(key=lambda p: float(p.time))

    return all_packets


# ===========================================================================
# Funcție utilitară de scriere
# ===========================================================================

def write_pcap(packets: List[Packet], path: str, description: str) -> None:
    """Scrie lista de pachete în fișier .pcap și afișează statistici."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    wrpcap(path, packets)

    if packets:
        duration = float(packets[-1].time) - float(packets[0].time)
    else:
        duration = 0.0

    print(
        f"  [OK] {os.path.basename(path):45s} "
        f"{len(packets):>5} pachete  "
        f"durata ~{duration:.1f}s"
        f"  ({description})"
    )


# ===========================================================================
# Entry point
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generator de fișiere .pcap sintetice pentru testarea IDS.\n"
            "Pachetele sunt fabricate cu Scapy — NU trafic de rețea real."
        )
    )
    parser.add_argument(
        "--output-dir",
        default="captures",
        metavar="DIR",
        help="Directorul în care se salvează fișierele .pcap (implicit: captures/)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = args.output_dir

    print("=" * 70)
    print("  Generator .pcap sintetic — IDS Signature-Based")
    print("  ATENȚIE: Pachetele sunt SINTETICE (Scapy), nu trafic real!")
    print("=" * 70)
    print(f"\n  Director output: {out}/\n")

    # ------------------------------------------------------------------
    # Generăm fiecare tip de atac
    # ------------------------------------------------------------------

    # 1. SYN Scan — 500 porturi în ~2.5s (200 pps)
    write_pcap(
        build_syn_scan(ports=range(1, 501), interval=0.005),
        f"{out}/synthetic_syn_scan.pcap",
        "SYN scan pe 500 porturi",
    )

    # 2. SYN Flood per sursă — 300 pachete SYN pe portul 80
    write_pcap(
        build_syn_flood(count=300, dst_port=80),
        f"{out}/synthetic_syn_flood.pcap",
        "SYN flood per sursă, port 80",
    )

    # 3. SYN Flood distribuit — 200 surse × 5 pachete = 1000 SYN-uri
    write_pcap(
        build_syn_flood_ddos(num_sources=200, packets_per_source=5),
        f"{out}/synthetic_syn_flood_ddos.pcap",
        "SYN flood distribuit (DDoS), 200 surse",
    )

    # 4. ARP Spoofing — baseline + atac + continuare
    write_pcap(
        build_arp_spoof(),
        f"{out}/synthetic_arp_spoof.pcap",
        "ARP spoofing (MitM)",
    )

    # 5. SSH Brute-Force — 30 tentative la 300ms interval
    write_pcap(
        build_ssh_bruteforce(num_attempts=30, interval=0.3),
        f"{out}/synthetic_ssh_bruteforce.pcap",
        "SSH brute-force, 30 tentative",
    )

    # 6. Mixed — toate atacurile combinate
    write_pcap(
        build_mixed_capture(),
        f"{out}/synthetic_mixed.pcap",
        "Toate atacurile combinate",
    )

    print(f"\n  Gata! Rulati IDS-ul pe fisierele generate:")
    print(f"    python main.py --pcap {out}/synthetic_syn_scan.pcap")
    print(f"    python main.py --pcap {out}/synthetic_mixed.pcap")
    print()
    print("  Diferenta fata de trafic REAL:")
    print("    - Lipsesc SYN+ACK, RST (raspunsurile serverului)")
    print("    - Timestamp-uri uniforme (nu naturale)")
    print("    - Lipsesc optiunile TCP (MSS, SACK, timestamps)")
    print("    - Zero trafic de fond (DNS, ARP normal, DHCP)")
    print("    - Sequence numbers predictibile (nu random ca la OS real)")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
