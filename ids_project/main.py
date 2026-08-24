"""
main.py — Punct de intrare pentru IDS-ul signature-based.

Utilizare:
    python main.py --pcap <fisier.pcap> [--config <config.yaml>]

Exemplu:
    python main.py --pcap captures/syn_scan.pcap
    python main.py --pcap captures/flood.pcap --config my_config.yaml
"""

from __future__ import annotations

import argparse
import sys

from ids.alerter import Alerter
from ids.config import load_config
from ids.detectors.arp_spoof import ArpSpoofDetector
from ids.detectors.ssh_bruteforce import SshBruteforceDetector
from ids.detectors.syn_flood import SynFloodDetector
from ids.detectors.syn_scan import SynScanDetector
from ids.engine import Engine
from ids.parser import read_pcap


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IDS Signature-Based — Analiză fișiere .pcap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Atacuri detectate:
  - TCP SYN Scan (port scanning)
  - SYN Flood (DoS/DDoS)
  - ARP Spoofing (Man-in-the-Middle)
  - SSH Brute-Force (credențiale)

Exemplu de generare pcap de test (într-un mediu izolat):
  Nmap SYN scan:   nmap -sS -p 1-1000 192.168.1.1 -oX - | tshark ...
  SYN flood:       hping3 -S --flood -p 80 192.168.1.1
  ARP spoof:       arpspoof -i eth0 -t 192.168.1.2 192.168.1.1
  SSH brute:       hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
        """,
    )
    parser.add_argument(
        "--pcap",
        required=True,
        metavar="FILE",
        help="Calea către fișierul .pcap de analizat",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="FILE",
        help="Calea către fișierul de configurare YAML (implicit: config.yaml)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # ------------------------------------------------------------------
    # 1. Încărcăm configurația
    # ------------------------------------------------------------------
    print(f"[*] Incarcare configuratie din: {args.config}")
    config = load_config(args.config)

    # ------------------------------------------------------------------
    # 2. Inițializăm modulul de alertare
    # ------------------------------------------------------------------
    alerter = Alerter(config.logging)
    print(f"[*] Alertele vor fi scrise in: {config.logging.file}")

    # ------------------------------------------------------------------
    # 3. Inițializăm motorul și înregistrăm detectorii
    # ------------------------------------------------------------------
    engine = Engine(alerter)

    engine.register(SynScanDetector(config.syn_scan))
    engine.register(SynFloodDetector(config.syn_flood))
    engine.register(ArpSpoofDetector(config.arp_spoof))
    engine.register(SshBruteforceDetector(config.ssh_bruteforce))

    print("[*] Detectori inregistrati: SYN Scan, SYN Flood, ARP Spoof, SSH BruteForce")

    # ------------------------------------------------------------------
    # 4. Citim fișierul pcap și rulăm analiza
    # ------------------------------------------------------------------
    print(f"[*] Analiza fisierului: {args.pcap}\n")

    try:
        packets = read_pcap(args.pcap)
        engine.run(packets)
    except FileNotFoundError as e:
        print(f"[EROARE] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[EROARE] Eroare neasteptata: {e}", file=sys.stderr)
        raise

    return 0


if __name__ == "__main__":
    sys.exit(main())
