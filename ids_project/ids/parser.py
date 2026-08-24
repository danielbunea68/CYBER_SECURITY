"""
parser.py — Citire fișiere .pcap și iterare pachete.

Folosește Scapy pentru a citi fișiere pcap/pcapng și a returna
pachetele unul câte unul (generator), fără a le încărca pe toate
în memorie simultan — util pentru fișiere mari.

Fiecare pachet returnat este un obiect Scapy Packet cu atributele
standard (IP, TCP, UDP, ARP etc.).
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from scapy.packet import Packet
from scapy.utils import PcapReader


def read_pcap(path: str) -> Generator[Packet, None, None]:
    """
    Generator care citește pachetele dintr-un fișier .pcap/.pcapng.

    Parametri
    ---------
    path : str
        Calea către fișierul .pcap.

    Yields
    ------
    Packet
        Câte un obiect Scapy Packet per iterație.

    Raises
    ------
    FileNotFoundError
        Dacă fișierul nu există.
    """
    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Fișierul pcap nu a fost găsit: {path}")

    # PcapReader citește pachet cu pachet (lazy), nu tot fișierul odată.
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            yield packet


def count_packets(path: str) -> int:
    """
    Returnează numărul total de pachete dintr-un fișier pcap.
    Util pentru afișarea progresului.
    """
    return sum(1 for _ in read_pcap(path))
