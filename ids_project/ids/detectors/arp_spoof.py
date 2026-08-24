"""
arp_spoof.py — Detector pentru ARP Spoofing (ARP Poisoning).

==============================================================================
CUM FUNCȚIONEAZĂ ATACUL (nivel protocol)
==============================================================================
ARP (Address Resolution Protocol, RFC 826) rezolvă adrese IP în adrese MAC
în rețelele Ethernet locale (Layer 2 / Layer 3 boundary).

Procesul normal ARP:
    Host A vrea să comunice cu 192.168.1.1 dar nu știe MAC-ul.
    Host A --[ARP Request: "Cine are 192.168.1.1?"]-->  Broadcast
    Router --[ARP Reply:   "Eu! MAC = AA:BB:CC:DD:EE:FF"]--> Host A
    Host A stochează în ARP cache: 192.168.1.1 → AA:BB:CC:DD:EE:FF

Vulnerabilitatea fundamentală a ARP:
    - ARP este STATELESS și FĂRĂ AUTENTIFICARE.
    - Orice host poate trimite un ARP Reply la orice moment, fără să fi
      primit un ARP Request. Acesta se numește "Gratuitous ARP".
    - Sistemele de operare ACCEPTĂ și ACTUALIZEAZĂ ARP cache-ul cu aceste
      reply-uri nesolictate.

Scenariul de atac (Man-in-the-Middle):
    Atacator (IP: 192.168.1.100, MAC: EE:EE:EE:EE:EE:EE) vrea să intercepteze
    traficul dintre Host A (192.168.1.2) și Router (192.168.1.1).

    Pas 1: Otrăvirea Host A:
        Atacatorul trimite ARP Reply: "192.168.1.1 are MAC EE:EE:EE:EE:EE:EE"
        → Host A crede că router-ul e atacatorul.

    Pas 2: Otrăvirea Router-ului:
        Atacatorul trimite ARP Reply: "192.168.1.2 are MAC EE:EE:EE:EE:EE:EE"
        → Router-ul crede că Host A e atacatorul.

    Rezultat: Tot traficul dintre Host A și Router trece prin atacator
    (atacatorul activează IP forwarding pentru a nu întrerupe comunicarea).

Atacul permite: interceptare (sniffing), modificare pachete, injectare trafic.

==============================================================================
DE CE SEMNĂTURA ALEASĂ ÎL TRĂDEAZĂ
==============================================================================
Semnătura noastră se bazează pe inconsistența observată față de starea
anterioară a rețelei:

    Un ARP Reply asociază un IP (sender_protocol_addr)
    cu un MAC (sender_hardware_addr).
    Dacă acel IP a fost văzut anterior asociat cu un MAC DIFERIT,
    este o indicație clară de ARP Spoofing.

Implementarea menține un cache IP→MAC observat:
    - La primul ARP Reply pentru un IP: se înregistrează MAC-ul (fără alertă,
      dacă alert_on_first_seen=false).
    - La ARP Reply-urile ulterioare: dacă MAC-ul e diferit față de cel
      înregistrat → alertă.

Detectăm ATÂT ARP Reply-uri normale (op=2) CÂT ȘI Gratuitous ARP (op=2
cu IP sursă = IP destinație sau broadcast), care sunt principalul vector
de atac.

==============================================================================
LIMITĂRI ȘI TEHNICI DE EVASION
==============================================================================
1. Atacatorul trimite ARP cu MAC-ul legitim la început:
   Dacă atacatorul cunoaște MAC-ul legitim și îl folosește în primele pachete,
   stabileşte un baseline fals → schimbarea ulterioară e mai greu de detectat.

2. MAC-uri care se schimbă legitim:
   - DHCP lease expiry + reassignment (IP schimbă host-ul).
   - Interfețe de rețea înlocuite (hardware nou).
   - Virtual MAC-uri (VMware, Docker bridge).
   Acestea generează fals-pozitive → IDS-ul real trebuie să fie mai permisiv.

3. Atac rapid înainte de prima observare:
   Dacă IDS-ul nu a văzut niciodată IP-ul înainte de atac, nu are baseline.

4. Evitarea broadcast-ului:
   Un atacator sofisticat poate trimite ARP Reply unicast doar victimei,
   fără broadcast → IDS-ul pe un alt segment nu vede pachetul (depinde de
   poziționarea în rețea, ex. port mirroring).

5. Flooding ARP cache:
   Inundarea cu ARP Reply-uri diferite poate amortiza detecția dacă IDS-ul
   nu gestionează corect un număr mare de mapping-uri.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from ids.alerter import Alert
from ids.config import ArpSpoofConfig
from ids.detectors.base import BaseDetector


class ArpSpoofDetector(BaseDetector):
    """
    Detectează ARP Spoofing prin menținerea unui cache IP→MAC și alertarea
    la orice modificare neașteptată a mapping-ului.

    Parametri
    ---------
    config : ArpSpoofConfig
        alert_on_first_seen — dacă True, alertează și la prima apariție
        a unui IP (fără baseline). Default False.
    """

    def __init__(self, config: ArpSpoofConfig) -> None:
        self._alert_on_first_seen = config.alert_on_first_seen
        # Cache: ip_address -> mac_address (ultimul MAC legitim văzut)
        self._arp_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> List[Alert]:
        """
        Analizează pachetele ARP și returnează alertă dacă se detectează
        o schimbare de MAC pentru un IP cunoscut.

        Se analizează:
            - ARP Reply (op=2): răspunsuri la cereri ARP.
            - Gratuitous ARP: ARP Reply cu IP sursă == IP destinație.
        """
        if not packet.haslayer(ARP):
            return []

        arp = packet[ARP]

        # Procesăm doar ARP Reply (op=2)
        # op=1 = ARP Request (cine are IP?), op=2 = ARP Reply (eu am IP, MAC=X)
        if arp.op != 2:
            return []

        sender_ip: str = arp.psrc    # IP-ul expeditorului
        sender_mac: str = arp.hwsrc  # MAC-ul expeditorului

        # Ignorăm adrese IP nevalide sau broadcast
        if not sender_ip or sender_ip in ("0.0.0.0", "255.255.255.255"):
            return []

        # Ignorăm MAC-uri broadcast/multicast
        if sender_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return []

        alerts: List[Alert] = []

        if sender_ip not in self._arp_cache:
            # Prima dată când vedem acest IP
            if self._alert_on_first_seen:
                alerts.append(Alert(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    src_ip=sender_ip,
                    dst_ip=arp.pdst,
                    attack_type="ARP_NEW_MAPPING",
                    severity="LOW",
                    explanation=(
                        f"ARP: Prima apariție a IP-ului {sender_ip} "
                        f"asociat cu MAC {sender_mac}. "
                        f"Înregistrat în cache."
                    ),
                ))
            # Înregistrăm în cache
            self._arp_cache[sender_ip] = sender_mac

        else:
            known_mac = self._arp_cache[sender_ip]
            if known_mac.lower() != sender_mac.lower():
                # MAC-ul s-a schimbat → posibil ARP Spoofing!
                alerts.append(Alert(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    src_ip=sender_ip,
                    dst_ip=arp.pdst,
                    attack_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    explanation=(
                        f"ARP Spoofing detectat: IP-ul {sender_ip} "
                        f"și-a schimbat MAC-ul din '{known_mac}' în '{sender_mac}'. "
                        f"Posibil atac Man-in-the-Middle. "
                        f"ARP Reply primit de la {sender_mac} destinat spre {arp.pdst}."
                    ),
                ))
                # Actualizăm cache-ul cu noul MAC (pentru a detecta schimbări ulterioare)
                self._arp_cache[sender_ip] = sender_mac

        return alerts

    def reset(self) -> None:
        """Resetează cache-ul ARP (util pentru teste)."""
        self._arp_cache.clear()

    @property
    def arp_cache(self) -> Dict[str, str]:
        """Expune cache-ul ARP (read-only, util pentru debugging/teste)."""
        return dict(self._arp_cache)
