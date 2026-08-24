# IDS Signature-Based — Proiect Academic Master Cybersecurity

Sistem de detecție a intruziunilor (Intrusion Detection System) bazat pe
semnături, implementat în Python cu Scapy. Analizează fișiere `.pcap` și
detectează atacuri de rețea prin reguli explicite, fără machine learning.

---

## Cuprins

1. [Arhitectură](#arhitectura)
2. [Instalare și rulare](#instalare-si-rulare)
3. [Configurare](#configurare)
4. [Atacuri detectate](#atacuri-detectate)
   - [TCP SYN Scan](#1-tcp-syn-scan)
   - [SYN Flood](#2-syn-flood-dos)
   - [ARP Spoofing](#3-arp-spoofing)
   - [SSH Brute-Force](#4-ssh-brute-force)
5. [Generare fișiere .pcap de test](#generare-fisiere-pcap-de-test)
6. [Rulare teste unitare](#rulare-teste-unitare)
7. [Plasarea în arhitectura de apărare](#plasarea-in-arhitectura-de-aparare)

---

## Arhitectura

```
ids_project/
├── ids/
│   ├── config.py          # Încărcare config.yaml → dataclasses tipizate
│   ├── parser.py          # Generator lazy de pachete Scapy din .pcap
│   ├── alerter.py         # Structura Alert + output consolă/JSON
│   ├── engine.py          # Motor central: distribuie pachete la detectori
│   └── detectors/
│       ├── base.py        # Clasă abstractă BaseDetector
│       ├── syn_scan.py    # TCP SYN port scan
│       ├── syn_flood.py   # SYN Flood DoS/DDoS
│       ├── arp_spoof.py   # ARP Spoofing / Poisoning
│       └── ssh_bruteforce.py  # SSH Brute-Force
├── tests/                 # Teste unitare cu pachete Scapy sintetice
├── logs/                  # Alerte JSON (generate la rulare)
├── config.yaml            # Configurare praguri și ferestre de timp
├── main.py                # Entry point CLI
└── requirements.txt
```

**Flux de date:**
```
[.pcap] → parser.py → engine.py → [detector 1, 2, 3, 4] → alerter.py → [consolă + JSON]
```

---

## Instalare si Rulare

### Cerințe

- Python 3.11+
- pip

### Instalare

```bash
# Clonează / navighează în directorul proiectului
cd ids_project

# (Recomandat) Crează un environment virtual
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Instalează dependențele
pip install -r requirements.txt
```

### Rulare

```bash
python main.py --pcap captures/test.pcap
python main.py --pcap captures/test.pcap --config config.yaml
```

### Argumente CLI

| Argument   | Implicit       | Descriere                          |
|------------|----------------|------------------------------------|
| `--pcap`   | (obligatoriu)  | Calea către fișierul .pcap         |
| `--config` | `config.yaml`  | Calea către fișierul de configurare |

### Output

- **Consolă:** Alerte colorate cu timestamp, severitate, IP-uri și explicație.
- **Fișier JSON:** `logs/alerts.json` (newline-delimited JSON, un obiect per linie).

Exemplu alertă JSON:
```json
{
  "timestamp": "2025-01-15T14:30:22.123456+00:00",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "attack_type": "TCP_SYN_SCAN",
  "severity": "HIGH",
  "explanation": "TCP SYN scan detectat: 192.168.1.100 a trimis pachete SYN către 25 porturi distincte pe 10.0.0.1 în ultimele 10s (prag: 20 porturi)."
}
```

---

## Configurare

Editează `config.yaml` pentru a ajusta pragurile:

```yaml
syn_scan:
  port_threshold: 20    # porturi distincte în fereastra de timp
  time_window: 10.0     # secunde

syn_flood:
  packet_threshold: 100 # SYN-uri fără ACK per (sursă, destinație, port)
  time_window: 5.0

ssh_bruteforce:
  connection_threshold: 10  # conexiuni TCP pe portul 22
  time_window: 30.0

arp_spoof:
  alert_on_first_seen: false  # true = alertă și la prima mapare IP->MAC

logging:
  console: true
  file: logs/alerts.json
  min_severity: LOW   # LOW | MEDIUM | HIGH | CRITICAL
```

---

## Atacuri Detectate

---

### 1. TCP SYN Scan

#### Mecanismul atacului

TCP SYN Scan (half-open scan) este tehnica standard de port scanning.
Atacatorul trimite pachete SYN la fiecare port și analizează răspunsul:
- **SYN+ACK** → portul este **deschis** (serviciu activ).
- **RST** → portul este **închis**.
- **Timeout / ICMP unreachable** → portul este **filtrat** (firewall).

Atacatorul trimite RST în loc de ACK pentru a nu finaliza handshake-ul TCP,
astfel conexiunea nu apare în log-urile aplicației server.

```
Atacator --[SYN]-->     Server:80    (port deschis)
Atacator <--[SYN+ACK]-- Server:80
Atacator --[RST]-->     Server:80    (abandon handshake)

Atacator --[SYN]-->     Server:81    (port închis)
Atacator <--[RST]--     Server:81
```

#### Semnătura detectată

O singură sursă IP trimite pachete TCP SYN (fără ACK) la **N porturi distincte**
ale **aceleiași destinații** în **T secunde**.

Detector: [syn_scan.py](ids/detectors/syn_scan.py)

#### Evasion techniques

| Tehnica | Descriere | Contramasura |
|---------|-----------|--------------|
| Slow scan | 1 SYN la câteva minute | Mărire time_window (cresc fals-pozitive) |
| Distributed scan | IP-uri diferite per port | Corelație inter-sursă |
| IP Spoofing | IP sursă falsificat | Alertă acuza IP greșit |
| Decoy scan (nmap -D) | SYN-uri de la IP-uri mambo + real | Greu de distins |

#### Plasare în arhitectura de apărare

Detectarea SYN scan este un **early warning indicator** — atacatorul adună
informații înainte de exploatare. Ideal se integrează cu:
- **Firewall** (block/rate-limit pe baza alertei).
- **Threat intelligence** (corelarea IP sursă cu liste de scanere cunoscute).
- **SIEM** (vizualizare tendințe de scanare în timp).

---

### 2. SYN Flood (DoS)

#### Mecanismul atacului

SYN Flood exploatează comportamentul stivei TCP în gestionarea conexiunilor
half-open (RFC 4987).

La fiecare SYN primit, serverul:
1. Alocă un slot în **SYN queue** (backlog).
2. Trimite SYN+ACK și pornește un timer (~75s implicit).
3. Așteaptă ACK-ul final.

Dacă atacatorul trimite mii de SYN-uri pe secundă (cu IP-uri false sau reale),
SYN queue-ul se umple → conexiunile legitime sunt respinse (DoS).

```
Atacator --[SYN src=1.2.3.4]-->  Server   (slot alocat în queue)
Atacator --[SYN src=1.2.3.5]-->  Server   (alt slot)
...×10000
Server: SYN queue PLIN → RST la conexiuni noi
Utilizator legitim --[SYN]--> Server  → RST (serviciu indisponibil)
```

#### Semnătura detectată

**Per sursă:** N pachete SYN de la același IP către același (dst_ip, dst_port)
în T secunde fără ACK corespunzător.

**Agregat (DDoS):** N×5 pachete SYN din surse multiple către același
(dst_ip, dst_port) → alertă `SYN_FLOOD_DISTRIBUTED`.

Detector: [syn_flood.py](ids/detectors/syn_flood.py)

#### Evasion techniques

| Tehnica | Descriere | Contramasura |
|---------|-----------|--------------|
| IP Spoofing | Sursă falsificată → fiecare SYN pare altă sursă | Detectare agregată pe destinație |
| DDoS | Mii de IP-uri reale (botnet) | Scrubbing center, BGP blackhole |
| Low-rate flood | Sub pragul per sursă | Agregare per destinație |

#### Contramasuri reale (NIDS complement)

- **SYN Cookies** (RFC 4987): serverul nu alocă slot până la completarea handshake-ului.
- **Firewall rate limiting**: DROP pachete SYN > N/s per IP.
- **Scrubbing centers**: traficul e redirecționat prin infrastructuri anti-DDoS.

---

### 3. ARP Spoofing

#### Mecanismul atacului

ARP (RFC 826) rezolvă IP → MAC în rețelele Ethernet locale, fără autentificare.

**Gratuitous ARP**: un host poate trimite ARP Reply fără să fi primit un Request,
iar toate sistemele din rețea actualizează ARP cache-ul local.

Scenariul Man-in-the-Middle:
```
Stare normală:
    Host A (10.0.0.2, MAC:A) <---> Router (10.0.0.1, MAC:R)

Atac:
    Atacator (10.0.0.100, MAC:E) trimite Gratuitous ARP:
        → Host A:   "10.0.0.1 are MAC:E"  (Host A trimite traficul la atacator)
        → Router:   "10.0.0.2 are MAC:E"  (Router trimite răspunsurile la atacator)

    Rezultat: Atacator interceptează TOT traficul dintre A și Router
```

#### Semnătura detectată

Un ARP Reply anunță IP=X cu MAC=Y, dar anterior IP=X fusese văzut cu MAC=Z (Z≠Y).

Detectorul menține un cache IP→MAC observat și alertează la orice modificare.

Detector: [arp_spoof.py](ids/detectors/arp_spoof.py)

#### Evasion techniques

| Tehnica | Descriere | Limitare detecție |
|---------|-----------|-------------------|
| Atac înainte de baseline | IDS nu a văzut IP-ul anterior | Prima mapare nu e detectată |
| MAC legitim inițial | Atacatorul cunoaște MAC-ul real | Schimbarea ulterioară e detectată |
| ARP unicast | Reply direct victimei, fără broadcast | IDS trebuie pe același segment |
| ARP cache flooding | Mii de mapări false | Poate copleși IDS-ul |

#### Contramasuri reale

- **DAI (Dynamic ARP Inspection)** pe switch-uri managed: validează ARP față de DHCP snooping table.
- **Static ARP entries** pentru gateway-uri critice.
- **802.1X** + segregare VLAN.

---

### 4. SSH Brute-Force

#### Mecanismul atacului

SSH (RFC 4253) permite autentificare cu parolă (keyboard-interactive) sau
cheie publică. Serverul permite implicit mai multe încercări per conexiune
(`MaxAuthTries` în `sshd_config`, default 6).

Atacatorul încearcă sistematic combinații username:parolă:

```
Atacator --[TCP SYN]-->         Server:22
Atacator <--[TCP SYN+ACK]--     Server
Atacator --[TCP ACK]-->          Server
Atacator <--> Server:            SSH handshake + key exchange
Atacator --> Server:             AUTH user="root" pass="password123"  → FAIL
Atacator --> Server:             AUTH user="root" pass="admin"        → FAIL
...×N
```

Tool-uri comune: **Hydra**, **Medusa**, **Ncrack**.

#### Semnătura detectată

La nivel Layer 3/4 (fără decriptare SSH): N pachete SYN de la același IP
sursă către `dst_ip:22` în T secunde.

Detector: [ssh_bruteforce.py](ids/detectors/ssh_bruteforce.py)

**Limitare importantă:** Nu vedem conținutul SSH (parolele încearcate), doar
că se inițiază conexiuni TCP repetate. Dacă atacatorul face N încercări pe
aceeași conexiune, generează un singur SYN → greu de detectat la Layer 4.

#### Evasion techniques

| Tehnica | Descriere | Contramasura |
|---------|-----------|--------------|
| Slow brute-force | 1 încercare la câteva minute | Mărire time_window |
| Distributed | IP-uri diferite per încercare | Corelație per destinație |
| Reutilizare sesiune | N parole per conexiune TCP | Layer 7 analysis (SSH proxy) |
| Port non-standard | SSH pe port 2222 | Reconfigurare `ssh_port` în config |

#### Contramasuri reale

- **Fail2ban**: blochează IP după K eșecuri (complementar IDS-ului).
- **SSH keys only**: dezactivare autentificare cu parolă în `sshd_config`.
- **Port knocking**: SSH activ doar după secvența de porturi corectă.
- **2FA/MFA**: autentificare în doi pași.

---

## Generare fisiere pcap de test

> **ATENȚIE**: Rulați aceste comenzi EXCLUSIV în medii de test izolate
> (lab virtual, mașini virtuale fără acces la internet, rețele dedicate testelor).
> Atacurile simulate sunt ilegale în rețele fără autorizare explicită.

### Opțiunea 1: Generare cu unelte de atac (mediu controlat)

```bash
# Captură trafic în fundal
tcpdump -i eth0 -w test.pcap &

# 1. TCP SYN Scan (nmap)
nmap -sS -p 1-1000 192.168.1.2

# 2. SYN Flood (hping3)
hping3 -S --flood -p 80 192.168.1.2

# 3. ARP Spoofing (arpspoof din dsniff)
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 192.168.1.2 192.168.1.1

# 4. SSH Brute-Force (hydra)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.2

# Oprire captură
kill %1
```

### Opțiunea 2: pcap-uri publice cu atacuri reale

Resurse publice cu pcap-uri de atac (pentru uz academic):

| Sursă | Conținut |
|-------|---------|
| [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) | Diverse protocoale |
| [NETRESEC PcapFiles](https://www.netresec.com/?page=PcapFiles) | Malware, atacuri |
| [CICIDS 2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) | DoS, Brute-Force, Scan |
| [CTF pcap collections](https://github.com/ctfs/) | Provocări CTF |

### Opțiunea 3: Generare sintetică cu Scapy (fără rețea reală)

```python
from scapy.all import *

packets = []
# SYN scan: 25 porturi de la 10.0.0.1 la 10.0.0.2
for port in range(1, 26):
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=port, flags="S")
    packets.append(pkt)

wrpcap("syn_scan_test.pcap", packets)
print("Generat syn_scan_test.pcap")
```

---

## Rulare teste unitare

```bash
# Din directorul rădăcină al proiectului (ids_project/)
python -m unittest discover -s tests -v

# Sau test individual
python -m unittest tests.test_syn_scan -v
python -m unittest tests.test_syn_flood -v
python -m unittest tests.test_arp_spoof -v
python -m unittest tests.test_ssh_bruteforce -v
```

Testele construiesc pachete Scapy sintetic și nu necesită fișiere pcap
sau trafic de rețea real.

---

## Plasarea in arhitectura de aparare

```
Internet
    │
    ▼
[Firewall / Router]
    │
    ├──► [IDS Network-based (NIDS)] ◄── Proiectul nostru (offline, pe pcap)
    │         Detectare: scan, flood, ARP, brute-force
    │         Output: alerte → SIEM
    │
    ▼
[Switch managed]
    │  DAI (Dynamic ARP Inspection) ← Contramasură ARP la Layer 2
    │  Port Security
    │
    ▼
[Servere / Hosts]
    │
    ├── [Host-based IDS (HIDS)] — Detectare la nivel OS (auditd, ossec)
    ├── [Fail2ban] — Răspuns automat la brute-force
    └── [SSH hardening] — Keys only, MaxAuthTries=3, port non-standard
```

**Locul proiectului:** NIDS offline (post-mortem analysis pe pcap).
Pentru producție, motorul s-ar conecta la un tap/mirror port de switch
sau la un broker de pachete (ex. trafic live via Scapy `sniff()`).

### Limitări generale ale abordării signature-based

1. **Zero-day attacks**: semnăturile detectează doar atacuri cunoscute.
2. **Encrypted traffic**: SYN scan/flood se detectează, dar payload-ul e opac.
3. **Evasion by design**: atacatorii cunoscuți pot calibra atacul sub praguri.
4. **Fals pozitive**: trafic legitim intens (CDN, load balancers) poate declanșa alerte.
5. **Poziționare în rețea**: IDS-ul trebuie să vadă traficul relevant (tap/mirror).

Complementul natural este **anomaly-based detection** (baseline + deviație statistică),
dar acela necesită date de antrenament și e mai predispus la fals pozitive inițiale.
