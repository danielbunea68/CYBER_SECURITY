"""
test_syn_scan.py — Teste unitare pentru SynScanDetector.

Pachetele sunt construite manual cu Scapy — nu avem nevoie de trafic real.
Se testează:
    - Detecție corectă la depășirea pragului de porturi.
    - Lipsa alertei sub prag.
    - Că pachetele SYN+ACK (răspunsuri normale) nu declanșează alertă.
    - Că fereastra de timp funcționează corect (pachete vechi nu contează).
    - Că reset() curăță starea corect.
"""

import time
import unittest

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from ids.config import SynScanConfig
from ids.detectors.syn_scan import SynScanDetector


def make_syn(src: str, dst: str, dport: int, ts: float = 0.0) -> Packet:
    """Construiește un pachet TCP SYN cu timestamp manual."""
    pkt = IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")
    pkt.time = ts
    return pkt


def make_synack(src: str, dst: str, dport: int, ts: float = 0.0) -> Packet:
    """Construiește un pachet TCP SYN+ACK (răspuns server)."""
    pkt = IP(src=src, dst=dst) / TCP(sport=dport, dport=50000, flags="SA")
    pkt.time = ts
    return pkt


class TestSynScanDetector(unittest.TestCase):

    def setUp(self):
        """Configurație cu prag mic (5 porturi în 10 secunde) pentru teste rapide."""
        cfg = SynScanConfig(port_threshold=5, time_window=10.0)
        self.detector = SynScanDetector(cfg)

    # ------------------------------------------------------------------
    # Test 1: Detecție normală — depășim pragul
    # ------------------------------------------------------------------
    def test_alert_when_threshold_exceeded(self):
        """Trebuie să genereze o alertă când un IP scanează >5 porturi."""
        alerts = []
        for port in range(1, 7):  # 6 porturi > prag de 5
            pkts = self.detector.process_packet(
                make_syn("10.0.0.1", "10.0.0.2", port, ts=float(port))
            )
            alerts.extend(pkts)

        self.assertEqual(len(alerts), 1, "Trebuie exact o alertă la depășirea pragului")
        alert = alerts[0]
        self.assertEqual(alert.attack_type, "TCP_SYN_SCAN")
        self.assertEqual(alert.src_ip, "10.0.0.1")
        self.assertEqual(alert.dst_ip, "10.0.0.2")
        self.assertEqual(alert.severity, "HIGH")

    # ------------------------------------------------------------------
    # Test 2: Sub prag — nicio alertă
    # ------------------------------------------------------------------
    def test_no_alert_below_threshold(self):
        """Nu trebuie alertă pentru mai puține porturi decât pragul."""
        alerts = []
        for port in range(1, 5):  # 4 porturi < prag de 5
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=1.0))
            )

        self.assertEqual(alerts, [], "Nu trebuie alertă sub prag")

    # ------------------------------------------------------------------
    # Test 3: SYN+ACK nu declanșează alerte
    # ------------------------------------------------------------------
    def test_synack_does_not_trigger(self):
        """Pachetele SYN+ACK (răspunsuri server) nu trebuie să genereze alerte."""
        alerts = []
        for port in range(1, 20):
            alerts.extend(
                self.detector.process_packet(
                    make_synack("10.0.0.2", "10.0.0.1", port, ts=float(port))
                )
            )

        self.assertEqual(alerts, [], "SYN+ACK nu trebuie să genereze alerte")

    # ------------------------------------------------------------------
    # Test 4: Fereastra de timp
    # ------------------------------------------------------------------
    def test_time_window_resets_old_packets(self):
        """Pachetele vechi (outside window) nu contribuie la prag."""
        # Trimitem 4 pachete vechi (la t=0)
        for port in range(1, 5):
            self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=0.0))

        # Acum trimitem un pachet nou la t=20 (depășit fereastra de 10s)
        # Pachetele de la t=0 nu mai sunt în fereastră → sub prag
        alerts = self.detector.process_packet(
            make_syn("10.0.0.1", "10.0.0.2", 5, ts=20.0)
        )
        self.assertEqual(alerts, [], "Pachetele din afara ferestrei nu trebuie să conteze")

    # ------------------------------------------------------------------
    # Test 5: Surse diferite sunt tratate independent
    # ------------------------------------------------------------------
    def test_different_sources_independent(self):
        """Scanuri de la IP-uri diferite nu se cumulează."""
        # Sursă 1 trimite 3 porturi
        for port in range(1, 4):
            self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=1.0))
        # Sursă 2 trimite alte 3 porturi
        alerts = []
        for port in range(4, 7):
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.99", "10.0.0.2", port, ts=1.0))
            )

        self.assertEqual(alerts, [], "Sursele diferite nu trebuie să se cumuleze")

    # ------------------------------------------------------------------
    # Test 6: Reset
    # ------------------------------------------------------------------
    def test_reset_clears_state(self):
        """reset() trebuie să șteargă starea internă."""
        for port in range(1, 7):
            self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=1.0))

        self.detector.reset()

        # După reset, aceleași pachete nu trebuie să fi acumulat stare
        alerts = []
        for port in range(1, 4):
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=2.0))
            )
        self.assertEqual(alerts, [], "Starea trebuie ștearsă după reset()")

    # ------------------------------------------------------------------
    # Test 7: O singură alertă per scan (fără duplicare)
    # ------------------------------------------------------------------
    def test_single_alert_per_scan(self):
        """Trebuie generată o singură alertă pentru un scan continuu."""
        alerts = []
        for port in range(1, 20):  # 19 porturi, mult peste prag
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=1.0))
            )

        self.assertEqual(len(alerts), 1, "Trebuie o singură alertă per scan, nu una per pachet")


if __name__ == "__main__":
    unittest.main()
