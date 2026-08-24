"""
test_syn_flood.py — Teste unitare pentru SynFloodDetector.

Se testează:
    - Detecție per sursă (SYN flood clasic).
    - Detecție distribuită/agregată per destinație (DDoS).
    - Absența alertei sub prag.
    - Că SYN+ACK nu declanșează.
    - Fereastra de timp.
"""

import unittest

from scapy.layers.inet import IP, TCP

from ids.config import SynFloodConfig
from ids.detectors.syn_flood import SynFloodDetector


def make_syn(src: str, dst: str, dport: int, ts: float = 1.0):
    pkt = IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    pkt.time = ts
    return pkt


class TestSynFloodDetector(unittest.TestCase):

    def setUp(self):
        # Prag mic pentru teste: 10 pachete în 5 secunde
        cfg = SynFloodConfig(packet_threshold=10, time_window=5.0)
        self.detector = SynFloodDetector(cfg)

    # ------------------------------------------------------------------
    # Test 1: SYN flood per sursă
    # ------------------------------------------------------------------
    def test_alert_on_syn_flood_single_source(self):
        """Alertă la N SYN-uri de la aceeași sursă pe același port."""
        alerts = []
        for i in range(15):  # 15 > prag 10
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", 80, ts=float(i) * 0.1))
            )

        syn_flood_alerts = [a for a in alerts if a.attack_type == "SYN_FLOOD"]
        self.assertEqual(len(syn_flood_alerts), 1)
        self.assertEqual(syn_flood_alerts[0].severity, "CRITICAL")
        self.assertEqual(syn_flood_alerts[0].src_ip, "10.0.0.1")

    # ------------------------------------------------------------------
    # Test 2: Sub prag — nicio alertă
    # ------------------------------------------------------------------
    def test_no_alert_below_threshold(self):
        """Nicio alertă pentru mai puține SYN-uri decât pragul."""
        alerts = []
        for i in range(9):  # 9 < prag 10
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", 80, ts=float(i) * 0.1))
            )

        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 3: SYN flood distribuit (DDoS)
    # ------------------------------------------------------------------
    def test_distributed_syn_flood_alert(self):
        """Alertă distribuită când N*5 SYN-uri vin din surse diferite."""
        alerts = []
        # 51 surse diferite → 51 pachete → depășim 10*5=50
        for i in range(51):
            src = f"10.0.{i // 256}.{i % 256}"
            alerts.extend(
                self.detector.process_packet(make_syn(src, "10.0.0.2", 443, ts=1.0))
            )

        ddos_alerts = [a for a in alerts if a.attack_type == "SYN_FLOOD_DISTRIBUTED"]
        self.assertGreaterEqual(len(ddos_alerts), 1, "Trebuie alertă DDoS")
        self.assertEqual(ddos_alerts[0].src_ip, "MULTIPLE")

    # ------------------------------------------------------------------
    # Test 4: Porturi diferite nu se cumulează per sursă
    # ------------------------------------------------------------------
    def test_different_ports_not_cumulated(self):
        """SYN-uri pe porturi DIFERITE de la aceeași sursă nu declanșează
        SYN flood (asta ar fi SYN scan). Verificăm că flood-ul e per port."""
        alerts = []
        for port in range(1, 15):  # 14 porturi diferite, câte 1 SYN fiecare
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", port, ts=1.0))
            )

        flood_alerts = [a for a in alerts if a.attack_type == "SYN_FLOOD"]
        self.assertEqual(flood_alerts, [], "SYN-uri pe porturi diferite nu sunt flood")

    # ------------------------------------------------------------------
    # Test 5: Fereastra de timp
    # ------------------------------------------------------------------
    def test_time_window(self):
        """Pachete vechi nu contribuie la flood în fereastra curentă."""
        # 9 pachete la t=0
        for i in range(9):
            self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", 80, ts=0.0))

        # 1 pachet la t=100 (depășit fereastra de 5s)
        alerts = self.detector.process_packet(
            make_syn("10.0.0.1", "10.0.0.2", 80, ts=100.0)
        )
        flood_alerts = [a for a in alerts if a.attack_type == "SYN_FLOOD"]
        self.assertEqual(flood_alerts, [], "Pachetele vechi nu trebuie să conteze")

    # ------------------------------------------------------------------
    # Test 6: Reset
    # ------------------------------------------------------------------
    def test_reset(self):
        """reset() curăță complet starea."""
        for i in range(15):
            self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", 80, ts=float(i) * 0.1))

        self.detector.reset()

        alerts = []
        for i in range(5):
            alerts.extend(
                self.detector.process_packet(make_syn("10.0.0.1", "10.0.0.2", 80, ts=float(i) * 0.1))
            )
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
