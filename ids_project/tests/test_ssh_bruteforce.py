"""
test_ssh_bruteforce.py — Teste unitare pentru SshBruteforceDetector.

Se testează:
    - Detecție la depășirea pragului de conexiuni SSH.
    - Lipsa alertei sub prag.
    - Că traficul non-SSH (alte porturi) nu declanșează alertă.
    - Că SYN+ACK (răspunsul serverului SSH) nu declanșează alertă.
    - Fereastra de timp.
    - Surse diferite sunt independente.
    - Reset.
"""

import unittest

from scapy.layers.inet import IP, TCP

from ids.config import SshBruteforceConfig
from ids.detectors.ssh_bruteforce import SSH_PORT, SshBruteforceDetector


def make_ssh_syn(src: str, dst: str, ts: float = 1.0):
    """SYN TCP către portul 22 (SSH)."""
    pkt = IP(src=src, dst=dst) / TCP(sport=55000, dport=SSH_PORT, flags="S")
    pkt.time = ts
    return pkt


def make_syn_to_port(src: str, dst: str, port: int, ts: float = 1.0):
    """SYN TCP către un port arbitrar."""
    pkt = IP(src=src, dst=dst) / TCP(sport=55000, dport=port, flags="S")
    pkt.time = ts
    return pkt


def make_ssh_synack(src: str, dst: str, ts: float = 1.0):
    """SYN+ACK de la serverul SSH (răspuns la conexiune)."""
    pkt = IP(src=src, dst=dst) / TCP(sport=SSH_PORT, dport=55000, flags="SA")
    pkt.time = ts
    return pkt


class TestSshBruteforceDetector(unittest.TestCase):

    def setUp(self):
        # Prag: 5 conexiuni în 30 secunde
        cfg = SshBruteforceConfig(connection_threshold=5, time_window=30.0)
        self.detector = SshBruteforceDetector(cfg)

    # ------------------------------------------------------------------
    # Test 1: Detecție normală
    # ------------------------------------------------------------------
    def test_alert_on_bruteforce(self):
        """Alertă la N conexiuni SSH de la aceeași sursă."""
        alerts = []
        for i in range(6):  # 6 > prag 5
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_syn("192.168.1.100", "10.0.0.1", ts=float(i))
                )
            )

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.attack_type, "SSH_BRUTEFORCE")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.src_ip, "192.168.1.100")
        self.assertEqual(alert.dst_ip, "10.0.0.1")

    # ------------------------------------------------------------------
    # Test 2: Sub prag
    # ------------------------------------------------------------------
    def test_no_alert_below_threshold(self):
        """Nicio alertă pentru mai puține conexiuni decât pragul."""
        alerts = []
        for i in range(4):  # 4 < prag 5
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_syn("192.168.1.100", "10.0.0.1", ts=float(i))
                )
            )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 3: Alt port — fără alertă
    # ------------------------------------------------------------------
    def test_non_ssh_port_no_alert(self):
        """SYN-uri pe porturi non-SSH nu declanșează detector SSH."""
        alerts = []
        for i in range(10):
            for port in [80, 443, 8080, 3389, 21]:
                alerts.extend(
                    self.detector.process_packet(
                        make_syn_to_port("192.168.1.100", "10.0.0.1", port, ts=float(i))
                    )
                )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 4: SYN+ACK de la server nu declanșează
    # ------------------------------------------------------------------
    def test_server_synack_no_alert(self):
        """Răspunsul SSH (SYN+ACK de la server) nu trebuie să genereze alertă."""
        alerts = []
        for i in range(10):
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_synack("10.0.0.1", "192.168.1.100", ts=float(i))
                )
            )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 5: Fereastra de timp
    # ------------------------------------------------------------------
    def test_time_window_expires(self):
        """Conexiunile vechi nu contează în fereastra curentă."""
        # 4 conexiuni la t=0
        for _ in range(4):
            self.detector.process_packet(make_ssh_syn("10.0.0.5", "10.0.0.1", ts=0.0))

        # 1 conexiune la t=100 (afară din fereastra de 30s)
        alerts = self.detector.process_packet(
            make_ssh_syn("10.0.0.5", "10.0.0.1", ts=100.0)
        )
        self.assertEqual(alerts, [], "Pachetele vechi nu trebuie să contribuie")

    # ------------------------------------------------------------------
    # Test 6: Surse diferite independente
    # ------------------------------------------------------------------
    def test_different_sources_independent(self):
        """Conexiunile de la IP-uri diferite nu se cumulează."""
        alerts = []
        for i in range(3):
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_syn("192.168.1.1", "10.0.0.1", ts=float(i))
                )
            )
        for i in range(3):
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_syn("192.168.1.2", "10.0.0.1", ts=float(i))
                )
            )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 7: O singură alertă per atac
    # ------------------------------------------------------------------
    def test_single_alert_per_attack(self):
        """Nu trebuie să se genereze mai multe alerte pentru același atac continuu."""
        alerts = []
        for i in range(20):  # mult peste prag
            alerts.extend(
                self.detector.process_packet(
                    make_ssh_syn("10.0.0.99", "10.0.0.1", ts=float(i) * 0.5)
                )
            )
        self.assertEqual(len(alerts), 1, "O singură alertă per atac continuu")

    # ------------------------------------------------------------------
    # Test 8: Reset
    # ------------------------------------------------------------------
    def test_reset(self):
        """reset() șterge starea complet."""
        for i in range(6):
            self.detector.process_packet(make_ssh_syn("10.0.0.1", "10.0.0.2", ts=float(i)))

        self.detector.reset()

        alerts = []
        for i in range(3):
            alerts.extend(
                self.detector.process_packet(make_ssh_syn("10.0.0.1", "10.0.0.2", ts=float(i)))
            )
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
