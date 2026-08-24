"""
test_arp_spoof.py — Teste unitare pentru ArpSpoofDetector.

Se testează:
    - Nicio alertă la prima apariție a unui IP (alert_on_first_seen=False).
    - Alertă la schimbarea MAC pentru un IP cunoscut.
    - Că același MAC (re-anunțat) nu generează alertă.
    - ARP Request (op=1) nu generează alertă.
    - alert_on_first_seen=True generează alertă și la prima apariție.
    - Reset curăță cache-ul.
"""

import unittest

from scapy.layers.l2 import ARP, Ether

from ids.config import ArpSpoofConfig
from ids.detectors.arp_spoof import ArpSpoofDetector


def make_arp_reply(sender_ip: str, sender_mac: str, target_ip: str = "10.0.0.1") -> ARP:
    """Construiește un pachet ARP Reply (op=2)."""
    pkt = Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
    )
    pkt.time = 1.0
    return pkt


def make_arp_request(sender_ip: str, sender_mac: str, target_ip: str) -> ARP:
    """Construiește un pachet ARP Request (op=1)."""
    pkt = Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
    )
    pkt.time = 1.0
    return pkt


class TestArpSpoofDetector(unittest.TestCase):

    def setUp(self):
        cfg = ArpSpoofConfig(alert_on_first_seen=False)
        self.detector = ArpSpoofDetector(cfg)

    # ------------------------------------------------------------------
    # Test 1: Prima apariție — fără alertă (alert_on_first_seen=False)
    # ------------------------------------------------------------------
    def test_no_alert_on_first_seen(self):
        """Prima mapare IP->MAC nu trebuie să genereze alertă."""
        alerts = self.detector.process_packet(
            make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 2: ARP spoofing — MAC se schimbă
    # ------------------------------------------------------------------
    def test_alert_on_mac_change(self):
        """Schimbarea MAC pentru un IP cunoscut trebuie să genereze alertă CRITICAL."""
        # Înregistrăm MAC-ul original
        self.detector.process_packet(
            make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        )

        # Acum vine un ARP Reply cu MAC diferit pentru același IP
        alerts = self.detector.process_packet(
            make_arp_reply("192.168.1.1", "11:22:33:44:55:66")
        )

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.attack_type, "ARP_SPOOFING")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertIn("11:22:33:44:55:66", alert.explanation)
        self.assertIn("aa:bb:cc:dd:ee:ff", alert.explanation)

    # ------------------------------------------------------------------
    # Test 3: Același MAC re-anunțat — fără alertă
    # ------------------------------------------------------------------
    def test_no_alert_same_mac(self):
        """Re-anunțarea aceluiași MAC pentru același IP nu e suspicioasă."""
        mac = "aa:bb:cc:dd:ee:ff"
        self.detector.process_packet(make_arp_reply("192.168.1.1", mac))
        alerts = self.detector.process_packet(make_arp_reply("192.168.1.1", mac))
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 4: ARP Request nu generează alertă
    # ------------------------------------------------------------------
    def test_arp_request_no_alert(self):
        """ARP Request (op=1) nu trebuie să genereze alertă."""
        alerts = self.detector.process_packet(
            make_arp_request("192.168.1.100", "aa:bb:cc:dd:ee:ff", "192.168.1.1")
        )
        self.assertEqual(alerts, [])

    # ------------------------------------------------------------------
    # Test 5: alert_on_first_seen=True
    # ------------------------------------------------------------------
    def test_alert_on_first_seen_true(self):
        """Cu alert_on_first_seen=True, prima apariție trebuie să genereze alertă LOW."""
        cfg = ArpSpoofConfig(alert_on_first_seen=True)
        detector = ArpSpoofDetector(cfg)

        alerts = detector.process_packet(
            make_arp_reply("192.168.1.50", "aa:00:00:00:00:01")
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "ARP_NEW_MAPPING")
        self.assertEqual(alerts[0].severity, "LOW")

    # ------------------------------------------------------------------
    # Test 6: IP-uri diferite sunt independente
    # ------------------------------------------------------------------
    def test_different_ips_independent(self):
        """Mapările pentru IP-uri diferite nu se interferează."""
        self.detector.process_packet(make_arp_reply("192.168.1.1", "aa:bb:cc:dd:ee:01"))
        self.detector.process_packet(make_arp_reply("192.168.1.2", "aa:bb:cc:dd:ee:02"))

        # Schimbăm MAC pentru .1 — trebuie alertă doar pentru .1
        alerts = self.detector.process_packet(
            make_arp_reply("192.168.1.1", "ff:ff:00:00:00:01")
        )
        self.assertEqual(len(alerts), 1)
        self.assertIn("192.168.1.1", alerts[0].src_ip)

        # MAC pentru .2 rămâne neschimbat — fără alertă
        alerts2 = self.detector.process_packet(
            make_arp_reply("192.168.1.2", "aa:bb:cc:dd:ee:02")
        )
        self.assertEqual(alerts2, [])

    # ------------------------------------------------------------------
    # Test 7: Cache expus corect
    # ------------------------------------------------------------------
    def test_arp_cache_populated(self):
        """Cache-ul ARP trebuie actualizat corect după fiecare Reply."""
        self.detector.process_packet(make_arp_reply("10.0.0.1", "ca:fe:00:00:00:01"))
        self.detector.process_packet(make_arp_reply("10.0.0.2", "ca:fe:00:00:00:02"))

        cache = self.detector.arp_cache
        self.assertEqual(cache.get("10.0.0.1"), "ca:fe:00:00:00:01")
        self.assertEqual(cache.get("10.0.0.2"), "ca:fe:00:00:00:02")

    # ------------------------------------------------------------------
    # Test 8: Reset
    # ------------------------------------------------------------------
    def test_reset_clears_cache(self):
        """reset() trebuie să șteargă tot cache-ul ARP."""
        self.detector.process_packet(make_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff"))
        self.detector.reset()

        self.assertEqual(self.detector.arp_cache, {})

        # După reset, același IP cu alt MAC nu mai generează alertă (nu e în cache)
        alerts = self.detector.process_packet(
            make_arp_reply("10.0.0.1", "11:22:33:44:55:66")
        )
        self.assertEqual(alerts, [], "Fără cache, prima apariție nu e alertă (first_seen=False)")


if __name__ == "__main__":
    unittest.main()
