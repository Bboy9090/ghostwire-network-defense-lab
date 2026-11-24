import json
import os
import struct
import tempfile
import unittest

from security.network_detector import (
    NetworkIngestionError,
    build_network_timeline,
    correlate_network_to_processes,
    ingest_suricata_eve,
    is_suspicious_dns_domain,
    parse_pcap_bytes,
)


def _build_minimal_pcap_ipv4_tcp(src_port: int = 51234, dst_port: int = 4444) -> bytes:
    # Global header (little-endian, LINKTYPE_ETHERNET=1)
    ghdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # 14-byte Ethernet (IPv4 0x0800) + 20-byte IPv4 (proto=6 TCP) + 4-byte TCP ports
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ip_hdr = bytes([0x45, 0x00, 0x00, 0x18, 0, 1, 0, 0, 64, 6, 0, 0]) + bytes([10, 0, 0, 5]) + bytes([192, 168, 56, 99])
    tcp_ports = struct.pack("!HH", src_port, dst_port)
    pkt = eth + ip_hdr + tcp_ports
    phdr = struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt))
    return ghdr + phdr + pkt


class TestNetworkDetector(unittest.TestCase):
    def test_pcap_parse_and_suspicious_port(self):
        raw = _build_minimal_pcap_ipv4_tcp(src_port=51234, dst_port=4444)
        events = parse_pcap_bytes(raw, asset_id="sensor-1")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.payload["src_ip"], "10.0.0.5")
        self.assertEqual(ev.payload["dst_ip"], "192.168.56.99")
        self.assertEqual(ev.payload["dst_port"], 4444)
        self.assertTrue(ev.payload["suspicious_port"])
        self.assertEqual(ev.severity, "medium")

    def test_pcap_malformed_rejected(self):
        with self.assertRaises(NetworkIngestionError):
            parse_pcap_bytes(b"short")
        with self.assertRaises(NetworkIngestionError):
            parse_pcap_bytes(b"\x00" * 24)

    def test_suricata_eve_ingestion_correlate_and_timeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            eve_path = os.path.join(tmp, "eve.json")
            lines = [
                json.dumps({
                    "timestamp": "2026-11-23T12:00:01.000000+0000",
                    "event_type": "dns",
                    "src_ip": "10.0.0.5",
                    "src_port": 53001,
                    "dest_ip": "1.1.1.1",
                    "dest_port": 53,
                    "proto": "UDP",
                    "dns": {"rrname": "x9k2m7q4p8z1v6b3n5c8r2t4w.bad.example"},
                }),
                "{malformed-json",
                json.dumps({
                    "timestamp": "2026-11-23T12:00:02.000000+0000",
                    "event_type": "alert",
                    "src_ip": "10.0.0.5",
                    "src_port": 51234,
                    "dest_ip": "192.168.56.99",
                    "dest_port": 4444,
                    "proto": "TCP",
                    "alert": {"severity": 1, "signature": "ET MALWARE Reverse Shell", "signature_id": 2000001},
                }),
            ]
            with open(eve_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            events, malformed = ingest_suricata_eve(eve_path)
            self.assertEqual(malformed, 1)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].severity, "medium")
            self.assertEqual(events[1].event_category, "detection_alert")
            self.assertEqual(events[1].severity, "high")

            correlate_network_to_processes(
                events,
                [{"local_port": 51234, "remote_ip": "192.168.56.99", "remote_port": 4444, "pid": 4242, "process_name": "nc"}],
            )
            timeline = build_network_timeline(events)
            self.assertEqual(len(timeline), 2)
            self.assertEqual(timeline[1]["process"], "nc")

    def test_dns_entropy_heuristic(self):
        susp, _ = is_suspicious_dns_domain("a8f3k9m2q7x1z5c4v6b8n0p2r.evil.example")
        self.assertTrue(susp)
        clean, _ = is_suspicious_dns_domain("api.github.com")
        self.assertFalse(clean)


if __name__ == "__main__":
    unittest.main()
