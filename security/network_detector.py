"""Ghostwire Network Threat Detection (Module C).

Passive offline network analysis supporting:
- Safe bounded PCAP parsing (IPv4/TCP/UDP) with malformed-input protection
- Suricata EVE JSON ingestion normalized to Ghostwire v2.0.0 SecurityEvent
- Suspicious DNS & connection analysis (DGA/high-entropy heuristics, unusual ports)
- Network-to-process correlation and chronological incident timelines
"""

from __future__ import annotations

import json
import math
import os
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from schema.event_schema import CorrelationInfo, ProvenanceInfo, SecurityEvent

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
SUSPICIOUS_PORTS = frozenset({4444, 1337, 31337, 6667, 9001})


class NetworkIngestionError(ValueError):
    """Raised when a PCAP or EVE JSON input is malformed or exceeds bounds."""


@dataclass
class NetworkFlowSummary:
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    bytes_len: int
    dns_query: Optional[str] = None
    suricata_signature: Optional[str] = None
    correlated_pid: Optional[int] = None
    correlated_process: Optional[str] = None


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_suspicious_dns_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """Heuristic check for DGA-like high-entropy or excessively long DNS labels."""
    clean = domain.strip().rstrip(".").lower()
    if not clean:
        return False, None
    labels = clean.split(".")
    longest = max(labels, key=len)
    if len(longest) >= 24 and _shannon_entropy(longest) >= 3.6:
        return True, f"High-entropy long DNS label ({len(longest)} chars)"
    if len(clean) > 100:
        return True, f"Excessively long DNS query ({len(clean)} chars)"
    return False, None


def parse_pcap_bytes(
    data: bytes,
    asset_id: str = "network-sensor",
    max_packets: int = 10_000,
    max_bytes: int = 25 * 1024 * 1024,
) -> List[SecurityEvent]:
    """Safely parse a raw libpcap byte stream into bounded v2.0.0 SecurityEvents."""
    if len(data) > max_bytes:
        raise NetworkIngestionError(f"PCAP exceeds max_bytes ({len(data)} > {max_bytes})")
    if len(data) < 24:
        raise NetworkIngestionError("Truncated PCAP global header (< 24 bytes)")

    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise NetworkIngestionError(f"Invalid PCAP magic header: 0x{magic:08x}")

    _, _, _, _, snaplen, linktype = struct.unpack(f"{endian}HHiIII", data[4:24])
    if linktype != 1:  # LINKTYPE_ETHERNET
        raise NetworkIngestionError(f"Unsupported PCAP linktype {linktype} (expected Ethernet=1)")

    events: List[SecurityEvent] = []
    offset = 24
    pkt_count = 0

    while offset + 16 <= len(data) and pkt_count < max_packets:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        if incl_len > snaplen or incl_len > 65535 or offset + incl_len > len(data):
            raise NetworkIngestionError(f"Malformed/truncated packet record at offset {offset}")

        pkt = data[offset : offset + incl_len]
        offset += incl_len
        pkt_count += 1

        if len(pkt) < 34:  # 14 Ethernet + 20 IPv4 min
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        if eth_type != 0x0800:  # IPv4 only
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if ihl < 20 or len(pkt) < 14 + ihl:
            continue
        proto_num = pkt[23]
        src_ip = ".".join(str(b) for b in pkt[26:30])
        dst_ip = ".".join(str(b) for b in pkt[30:34])
        l4_off = 14 + ihl
        src_port = dst_port = 0
        proto_name = f"ip_{proto_num}"

        if proto_num == 6 and len(pkt) >= l4_off + 4:
            proto_name = "tcp"
            src_port, dst_port = struct.unpack("!HH", pkt[l4_off : l4_off + 4])
        elif proto_num == 17 and len(pkt) >= l4_off + 4:
            proto_name = "udp"
            src_port, dst_port = struct.unpack("!HH", pkt[l4_off : l4_off + 4])

        from datetime import datetime, timezone

        ts_iso = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000.0, tz=timezone.utc).isoformat()
        is_susp_port = dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS
        events.append(
            SecurityEvent(
                timestamp=ts_iso,
                asset_id=asset_id,
                event_category="network",
                event_action="pcap_packet",
                severity="medium" if is_susp_port else "info",
                confidence=0.75 if is_susp_port else 1.0,
                provenance=ProvenanceInfo(source_component="ghostwire_pcap_parser", is_synthetic=False),
                payload={
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto_name,
                    "orig_len": orig_len,
                    "suspicious_port": is_susp_port,
                },
            )
        )
    return events


def ingest_suricata_eve(
    eve_path: str,
    asset_id: str = "suricata-sensor",
    max_lines: int = 50_000,
) -> Tuple[List[SecurityEvent], int]:
    """Ingest Suricata EVE JSONL safely with bounded lines. Returns (events, malformed_count)."""
    if not os.path.isfile(eve_path):
        raise NetworkIngestionError(f"EVE JSON file not found: {eve_path}")

    events: List[SecurityEvent] = []
    malformed = 0

    with open(eve_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx >= max_lines:
                break
            raw = line.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
                if not isinstance(rec, dict):
                    malformed += 1
                    continue
            except json.JSONDecodeError:
                malformed += 1
                continue

            eve_type = str(rec.get("event_type") or "flow").lower()
            ts = str(rec.get("timestamp") or "2026-11-23T00:00:00+00:00")
            # Normalize Suricata "+0000" offset to "+00:00" for Python fromisoformat compatibility
            if len(ts) > 5 and (ts[-5] in ("+", "-")) and ts[-3] != ":":
                ts = ts[:-2] + ":" + ts[-2:]

            src_ip = str(rec.get("src_ip") or "")
            dst_ip = str(rec.get("dest_ip") or "")
            src_port = int(rec.get("src_port") or 0)
            dst_port = int(rec.get("dest_port") or 0)
            proto = str(rec.get("proto") or "unknown").lower()

            category = "detection_alert" if eve_type == "alert" else "network"
            severity = "info"
            confidence = 0.8
            payload: Dict[str, Any] = {
                "eve_type": eve_type,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
            }

            if eve_type == "alert" and isinstance(rec.get("alert"), dict):
                alert = rec["alert"]
                sev_num = int(alert.get("severity") or 3)
                severity = "high" if sev_num == 1 else ("medium" if sev_num == 2 else "low")
                payload["signature"] = alert.get("signature", "Suricata Alert")
                payload["signature_id"] = alert.get("signature_id")
                payload["category"] = alert.get("category")
            elif eve_type == "dns" and isinstance(rec.get("dns"), dict):
                qname = str(rec["dns"].get("rrname") or "")
                payload["dns_query"] = qname
                susp, reason = is_suspicious_dns_domain(qname)
                if susp:
                    severity = "medium"
                    payload["dns_suspicious_reason"] = reason
            elif dst_port in SUSPICIOUS_PORTS:
                severity = "medium"
                payload["suspicious_port"] = True

            events.append(
                SecurityEvent(
                    timestamp=ts,
                    asset_id=asset_id,
                    event_category=category,
                    event_action=f"suricata_{eve_type}",
                    severity=severity,
                    confidence=confidence,
                    provenance=ProvenanceInfo(source_component="suricata_eve_ingest", is_synthetic=False),
                    payload=payload,
                )
            )

    return events, malformed


def correlate_network_to_processes(
    network_events: List[SecurityEvent],
    host_sockets: List[Dict[str, Any]],
) -> List[SecurityEvent]:
    """Correlate network events to host process telemetry using (src_port, dst_ip, dst_port)."""
    lookup: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
    for sock in host_sockets:
        key = (int(sock.get("local_port", 0)), str(sock.get("remote_ip", "")), int(sock.get("remote_port", 0)))
        lookup[key] = sock

    for ev in network_events:
        p = ev.payload
        key = (int(p.get("src_port", 0)), str(p.get("dst_ip", "")), int(p.get("dst_port", 0)))
        if key in lookup:
            sock = lookup[key]
            p["correlated_pid"] = sock.get("pid")
            p["correlated_process"] = sock.get("process_name")
            if sock.get("event_id"):
                ev.correlation = CorrelationInfo(
                    correlation_id=ev.correlation.correlation_id,
                    parent_event_id=str(sock["event_id"]),
                )
    return network_events


def build_network_timeline(events: List[SecurityEvent]) -> List[Dict[str, Any]]:
    """Build a chronological network incident timeline from normalized SecurityEvents."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    return [
        {
            "timestamp": e.timestamp,
            "event_id": e.event_id,
            "action": e.event_action,
            "severity": e.severity,
            "src": f"{e.payload.get('src_ip', '')}:{e.payload.get('src_port', '')}",
            "dst": f"{e.payload.get('dst_ip', '')}:{e.payload.get('dst_port', '')}",
            "process": e.payload.get("correlated_process"),
            "detail": e.payload.get("signature") or e.payload.get("dns_suspicious_reason") or e.payload.get("dns_query") or "",
        }
        for e in ordered
    ]
