"""Versioned Security Event Schema (v2.0.0) and deterministic pipeline controls.

Provides:
- Strict input validation for security events across endpoint, network, scan,
  detection, DFIR, and audit categories.
- Backward-compatible migration from legacy Ghostwire v1.0 lab records.
- Bounded deduplication and bounded queues with explicit telemetry-loss events.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional, Tuple

SCHEMA_VERSION = "2.0.0"

VALID_CATEGORIES = frozenset({
    "process",
    "file",
    "network",
    "persistence",
    "auth",
    "malware_scan",
    "quarantine",
    "detection_alert",
    "investigation",
    "audit",
    "telemetry_loss",
    "heartbeat",
})

VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})

LEGACY_TYPE_MAP = {
    "telemetry": ("process", "telemetry", "info"),
    "heartbeat": ("heartbeat", "heartbeat", "info"),
    "alert": ("detection_alert", "alert", "high"),
    "auth_failed": ("auth", "auth_failed", "high"),
    "record_rejected": ("audit", "record_rejected", "medium"),
}


class SchemaValidationError(ValueError):
    """Raised when an event violates the Ghostwire v2.0.0 security event schema."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_iso_timestamp(value: str) -> str:
    """Validate ISO-8601 timestamp string and return it normalized."""
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError("timestamp must be a non-empty ISO-8601 string")
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise SchemaValidationError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    return value.strip()


@dataclass
class ProvenanceInfo:
    source_component: str
    collector_version: str = "2.0.0"
    host_os: str = "unknown"
    is_synthetic: bool = False

    def validate(self) -> None:
        if not isinstance(self.source_component, str) or not self.source_component.strip():
            raise SchemaValidationError("provenance.source_component must be non-empty")
        if not isinstance(self.is_synthetic, bool):
            raise SchemaValidationError("provenance.is_synthetic must be a boolean")


@dataclass
class CorrelationInfo:
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_event_id: Optional[str] = None
    detection_id: Optional[str] = None
    case_id: Optional[str] = None


@dataclass
class SecurityEvent:
    asset_id: str
    event_category: str
    event_action: str
    severity: str
    confidence: float
    provenance: ProvenanceInfo
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now_iso)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SCHEMA_VERSION
    correlation: CorrelationInfo = field(default_factory=CorrelationInfo)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaValidationError(f"Unsupported schema_version: {self.schema_version!r}")
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise SchemaValidationError("event_id must be a non-empty string")
        if not isinstance(self.asset_id, str) or not self.asset_id.strip():
            raise SchemaValidationError("asset_id must be a non-empty string")
        validate_iso_timestamp(self.timestamp)
        if self.event_category not in VALID_CATEGORIES:
            raise SchemaValidationError(f"Invalid event_category: {self.event_category!r}")
        if not isinstance(self.event_action, str) or not self.event_action.strip():
            raise SchemaValidationError("event_action must be a non-empty string")
        if self.severity not in VALID_SEVERITIES:
            raise SchemaValidationError(f"Invalid severity: {self.severity!r}")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 1.0):
            raise SchemaValidationError(f"confidence must be between 0.0 and 1.0, got {self.confidence!r}")
        if not isinstance(self.payload, dict):
            raise SchemaValidationError("payload must be a dictionary")
        self.provenance.validate()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        if not isinstance(data, dict):
            raise SchemaValidationError("Event record must be a JSON object")
        if "schema_version" not in data:
            return migrate_legacy_event(data)
        prov_raw = data.get("provenance")
        if not isinstance(prov_raw, dict):
            raise SchemaValidationError("provenance object is required")
        corr_raw = data.get("correlation") or {}
        if not isinstance(corr_raw, dict):
            raise SchemaValidationError("correlation must be an object")
        return cls(
            schema_version=str(data.get("schema_version", "")),
            event_id=str(data.get("event_id") or uuid.uuid4()),
            timestamp=str(data.get("timestamp") or ""),
            asset_id=str(data.get("asset_id") or ""),
            event_category=str(data.get("event_category") or ""),
            event_action=str(data.get("event_action") or ""),
            severity=str(data.get("severity") or ""),
            confidence=float(data.get("confidence", -1.0)),
            provenance=ProvenanceInfo(
                source_component=str(prov_raw.get("source_component") or ""),
                collector_version=str(prov_raw.get("collector_version") or "2.0.0"),
                host_os=str(prov_raw.get("host_os") or "unknown"),
                is_synthetic=bool(prov_raw.get("is_synthetic", False)),
            ),
            correlation=CorrelationInfo(
                correlation_id=str(corr_raw.get("correlation_id") or uuid.uuid4()),
                parent_event_id=corr_raw.get("parent_event_id"),
                detection_id=corr_raw.get("detection_id"),
                case_id=corr_raw.get("case_id"),
            ),
            payload=dict(data.get("payload") or {}),
        )


def migrate_legacy_event(record: Dict[str, Any]) -> SecurityEvent:
    """Migrate a Ghostwire v1.0 lab/server record into a v2.0.0 SecurityEvent."""
    if not isinstance(record, dict):
        raise SchemaValidationError("Legacy record must be a dictionary")

    rec_type = str(record.get("type") or "")
    if rec_type in LEGACY_TYPE_MAP:
        category, default_action, default_sev = LEGACY_TYPE_MAP[rec_type]
    else:
        raise SchemaValidationError(f"Cannot migrate unknown legacy record type: {rec_type!r}")

    action = str(record.get("action") or default_action)
    if rec_type == "telemetry" and record.get("phase"):
        action = f"{action}.{record['phase']}"

    sev_raw = str(record.get("severity") or default_sev).lower()
    if sev_raw == "warning":
        sev_raw = "medium"
    if sev_raw not in VALID_SEVERITIES:
        sev_raw = default_sev

    asset_id = str(record.get("agent_id") or record.get("peer_ip") or "lab-unknown")
    timestamp = str(record.get("timestamp") or record.get("ingested_at") or _utc_now_iso())

    # Deterministic event_id for legacy records without explicit id
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    event_id = str(record.get("event_id") or f"leg-{digest}")

    excluded_keys = {"type", "agent_id", "timestamp", "severity", "event_id"}
    payload = {k: v for k, v in record.items() if k not in excluded_keys}

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        asset_id=asset_id,
        event_category=category,
        event_action=action,
        severity=sev_raw,
        confidence=0.85 if category == "detection_alert" else 1.0,
        provenance=ProvenanceInfo(
            source_component=str(record.get("source") or "ghostwire_legacy_v1"),
            collector_version="1.0.0",
            host_os=str(record.get("os") or "unknown"),
            is_synthetic=bool(record.get("is_synthetic", False)),
        ),
        correlation=CorrelationInfo(
            correlation_id=str(record.get("correlation_id") or event_id),
            detection_id=record.get("rule") if category == "detection_alert" else None,
        ),
        payload=payload,
    )


class EventDeduplicator:
    """Bounded FIFO/LRU deduplicator preventing duplicate event ingestion storms."""

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._seen: OrderedDict[str, None] = OrderedDict()

    def fingerprint(self, event: SecurityEvent) -> str:
        canonical = json.dumps(
            {
                "event_id": event.event_id,
                "asset_id": event.asset_id,
                "category": event.event_category,
                "action": event.event_action,
                "timestamp": event.timestamp,
                "payload": event.payload,
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def is_duplicate(self, event: SecurityEvent) -> bool:
        fp = self.fingerprint(event)
        if fp in self._seen:
            self._seen.move_to_end(fp)
            return True
        self._seen[fp] = None
        if len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)
        return False


class BoundedEventQueue:
    """Bounded queue with backpressure and explicit telemetry-loss visibility."""

    def __init__(self, max_size: int = 1000, policy: str = "drop_oldest", asset_id: str = "local-pipeline") -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if policy not in ("drop_oldest", "reject_new"):
            raise ValueError("policy must be 'drop_oldest' or 'reject_new'")
        self.max_size = max_size
        self.policy = policy
        self.asset_id = asset_id
        self._queue: Deque[SecurityEvent] = deque()
        self.dropped_count: int = 0
        self.enqueued_count: int = 0

    def push(self, event: SecurityEvent) -> Tuple[bool, Optional[SecurityEvent]]:
        """Enqueue an event. Returns (accepted, optional_telemetry_loss_event)."""
        loss_event: Optional[SecurityEvent] = None
        if len(self._queue) >= self.max_size:
            self.dropped_count += 1
            if self.policy == "drop_oldest":
                dropped = self._queue.popleft()
                loss_event = self._make_loss_event(dropped.event_id, "queue_overflow_drop_oldest")
                self._queue.append(event)
                self.enqueued_count += 1
                return True, loss_event
            else:
                loss_event = self._make_loss_event(event.event_id, "queue_overflow_reject_new")
                return False, loss_event

        self._queue.append(event)
        self.enqueued_count += 1
        return True, None

    def pop(self) -> Optional[SecurityEvent]:
        return self._queue.popleft() if self._queue else None

    def __len__(self) -> int:
        return len(self._queue)

    def _make_loss_event(self, dropped_event_id: str, reason: str) -> SecurityEvent:
        return SecurityEvent(
            asset_id=self.asset_id,
            event_category="telemetry_loss",
            event_action="event_dropped",
            severity="high",
            confidence=1.0,
            provenance=ProvenanceInfo(source_component="bounded_event_queue", is_synthetic=False),
            payload={
                "reason": reason,
                "dropped_event_id": dropped_event_id,
                "total_dropped_count": self.dropped_count,
                "queue_capacity": self.max_size,
            },
        )
