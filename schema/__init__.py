"""Ghostwire versioned security event schema and pipeline primitives."""

from .event_schema import (
    SCHEMA_VERSION,
    VALID_CATEGORIES,
    VALID_SEVERITIES,
    BoundedEventQueue,
    CorrelationInfo,
    EventDeduplicator,
    ProvenanceInfo,
    SchemaValidationError,
    SecurityEvent,
    migrate_legacy_event,
)

__all__ = [
    "SCHEMA_VERSION",
    "VALID_CATEGORIES",
    "VALID_SEVERITIES",
    "BoundedEventQueue",
    "CorrelationInfo",
    "EventDeduplicator",
    "ProvenanceInfo",
    "SchemaValidationError",
    "SecurityEvent",
    "migrate_legacy_event",
]
