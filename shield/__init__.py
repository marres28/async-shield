"""Async-Shield: Immutable security context middleware for Redis Streams multi-agent pipelines."""

from shield.broker import ShieldBroker, StreamMessage
from shield.envelope import (
    EnvelopeMetadata,
    EnvelopeVerificationError,
    SecurityContext,
    StreamEnvelope,
    canonical_json_bytes,
    compute_envelope_hmac,
    compute_payload_hash,
)
from shield.interceptor import (
    AudienceMismatchError,
    AuditRecord,
    CapabilityViolationError,
    ContextExpiredError,
    IntegrityViolationError,
    ReplayDetectedError,
    ReplayStoreUnavailableError,
    SecurityException,
    SinkGate,
    TamperedEnvelopeError,
    UnauthorizedIssuerError,
    UnenvelopedPayloadError,
    secure_tool,
)
from shield.keys import KeyRing, KeySpec, MissingSecretKeyError
from shield.replay import InMemoryReplayStore, RedisReplayStore, ReplayStore, ReplayStoreError
from shield.types import IntegrityLevel

__all__ = [
    "AudienceMismatchError",
    "AuditRecord",
    "CapabilityViolationError",
    "ContextExpiredError",
    "EnvelopeMetadata",
    "EnvelopeVerificationError",
    "InMemoryReplayStore",
    "IntegrityLevel",
    "IntegrityViolationError",
    "KeyRing",
    "KeySpec",
    "MissingSecretKeyError",
    "RedisReplayStore",
    "ReplayDetectedError",
    "ReplayStore",
    "ReplayStoreError",
    "ReplayStoreUnavailableError",
    "SecurityContext",
    "SecurityException",
    "ShieldBroker",
    "SinkGate",
    "StreamEnvelope",
    "StreamMessage",
    "TamperedEnvelopeError",
    "UnauthorizedIssuerError",
    "UnenvelopedPayloadError",
    "canonical_json_bytes",
    "compute_envelope_hmac",
    "compute_payload_hash",
    "secure_tool",
]

__version__ = "0.3.0"
