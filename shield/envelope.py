"""Immutable security envelope, hardened canonical JSON, audience binding, and HMAC sealing.

Every message traversing a Redis Stream is wrapped in a ``StreamEnvelope`` whose
HMAC-SHA256 seal authenticates:
1. Protocol version (``v=1``) and Key ID (``kid``) for rotation, integrity ceiling,
   and capability-allowlist enforcement.
2. Canonical representation of the frozen ``SecurityContext``, including unique
   ``nonce`` and explicit audience bindings (``target_stream`` and ``target_tool``).
3. ``payload_hash`` (SHA-256 of deterministically canonicalized ``payload``).

Canonicalization normalizes:
- All strings (keys and values) to Unicode NFC, rejecting duplicate keys that
  collide after NFC normalization.
- Integral floats within IEEE-754 exact integer bounds (``|x| <= 2**53``),
  including ``1.0 -> 1`` and ``-0.0 -> 0``, preventing int/float digest drift.
- Non-finite floats/Decimals (``NaN``, ``Inf``, ``-Inf``) are rejected.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import math
import time
import unicodedata
import uuid
from decimal import Decimal
from enum import Enum
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shield.keys import KeyRing, KeySpec
from shield.types import IntegrityLevel

_MAX_SAFE_INT_FLOAT = 9_007_199_254_740_992  # 2**53


def _norm_str(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _canonicalize(value: Any) -> Any:
    """Recursively normalize Python values for deterministic JSON serialization."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _norm_str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"Non-finite float {value!r} cannot be canonically signed.")
        if value == 0.0:
            return 0
        if value.is_integer() and abs(value) <= _MAX_SAFE_INT_FLOAT:
            return int(value)
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError(f"Non-finite Decimal {value!r} cannot be canonically signed.")
        return format(value.normalize(), "f") if value != 0 else "0"
    if isinstance(value, datetime.datetime):
        dt = (
            value.replace(tzinfo=datetime.timezone.utc)
            if value.tzinfo is None
            else value.astimezone(datetime.timezone.utc)
        )
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Enum):
        return _canonicalize(value.value)
    if isinstance(value, dict):
        normalized_items: list[tuple[str, Any]] = []
        seen_keys: set[str] = set()
        for raw_k, raw_v in value.items():
            norm_k = _norm_str(str(raw_k))
            if norm_k in seen_keys:
                raise ValueError(
                    f"Ambiguous duplicate dictionary key {norm_k!r} after Unicode NFC normalization."
                )
            seen_keys.add(norm_k)
            normalized_items.append((norm_k, _canonicalize(raw_v)))
        normalized_items.sort(key=lambda kv: kv[0])
        return dict(normalized_items)
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_canonicalize(item) for item in value]
        return sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
    raise TypeError(f"Unsupported type for canonical serialization: {type(value).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize an arbitrary JSON-compatible structure deterministically to UTF-8 bytes."""
    normalized = _canonicalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=True,
    ).encode("utf-8")


def compute_payload_hash(payload: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest over ``payload``."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _ts_to_micros(ts: float | None) -> int | None:
    if ts is None:
        return None
    if not math.isfinite(ts):
        raise ValueError(f"Non-finite timestamp {ts!r}.")
    return int(round(ts * 1_000_000))


class SecurityContext(BaseModel):
    """Immutable, audience-bound security label attached to every message."""

    model_config = ConfigDict(frozen=True)

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)
    integrity: IntegrityLevel = IntegrityLevel.LOW
    origin_channel: str
    allowed_sink_capabilities: tuple[str, ...] = Field(default_factory=tuple)
    target_stream: str | None = None
    target_tool: str | None = None
    parent_trace_ids: tuple[str, ...] = Field(default_factory=tuple)
    created_at: float = Field(default_factory=lambda: round(time.time(), 6))
    expires_at: float | None = None

    @field_validator("allowed_sink_capabilities", "parent_trace_ids", mode="before")
    @classmethod
    def _normalize_str_tuple(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (_norm_str(value),)
        seen: dict[str, None] = {}
        for item in value:
            seen[_norm_str(str(item))] = None
        return tuple(seen.keys())

    @field_validator("created_at", "expires_at", mode="after")
    @classmethod
    def _validate_finite_ts(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("Timestamp must be a finite number.")
        return value

    def canonical_dict(self) -> dict[str, Any]:
        """Return a float-drift-free canonical dictionary for HMAC sealing."""
        return {
            "trace_id": _norm_str(self.trace_id),
            "nonce": _norm_str(self.nonce),
            "integrity": self.integrity.value,
            "origin_channel": _norm_str(self.origin_channel),
            "allowed_sink_capabilities": sorted(_norm_str(c) for c in self.allowed_sink_capabilities),
            "target_stream": _norm_str(self.target_stream) if self.target_stream is not None else None,
            "target_tool": _norm_str(self.target_tool) if self.target_tool is not None else None,
            "parent_trace_ids": [_norm_str(p) for p in self.parent_trace_ids],
            "created_at_us": _ts_to_micros(self.created_at),
            "expires_at_us": _ts_to_micros(self.expires_at),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_dict())

    def is_expired(self, now: float | None = None) -> bool:
        """Check whether the context has passed its expiration deadline."""
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return current > self.expires_at

    @classmethod
    def join(
        cls,
        contexts: Sequence[SecurityContext],
        *,
        narrow_capabilities: Iterable[str] | None = None,
        downgrade_integrity: IntegrityLevel | None = None,
        target_stream: str | None = None,
        target_tool: str | None = None,
        fresh_nonce: bool = True,
    ) -> SecurityContext:
        """Combine one or more upstream contexts using monotonic taint propagation."""
        if not contexts:
            raise ValueError("Cannot join an empty sequence of SecurityContext objects.")

        levels = [c.integrity for c in contexts]
        if downgrade_integrity is not None:
            levels.append(downgrade_integrity)
        joined_integrity = IntegrityLevel.meet(levels)

        cap_sets = [set(c.allowed_sink_capabilities) for c in contexts]
        joined_caps_set = set.intersection(*cap_sets) if cap_sets else set()
        if narrow_capabilities is not None:
            joined_caps_set &= set(narrow_capabilities)
        joined_caps = tuple(sorted(joined_caps_set))

        if len(contexts) == 1:
            primary = contexts[0]
            trace_id = primary.trace_id
            origin_channel = primary.origin_channel
            parent_trace_ids = primary.parent_trace_ids
            nonce = uuid.uuid4().hex if fresh_nonce else primary.nonce
        else:
            trace_id = str(uuid.uuid4())
            unique_origins = list(dict.fromkeys(c.origin_channel for c in contexts))
            origin_channel = (
                unique_origins[0]
                if len(unique_origins) == 1
                else f"join({','.join(unique_origins)})"
            )
            parent_ids: list[str] = []
            for c in contexts:
                parent_ids.append(c.trace_id)
                parent_ids.extend(c.parent_trace_ids)
            parent_trace_ids = tuple(dict.fromkeys(parent_ids))
            nonce = uuid.uuid4().hex

        created_at = min(c.created_at for c in contexts)
        expirations = [c.expires_at for c in contexts if c.expires_at is not None]
        expires_at = min(expirations) if expirations else None

        return cls(
            trace_id=trace_id,
            nonce=nonce,
            integrity=joined_integrity,
            origin_channel=origin_channel,
            allowed_sink_capabilities=joined_caps,
            target_stream=target_stream,
            target_tool=target_tool,
            parent_trace_ids=parent_trace_ids,
            created_at=created_at,
            expires_at=expires_at,
        )


def _signing_material(kid: str, context: SecurityContext, payload_hash: str) -> bytes:
    """Canonical domain-separated message authenticated by HMAC-SHA256."""
    return canonical_json_bytes(
        {
            "v": 1,
            "kid": kid,
            "context": context.canonical_dict(),
            "payload_hash": payload_hash,
        }
    )


def compute_envelope_hmac(
    key: KeySpec,
    context: SecurityContext,
    payload_hash: str,
) -> str:
    """Compute hex-encoded HMAC-SHA256 over ``(v=1, kid, context, payload_hash)``."""
    material = _signing_material(key.kid, context, payload_hash)
    return hmac.new(key.secret, material, hashlib.sha256).hexdigest()


class EnvelopeMetadata(BaseModel):
    """Mutable transport metadata kept strictly outside the signed material.

    Note: Because transport metadata is unsigned, a writer with Redis access can
    modify ``retry_count`` (availability/DoS risk by accelerating DLQ routing),
    but cannot escalate integrity, capabilities, audience, or payload contents.
    """

    hop_count: int = 0
    retry_count: int = 0
    last_worker: str | None = None
    dlq_reason: str | None = None
    original_stream: str | None = None
    original_message_id: str | None = None
    failed_at: float | None = None


class EnvelopeVerificationError(Exception):
    """Internal detailed verification error mapped to interceptor security exceptions."""

    def __init__(self, reason: str, *, unauthorized_issuer: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.unauthorized_issuer = unauthorized_issuer


class StreamEnvelope(BaseModel):
    """Typed, cryptographically sealed message envelope transmitted over Redis Streams."""

    context: SecurityContext
    payload: dict[str, Any]
    kid: str | None = None
    payload_hash: str | None = None
    signature: str | None = None
    metadata: EnvelopeMetadata = Field(default_factory=EnvelopeMetadata)

    def seal(self, keyring: KeyRing, *, kid: str | None = None) -> StreamEnvelope:
        """Seal ``(kid, context, payload_hash)`` enforcing both integrity and capability authority."""
        key = keyring.signing_key(kid)
        if not key.max_integrity.satisfies(self.context.integrity):
            raise EnvelopeVerificationError(
                f"Key '{key.kid}' (role={key.role}, max_integrity={key.max_integrity.value.upper()}) "
                f"is not authorized to mint integrity={self.context.integrity.value.upper()}.",
                unauthorized_issuer=True,
            )

        if not key.can_mint_capabilities(self.context.allowed_sink_capabilities):
            disallowed = sorted(
                set(self.context.allowed_sink_capabilities) - set(key.allowed_capabilities)
            )
            raise EnvelopeVerificationError(
                f"Key '{key.kid}' (role={key.role}) is not authorized to mint capabilities {disallowed}.",
                unauthorized_issuer=True,
            )

        p_hash = compute_payload_hash(self.payload)
        sig = compute_envelope_hmac(key, self.context, p_hash)
        return self.model_copy(
            update={
                "kid": key.kid,
                "payload_hash": p_hash,
                "signature": sig,
            }
        )

    def verify_strict(self, keyring: KeyRing) -> KeySpec:
        """Strictly verify key authority (integrity + capabilities), payload hash, and HMAC."""
        if not self.kid or not self.signature or not self.payload_hash:
            raise EnvelopeVerificationError(
                "Envelope is missing required cryptographic seal fields (kid, payload_hash, signature)."
            )

        key = keyring.get(self.kid)
        if key is None:
            raise EnvelopeVerificationError(f"Unknown or revoked key id '{self.kid}'.")

        if not key.max_integrity.satisfies(self.context.integrity):
            raise EnvelopeVerificationError(
                f"Issuer key '{key.kid}' (max_integrity={key.max_integrity.value.upper()}) "
                f"cannot authorize context integrity={self.context.integrity.value.upper()}.",
                unauthorized_issuer=True,
            )

        if not key.can_mint_capabilities(self.context.allowed_sink_capabilities):
            disallowed = sorted(
                set(self.context.allowed_sink_capabilities) - set(key.allowed_capabilities)
            )
            raise EnvelopeVerificationError(
                f"Issuer key '{key.kid}' (role={key.role}) cannot authorize capabilities {disallowed}.",
                unauthorized_issuer=True,
            )

        actual_payload_hash = compute_payload_hash(self.payload)
        if not hmac.compare_digest(actual_payload_hash, self.payload_hash):
            raise EnvelopeVerificationError(
                "Payload SHA-256 digest mismatch (payload tampered in transit)."
            )

        expected_sig = compute_envelope_hmac(key, self.context, actual_payload_hash)
        if not hmac.compare_digest(expected_sig, self.signature):
            raise EnvelopeVerificationError("Invalid HMAC-SHA256 signature on envelope.")

        return key

    def verify(self, keyring: KeyRing) -> bool:
        """Boolean convenience wrapper around ``verify_strict``."""
        try:
            self.verify_strict(keyring)
            return True
        except EnvelopeVerificationError:
            return False

    def derive(
        self,
        new_payload: dict[str, Any],
        *,
        keyring: KeyRing,
        kid: str | None = None,
        worker_name: str | None = None,
        narrow_capabilities: Iterable[str] | None = None,
        downgrade_integrity: IntegrityLevel | None = None,
        target_stream: str | None = None,
        target_tool: str | None = None,
    ) -> StreamEnvelope:
        """Produce and re-seal a downstream envelope clamped to this worker key's authority."""
        key = keyring.signing_key(kid)
        ceiling = (
            IntegrityLevel.meet([key.max_integrity, downgrade_integrity])
            if downgrade_integrity is not None
            else key.max_integrity
        )

        # Clamp capabilities to key's allowlist (unless wildcard "*")
        effective_narrow: Iterable[str] | None = narrow_capabilities
        if "*" not in key.allowed_capabilities:
            key_caps = set(key.allowed_capabilities)
            effective_narrow = (
                key_caps & set(narrow_capabilities)
                if narrow_capabilities is not None
                else key_caps
            )

        derived_ctx = SecurityContext.join(
            [self.context],
            narrow_capabilities=effective_narrow,
            downgrade_integrity=ceiling,
            target_stream=target_stream,
            target_tool=target_tool,
            fresh_nonce=True,
        )
        new_meta = self.metadata.model_copy(
            update={
                "hop_count": self.metadata.hop_count + 1,
                "last_worker": worker_name or self.metadata.last_worker,
            }
        )
        return StreamEnvelope(
            context=derived_ctx,
            payload=new_payload,
            metadata=new_meta,
        ).seal(keyring, kid=key.kid)

    @classmethod
    def join(
        cls,
        envelopes: Sequence[StreamEnvelope],
        new_payload: dict[str, Any],
        *,
        keyring: KeyRing,
        kid: str | None = None,
        worker_name: str | None = None,
        narrow_capabilities: Iterable[str] | None = None,
        downgrade_integrity: IntegrityLevel | None = None,
        target_stream: str | None = None,
        target_tool: str | None = None,
    ) -> StreamEnvelope:
        """Join one or more upstream envelopes into a freshly sealed derived envelope."""
        if not envelopes:
            raise ValueError("Cannot join an empty sequence of StreamEnvelope objects.")
        if len(envelopes) == 1:
            return envelopes[0].derive(
                new_payload,
                keyring=keyring,
                kid=kid,
                worker_name=worker_name,
                narrow_capabilities=narrow_capabilities,
                downgrade_integrity=downgrade_integrity,
                target_stream=target_stream,
                target_tool=target_tool,
            )

        key = keyring.signing_key(kid)
        ceiling = (
            IntegrityLevel.meet([key.max_integrity, downgrade_integrity])
            if downgrade_integrity is not None
            else key.max_integrity
        )
        effective_narrow: Iterable[str] | None = narrow_capabilities
        if "*" not in key.allowed_capabilities:
            key_caps = set(key.allowed_capabilities)
            effective_narrow = (
                key_caps & set(narrow_capabilities)
                if narrow_capabilities is not None
                else key_caps
            )

        joined_ctx = SecurityContext.join(
            [env.context for env in envelopes],
            narrow_capabilities=effective_narrow,
            downgrade_integrity=ceiling,
            target_stream=target_stream,
            target_tool=target_tool,
            fresh_nonce=True,
        )
        max_hops = max(env.metadata.hop_count for env in envelopes)
        return cls(
            context=joined_ctx,
            payload=new_payload,
            metadata=EnvelopeMetadata(
                hop_count=max_hops + 1,
                last_worker=worker_name,
            ),
        ).seal(keyring, kid=key.kid)

    def to_stream_fields(self) -> dict[str, str]:
        """Serialize envelope into Redis Stream string field mapping."""
        return {
            "envelope": self.model_dump_json(),
            "trace_id": self.context.trace_id,
            "integrity": self.context.integrity.value,
            "origin_channel": self.context.origin_channel,
            "kid": self.kid or "",
            "target_stream": self.context.target_stream or "",
            "target_tool": self.context.target_tool or "",
        }

    @classmethod
    def from_stream_fields(cls, fields: dict[Any, Any]) -> StreamEnvelope:
        """Deserialize a Redis Stream entry back into a ``StreamEnvelope``."""
        raw = fields.get("envelope") or fields.get(b"envelope")
        if raw is None:
            raise ValueError("Redis Stream entry is missing required 'envelope' field.")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return cls.model_validate_json(raw)
