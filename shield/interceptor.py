"""Fail-closed sink interceptor / capability gate for critical agent tools.

Enforces seven sequential checks before invoking a protected tool:
0. Envelope presence (rejects raw untyped dicts with ``UnenvelopedPayloadError``).
1. Key authority (``kid`` exists, ``key.max_integrity >= context.integrity``,
   and ``key.allowed_capabilities`` covers ``context.allowed_sink_capabilities``).
2. Payload-bound HMAC-SHA256 verification (constant-time ``hmac.compare_digest``).
3. Audience binding (signed ``target_tool`` and optional ``target_stream`` match sink).
4. Freshness / TTL check (``expires_at``).
5. Ordered Biba integrity & explicit sink capability membership.
6. Atomic single-use nonce / at-most-once replay check (``ReplayStore``) with
   guaranteed TTL invariant ``replay_ttl >= ceil(expires_at - now) + clock_skew_seconds``
   and strict fail-closed behavior if Redis is unreachable.
"""

from __future__ import annotations

import functools
import math
import time
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from shield.envelope import EnvelopeVerificationError, StreamEnvelope
from shield.keys import KeyRing
from shield.replay import ReplayStore
from shield.types import IntegrityLevel

F = TypeVar("F", bound=Callable[..., Any])


class SecurityException(Exception):
    """Base exception raised when a sink gate blocks a tool invocation."""

    def __init__(self, message: str, audit: AuditRecord | None = None) -> None:
        super().__init__(message)
        self.audit = audit


class UnenvelopedPayloadError(SecurityException):
    """Raised when a caller attempts to invoke a protected tool with a raw untyped payload."""


class TamperedEnvelopeError(SecurityException):
    """Raised when ``kid``, ``payload_hash``, or HMAC-SHA256 signature verification fails."""


class UnauthorizedIssuerError(SecurityException):
    """Raised when an envelope's signing key is not authorized for its integrity or capabilities."""


class AudienceMismatchError(SecurityException):
    """Raised when signed ``target_tool`` or ``target_stream`` does not match the invoked sink."""


class ContextExpiredError(SecurityException):
    """Raised when the ``SecurityContext`` TTL has elapsed or is missing when required."""


class IntegrityViolationError(SecurityException):
    """Raised when the message's integrity level is lower than required by the sink."""


class CapabilityViolationError(SecurityException):
    """Raised when the message lacks the required sink capability."""


class ReplayDetectedError(SecurityException):
    """Raised when a valid envelope nonce is replayed within its TTL."""


class ReplayStoreUnavailableError(SecurityException):
    """Raised (fail-closed) when the backing replay store (e.g. Redis) is unreachable."""


@dataclass(frozen=True)
class AuditRecord:
    """Structured telemetry emitted for every sink gate decision."""

    tool_name: str
    trace_id: str | None
    nonce: str | None
    kid: str | None
    origin_channel: str | None
    context_integrity: IntegrityLevel | None
    required_integrity: IntegrityLevel
    required_capability: str
    allowed: bool
    reason: str
    overhead_ms: float
    timestamp: float


class SinkGate:
    """Fail-closed policy enforcer backed by a role-scoped ``KeyRing`` and optional ``ReplayStore``."""

    def __init__(
        self,
        keyring: KeyRing,
        *,
        expected_stream: str,
        replay_store: ReplayStore | None = None,
        clock_skew_seconds: int = 60,
        require_expiry_for_replay: bool = True,
        require_tool_audience: bool = True,
        default_replay_ttl_seconds: int = 3600,
        audit_callback: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        if not isinstance(expected_stream, str) or not expected_stream.strip():
            raise ValueError(
                "SinkGate requires a non-empty 'expected_stream' for fail-closed audience binding."
            )
        if clock_skew_seconds < 0:
            raise ValueError("clock_skew_seconds must be >= 0.")
        self.keyring = keyring
        self.expected_stream = expected_stream
        self.replay_store = replay_store
        self.clock_skew_seconds = clock_skew_seconds
        self.require_expiry_for_replay = require_expiry_for_replay
        self.require_tool_audience = require_tool_audience
        self.default_replay_ttl_seconds = default_replay_ttl_seconds
        self.audit_callback = audit_callback
        self.audit_log: list[AuditRecord] = []

    def _record(self, record: AuditRecord) -> AuditRecord:
        self.audit_log.append(record)
        if self.audit_callback is not None:
            self.audit_callback(record)
        return record

    def evaluate(
        self,
        envelope: Any,
        *,
        tool_name: str,
        required_integrity: IntegrityLevel,
        capability_name: str,
        expected_stream: str | None = None,
        enforce_replay_protection: bool = True,
    ) -> AuditRecord:
        """Verify an envelope against sink policy or raise a ``SecurityException`` subclass."""
        start_ns = time.perf_counter_ns()

        def _elapsed_ms() -> float:
            return (time.perf_counter_ns() - start_ns) / 1_000_000.0

        # 0. Fail closed on raw untyped payload bypass
        if not isinstance(envelope, StreamEnvelope):
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=None,
                    nonce=None,
                    kid=None,
                    origin_channel=None,
                    context_integrity=None,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason="Missing StreamEnvelope (untyped payload bypass rejected).",
                    overhead_ms=_elapsed_ms(),
                    timestamp=time.time(),
                )
            )
            raise UnenvelopedPayloadError(
                f"[BLOCK] Tool '{tool_name}' requires a valid StreamEnvelope; "
                f"received {type(envelope).__name__}.",
                audit=record,
            )

        ctx = envelope.context

        # 1 & 2. Key authority (integrity + capabilities), payload SHA-256, and HMAC-SHA256
        try:
            envelope.verify_strict(self.keyring)
        except EnvelopeVerificationError as exc:
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=exc.reason,
                    overhead_ms=_elapsed_ms(),
                    timestamp=time.time(),
                )
            )
            if exc.unauthorized_issuer:
                raise UnauthorizedIssuerError(
                    f"[BLOCK] Unauthorized issuer for tool '{tool_name}': {exc.reason}",
                    audit=record,
                ) from exc
            raise TamperedEnvelopeError(
                f"[BLOCK] Cryptographic verification failed for tool '{tool_name}': {exc.reason}",
                audit=record,
            ) from exc

        now = time.time()

        # 3. Audience binding (signed target_tool & target_stream prevent sink redirection)
        if self.require_tool_audience and ctx.target_tool is None:
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=f"Missing signed target_tool audience binding for '{tool_name}'.",
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise AudienceMismatchError(
                f"[BLOCK] Missing signed target_tool audience binding for tool '{tool_name}'.",
                audit=record,
            )

        if ctx.target_tool is not None and ctx.target_tool != tool_name:
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=(
                        f"Audience mismatch: envelope signed for target_tool='{ctx.target_tool}', "
                        f"cannot invoke '{tool_name}'."
                    ),
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise AudienceMismatchError(
                f"[BLOCK] Audience mismatch: envelope targets tool '{ctx.target_tool}', not '{tool_name}'.",
                audit=record,
            )

        active_expected_stream = expected_stream if expected_stream is not None else self.expected_stream
        if ctx.target_stream != active_expected_stream:
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=(
                        f"Stream audience mismatch: envelope targets stream '{ctx.target_stream}', "
                        f"expected '{active_expected_stream}'."
                    ),
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise AudienceMismatchError(
                f"[BLOCK] Stream audience mismatch: envelope targets '{ctx.target_stream}', "
                f"expected '{active_expected_stream}'.",
                audit=record,
            )

        # 4. Freshness / TTL window check
        if ctx.is_expired(now=now):
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason="SecurityContext expired before sink execution.",
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise ContextExpiredError(
                f"[BLOCK] SecurityContext expired (trace_id={ctx.trace_id}) "
                f"before executing tool '{tool_name}'.",
                audit=record,
            )

        # 5. Ordered Biba integrity check
        if not ctx.integrity.satisfies(required_integrity):
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=(
                        f"Context Integrity: {ctx.integrity.value.upper()}. "
                        f"Required: {required_integrity.value.upper()}."
                    ),
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise IntegrityViolationError(
                f"[BLOCK] Tool '{tool_name}' requires integrity "
                f"{required_integrity.value.upper()}, but envelope has "
                f"{ctx.integrity.value.upper()}.",
                audit=record,
            )

        # 6. Explicit sink capability check
        if capability_name not in ctx.allowed_sink_capabilities:
            record = self._record(
                AuditRecord(
                    tool_name=tool_name,
                    trace_id=ctx.trace_id,
                    nonce=ctx.nonce,
                    kid=envelope.kid,
                    origin_channel=ctx.origin_channel,
                    context_integrity=ctx.integrity,
                    required_integrity=required_integrity,
                    required_capability=capability_name,
                    allowed=False,
                    reason=f"Missing capability '{capability_name}'.",
                    overhead_ms=_elapsed_ms(),
                    timestamp=now,
                )
            )
            raise CapabilityViolationError(
                f"[BLOCK] Missing capability '{capability_name}' for tool '{tool_name}'.",
                audit=record,
            )

        # 7. Atomic at-most-once replay guard: replay_ttl >= ceil(expires_at - now) + clock_skew_seconds
        if enforce_replay_protection and self.replay_store is not None:
            if ctx.expires_at is None:
                if self.require_expiry_for_replay:
                    record = self._record(
                        AuditRecord(
                            tool_name=tool_name,
                            trace_id=ctx.trace_id,
                            nonce=ctx.nonce,
                            kid=envelope.kid,
                            origin_channel=ctx.origin_channel,
                            context_integrity=ctx.integrity,
                            required_integrity=required_integrity,
                            required_capability=capability_name,
                            allowed=False,
                            reason="Replay-protected sink requires explicit expires_at.",
                            overhead_ms=_elapsed_ms(),
                            timestamp=now,
                        )
                    )
                    raise ContextExpiredError(
                        f"[BLOCK] Tool '{tool_name}' requires explicit expires_at when replay protection is enabled.",
                        audit=record,
                    )
                ttl_sec = self.default_replay_ttl_seconds
            else:
                remaining = max(ctx.expires_at - now, 0.0)
                ttl_sec = max(math.ceil(remaining) + self.clock_skew_seconds, 1)

            try:
                fresh = self.replay_store.check_and_mark(tool_name, ctx.nonce, ttl_sec)
            except Exception as exc:  # noqa: BLE001 — fail closed on any replay store failure
                record = self._record(
                    AuditRecord(
                        tool_name=tool_name,
                        trace_id=ctx.trace_id,
                        nonce=ctx.nonce,
                        kid=envelope.kid,
                        origin_channel=ctx.origin_channel,
                        context_integrity=ctx.integrity,
                        required_integrity=required_integrity,
                        required_capability=capability_name,
                        allowed=False,
                        reason=f"Replay store unavailable (fail-closed): {exc}",
                        overhead_ms=_elapsed_ms(),
                        timestamp=now,
                    )
                )
                raise ReplayStoreUnavailableError(
                    f"[BLOCK] Replay store unavailable (fail-closed) for tool '{tool_name}': {exc}",
                    audit=record,
                ) from exc

            if not fresh:
                record = self._record(
                    AuditRecord(
                        tool_name=tool_name,
                        trace_id=ctx.trace_id,
                        nonce=ctx.nonce,
                        kid=envelope.kid,
                        origin_channel=ctx.origin_channel,
                        context_integrity=ctx.integrity,
                        required_integrity=required_integrity,
                        required_capability=capability_name,
                        allowed=False,
                        reason=f"Replay detected for nonce '{ctx.nonce}' on tool '{tool_name}'.",
                        overhead_ms=_elapsed_ms(),
                        timestamp=now,
                    )
                )
                raise ReplayDetectedError(
                    f"[BLOCK] Replay detected: nonce '{ctx.nonce}' already consumed for '{tool_name}'.",
                    audit=record,
                )

        return self._record(
            AuditRecord(
                tool_name=tool_name,
                trace_id=ctx.trace_id,
                nonce=ctx.nonce,
                kid=envelope.kid,
                origin_channel=ctx.origin_channel,
                context_integrity=ctx.integrity,
                required_integrity=required_integrity,
                required_capability=capability_name,
                allowed=True,
                reason="OK",
                overhead_ms=_elapsed_ms(),
                timestamp=now,
            )
        )

    def secure_tool(
        self,
        required_integrity: IntegrityLevel,
        capability_name: str,
        *,
        expected_stream: str | None = None,
        enforce_replay_protection: bool = True,
    ) -> Callable[[F], F]:
        """Decorator binding a tool function to this ``SinkGate`` instance."""

        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(envelope: StreamEnvelope, *args: Any, **kwargs: Any) -> Any:
                self.evaluate(
                    envelope,
                    tool_name=func.__name__,
                    required_integrity=required_integrity,
                    capability_name=capability_name,
                    expected_stream=expected_stream,
                    enforce_replay_protection=enforce_replay_protection,
                )
                return func(envelope.payload, *args, **kwargs)

            wrapper._shield_gate = self  # type: ignore[attr-defined]
            return wrapper  # type: ignore[return-value]

        return decorator


def secure_tool(
    required_integrity: IntegrityLevel,
    capability_name: str,
    *,
    gate: SinkGate,
    expected_stream: str | None = None,
    enforce_replay_protection: bool = True,
) -> Callable[[F], F]:
    """Decorate a critical executor tool with a fail-closed ``SinkGate``."""
    return gate.secure_tool(
        required_integrity=required_integrity,
        capability_name=capability_name,
        expected_stream=expected_stream,
        enforce_replay_protection=enforce_replay_protection,
    )
