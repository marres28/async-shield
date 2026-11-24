"""Transparent Redis Streams middleware enforcing sealed, audience-bound StreamEnvelope propagation.

Wraps ``xadd``, ``xreadgroup``, ``xack``, ``xpending_range``, and ``xautoclaim``:
- Every published envelope is sealed with a role- and capability-scoped ``KeyRing``
  key (``kid``) binding ``SecurityContext``, audience (``target_stream`` + optional
  ``target_tool``), and ``payload_hash``.
- ``consume()`` and ``reclaim_pending()`` verify ``target_stream == stream``,
  blocking cross-stream redirection attacks with ``AudienceMismatchError``.
- Crashed workers' pending entries and DLQ messages preserve the full sealed
  envelope intact; ``read_dlq()`` validates against the original stream audience.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

import redis

from shield.envelope import (
    EnvelopeVerificationError,
    SecurityContext,
    StreamEnvelope,
)
from shield.interceptor import (
    AudienceMismatchError,
    TamperedEnvelopeError,
    UnauthorizedIssuerError,
)
from shield.keys import KeyRing
from shield.types import IntegrityLevel


@dataclass(frozen=True)
class StreamMessage:
    """A single consumed Redis Stream entry with its verified ``StreamEnvelope``."""

    stream: str
    message_id: str
    envelope: StreamEnvelope
    delivery_count: int = 1


def _raise_verification_error(exc: EnvelopeVerificationError, context_msg: str) -> None:
    if exc.unauthorized_issuer:
        raise UnauthorizedIssuerError(f"{context_msg}: {exc.reason}") from exc
    raise TamperedEnvelopeError(f"{context_msg}: {exc.reason}") from exc


class ShieldBroker:
    """Security wrapper around ``redis.Redis`` for Redis Streams."""

    def __init__(
        self,
        client: redis.Redis,
        *,
        keyring: KeyRing,
        signing_kid: str | None = None,
        verify_on_read: bool = True,
        enforce_stream_audience: bool = True,
        default_max_retries: int = 3,
        dlq_suffix: str = ":dlq",
    ) -> None:
        self.client = client
        self.keyring = keyring
        self.signing_kid = signing_kid
        self.verify_on_read = verify_on_read
        self.enforce_stream_audience = enforce_stream_audience
        self.default_max_retries = default_max_retries
        self.dlq_suffix = dlq_suffix

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        keyring: KeyRing,
        signing_kid: str | None = None,
        verify_on_read: bool = True,
        enforce_stream_audience: bool = True,
        default_max_retries: int = 3,
        dlq_suffix: str = ":dlq",
    ) -> ShieldBroker:
        client = redis.Redis.from_url(url, decode_responses=True)
        return cls(
            client,
            keyring=keyring,
            signing_kid=signing_kid,
            verify_on_read=verify_on_read,
            enforce_stream_audience=enforce_stream_audience,
            default_max_retries=default_max_retries,
            dlq_suffix=dlq_suffix,
        )

    def ensure_group(
        self,
        stream: str,
        group: str,
        *,
        start_id: str = "0",
        mkstream: bool = True,
    ) -> None:
        """Idempotently create a Redis Stream consumer group."""
        try:
            self.client.xgroup_create(stream, group, id=start_id, mkstream=mkstream)
        except redis.exceptions.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def publish(
        self,
        stream: str,
        envelope: StreamEnvelope,
        *,
        kid: str | None = None,
        maxlen: int | None = None,
        approximate: bool = True,
        auto_seal: bool = True,
        allow_dlq_stream: bool = False,
    ) -> str:
        """Publish a sealed ``StreamEnvelope`` to a Redis Stream via ``XADD``."""
        if envelope.signature is None:
            if not auto_seal:
                raise TamperedEnvelopeError(
                    "Refusing to publish unsealed StreamEnvelope with auto_seal=False."
                )
            try:
                envelope = envelope.seal(self.keyring, kid=kid or self.signing_kid)
            except EnvelopeVerificationError as exc:
                _raise_verification_error(exc, f"Refusing to seal envelope for stream '{stream}'")
        else:
            try:
                envelope.verify_strict(self.keyring)
            except EnvelopeVerificationError as exc:
                _raise_verification_error(
                    exc, f"Refusing to publish invalid envelope to stream '{stream}'"
                )

        if (
            self.enforce_stream_audience
            and not allow_dlq_stream
            and envelope.context.target_stream is not None
            and envelope.context.target_stream != stream
        ):
            raise AudienceMismatchError(
                f"Refusing to publish envelope bound to stream '{envelope.context.target_stream}' "
                f"onto '{stream}'."
            )

        fields = envelope.to_stream_fields()
        msg_id = self.client.xadd(
            stream,
            fields,  # type: ignore[arg-type]
            maxlen=maxlen,
            approximate=approximate,
        )
        return msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)

    def publish_ingress(
        self,
        stream: str,
        payload: dict[str, Any],
        *,
        origin_channel: str,
        integrity: IntegrityLevel = IntegrityLevel.LOW,
        allowed_sink_capabilities: Iterable[str] = (),
        target_tool: str | None = None,
        ttl_seconds: float | None = None,
        worker_name: str | None = None,
        kid: str | None = None,
    ) -> tuple[str, StreamEnvelope]:
        """Mint and publish a fresh audience-bound sealed envelope at pipeline ingress."""
        now = round(time.time(), 6)
        ctx = SecurityContext(
            integrity=integrity,
            origin_channel=origin_channel,
            allowed_sink_capabilities=tuple(allowed_sink_capabilities),
            target_stream=stream,
            target_tool=target_tool,
            created_at=now,
            expires_at=round(now + ttl_seconds, 6) if ttl_seconds is not None else None,
        )
        envelope = StreamEnvelope(context=ctx, payload=payload)
        envelope.metadata.last_worker = worker_name
        try:
            sealed = envelope.seal(self.keyring, kid=kid or self.signing_kid)
        except EnvelopeVerificationError as exc:
            _raise_verification_error(exc, f"Ingress mint rejected for stream '{stream}'")
        msg_id = self.publish(stream, sealed, auto_seal=False)
        return msg_id, sealed

    def publish_derived(
        self,
        stream: str,
        sources: StreamEnvelope | Sequence[StreamEnvelope],
        new_payload: dict[str, Any],
        *,
        target_tool: str | None = None,
        worker_name: str | None = None,
        narrow_capabilities: Iterable[str] | None = None,
        downgrade_integrity: IntegrityLevel | None = None,
        kid: str | None = None,
    ) -> tuple[str, StreamEnvelope]:
        """Publish a derived downstream message sealed and audience-bound to ``stream``."""
        source_list = [sources] if isinstance(sources, StreamEnvelope) else list(sources)
        if self.verify_on_read:
            for src in source_list:
                try:
                    src.verify_strict(self.keyring)
                except EnvelopeVerificationError as exc:
                    _raise_verification_error(
                        exc,
                        f"Cannot derive from invalid upstream envelope (trace_id={src.context.trace_id})",
                    )

        try:
            derived = StreamEnvelope.join(
                source_list,
                new_payload,
                keyring=self.keyring,
                kid=kid or self.signing_kid,
                worker_name=worker_name,
                narrow_capabilities=narrow_capabilities,
                downgrade_integrity=downgrade_integrity,
                target_stream=stream,
                target_tool=target_tool,
            )
        except EnvelopeVerificationError as exc:
            _raise_verification_error(exc, f"Failed to derive envelope for stream '{stream}'")

        msg_id = self.publish(stream, derived, auto_seal=False)
        return msg_id, derived

    def _decode_entry(
        self,
        stream: str,
        raw_id: Any,
        fields: dict[Any, Any],
        *,
        delivery_count: int = 1,
        expected_audience_stream: str | None = None,
    ) -> StreamMessage:
        msg_id = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else str(raw_id)
        envelope = StreamEnvelope.from_stream_fields(fields)

        if self.verify_on_read:
            try:
                envelope.verify_strict(self.keyring)
            except EnvelopeVerificationError as exc:
                _raise_verification_error(
                    exc,
                    f"Tampered or unauthorized envelope on stream '{stream}' entry '{msg_id}'",
                )

            if self.enforce_stream_audience:
                expected = expected_audience_stream if expected_audience_stream is not None else stream
                if envelope.context.target_stream != expected:
                    raise AudienceMismatchError(
                        f"Stream audience mismatch on '{stream}' entry '{msg_id}': "
                        f"envelope bound to '{envelope.context.target_stream}', expected '{expected}'."
                    )

        return StreamMessage(
            stream=stream,
            message_id=msg_id,
            envelope=envelope,
            delivery_count=delivery_count,
        )

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 1,
        block: int | None = 1000,
        stream_id: str = ">",
    ) -> list[StreamMessage]:
        """Read and cryptographically verify audience-bound envelopes via ``XREADGROUP``."""
        response = self.client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: stream_id},
            count=count,
            block=block,
        )
        if not response:
            return []

        messages: list[StreamMessage] = []
        for raw_stream, entries in response:
            stream_name = (
                raw_stream.decode("utf-8") if isinstance(raw_stream, bytes) else str(raw_stream)
            )
            for raw_id, fields in entries:
                if not fields:
                    continue
                messages.append(self._decode_entry(stream_name, raw_id, fields, delivery_count=1))
        return messages

    def ack(self, stream: str, group: str, *message_ids: str) -> int:
        """Acknowledge processed entries via ``XACK``."""
        if not message_ids:
            return 0
        return int(self.client.xack(stream, group, *message_ids))

    def get_delivery_count(self, stream: str, group: str, message_id: str) -> int:
        """Query Redis PEL (``XPENDING``) for how many times an entry was delivered."""
        pending = self.client.xpending_range(
            name=stream,
            groupname=group,
            min=message_id,
            max=message_id,
            count=1,
        )
        if not pending:
            return 1
        return int(pending[0].get("times_delivered", 1))

    def reclaim_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_time_ms: int = 5000,
        count: int = 10,
        start_id: str = "0-0",
    ) -> list[StreamMessage]:
        """Reclaim unacknowledged entries from crashed consumers via ``XAUTOCLAIM``."""
        result = self.client.xautoclaim(
            name=stream,
            groupname=group,
            consumername=consumer,
            min_idle_time=min_idle_time_ms,
            start_id=start_id,
            count=count,
        )
        entries = result[1] if len(result) >= 2 else []
        messages: list[StreamMessage] = []
        for raw_id, fields in entries:
            if not fields:
                continue
            msg_id = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else str(raw_id)
            deliveries = self.get_delivery_count(stream, group, msg_id)
            msg = self._decode_entry(stream, msg_id, fields, delivery_count=deliveries)
            updated_meta = msg.envelope.metadata.model_copy(
                update={"retry_count": max(deliveries - 1, msg.envelope.metadata.retry_count + 1)}
            )
            reclaimed_env = msg.envelope.model_copy(update={"metadata": updated_meta})
            messages.append(
                StreamMessage(
                    stream=msg.stream,
                    message_id=msg.message_id,
                    envelope=reclaimed_env,
                    delivery_count=deliveries,
                )
            )
        return messages

    def route_to_dlq(
        self,
        stream: str,
        group: str,
        message: StreamMessage,
        *,
        reason: str,
        dlq_stream: str | None = None,
    ) -> str:
        """Move an exhausted entry to the Dead-Letter Queue without losing context or seal."""
        target_dlq = dlq_stream or f"{stream}{self.dlq_suffix}"
        dlq_meta = message.envelope.metadata.model_copy(
            update={
                "retry_count": max(message.delivery_count - 1, message.envelope.metadata.retry_count),
                "dlq_reason": reason,
                "original_stream": stream,
                "original_message_id": message.message_id,
                "failed_at": time.time(),
            }
        )
        dlq_envelope = message.envelope.model_copy(update={"metadata": dlq_meta})
        dlq_id = self.publish(target_dlq, dlq_envelope, auto_seal=False, allow_dlq_stream=True)
        self.ack(stream, group, message.message_id)
        return dlq_id

    def read_dlq(
        self,
        stream: str,
        *,
        dlq_stream: str | None = None,
        count: int = 100,
    ) -> list[StreamMessage]:
        """Inspect and verify messages stored in the Dead-Letter Queue against ``stream`` audience."""
        target_dlq = dlq_stream or f"{stream}{self.dlq_suffix}"
        entries = self.client.xrange(target_dlq, min="-", max="+", count=count)
        return [
            self._decode_entry(target_dlq, raw_id, fields, expected_audience_stream=stream)
            for raw_id, fields in entries
            if fields
        ]

    def process_pending_with_dlq(
        self,
        stream: str,
        group: str,
        consumer: str,
        handler: Callable[[StreamMessage], Any],
        *,
        min_idle_time_ms: int = 0,
        max_retries: int | None = None,
        dlq_stream: str | None = None,
    ) -> dict[str, list[str]]:
        """Reclaim crashed/pending entries, re-run ``handler``, or route to DLQ on exhaustion."""
        limit = self.default_max_retries if max_retries is None else max_retries
        reclaimed = self.reclaim_pending(
            stream,
            group,
            consumer,
            min_idle_time_ms=min_idle_time_ms,
        )
        summary: dict[str, list[str]] = {"acked": [], "retried": [], "dlq": []}

        for msg in reclaimed:
            if msg.delivery_count > limit:
                dlq_id = self.route_to_dlq(
                    stream,
                    group,
                    msg,
                    reason=f"Exceeded max_retries ({limit}) after {msg.delivery_count} deliveries.",
                    dlq_stream=dlq_stream,
                )
                summary["dlq"].append(dlq_id)
                continue

            try:
                handler(msg)
            except Exception as exc:  # noqa: BLE001
                if msg.delivery_count >= limit:
                    dlq_id = self.route_to_dlq(
                        stream,
                        group,
                        msg,
                        reason=f"{type(exc).__name__}: {exc}",
                        dlq_stream=dlq_stream,
                    )
                    summary["dlq"].append(dlq_id)
                else:
                    summary["retried"].append(msg.message_id)
            else:
                self.ack(stream, group, msg.message_id)
                summary["acked"].append(msg.message_id)

        return summary
