"""Unit tests for fail-closed SinkGate: mandatory expected_stream, audience binding, replay TTL, at-most-once, and Redis failure."""

from __future__ import annotations

import math
import time
from typing import Any

import pytest
import redis

from shield import (
    AudienceMismatchError,
    CapabilityViolationError,
    ContextExpiredError,
    InMemoryReplayStore,
    IntegrityLevel,
    IntegrityViolationError,
    KeyRing,
    KeySpec,
    RedisReplayStore,
    ReplayDetectedError,
    ReplayStoreUnavailableError,
    SecurityContext,
    SinkGate,
    StreamEnvelope,
    TamperedEnvelopeError,
    UnauthorizedIssuerError,
    UnenvelopedPayloadError,
    compute_envelope_hmac,
    compute_payload_hash,
)

TEST_STREAM = "stream:actions"


def _setup_rings() -> tuple[KeyRing, KeyRing, KeyRing, KeyRing]:
    low_k = KeySpec.create(
        "ingest-v1",
        "test-ingest-secret-key-000001",
        IntegrityLevel.LOW,
        allowed_capabilities=("ticket:reply", "ticket:tag"),
        role="ingest",
    )
    med_k = KeySpec.create(
        "parser-v1",
        "test-parser-secret-key-000002",
        IntegrityLevel.MEDIUM,
        allowed_capabilities=("db:write_role", "ticket:reply"),
        role="parser",
    )
    high_k = KeySpec.create(
        "admin-v1",
        "test-admin-secret-key-0000003",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role", "api:invoice_read", "ticket:reply"),
        role="admin_sso",
    )
    return (
        KeyRing([low_k], default_signing_kid="ingest-v1"),
        KeyRing([med_k], default_signing_kid="parser-v1"),
        KeyRing([high_k], default_signing_kid="admin-v1"),
        KeyRing([low_k, med_k, high_k]),
    )


def test_sink_gate_requires_non_empty_expected_stream() -> None:
    _, _, _, exec_r = _setup_rings()
    with pytest.raises(TypeError):
        SinkGate(keyring=exec_r)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="expected_stream"):
        SinkGate(keyring=exec_r, expected_stream="")
    with pytest.raises(ValueError, match="expected_stream"):
        SinkGate(keyring=exec_r, expected_stream="   ")


def test_sink_gate_blocks_low_and_medium_integrity_for_high_sink() -> None:
    low_r, med_r, _, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM, replay_store=InMemoryReplayStore())
    db_writes = 0

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        nonlocal db_writes
        db_writes += 1
        return f"updated:{payload['user_id']}"

    low_env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.LOW,
            origin_channel="webhook:ticket",
            allowed_sink_capabilities=["ticket:reply"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "guest_01", "new_role": "admin"},
    ).seal(low_r)

    with pytest.raises(IntegrityViolationError) as exc_low:
        update_user_role(low_env)
    assert exc_low.value.audit is not None
    assert not exc_low.value.audit.allowed

    med_env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.MEDIUM,
            origin_channel="internal:parser",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "guest_01", "new_role": "admin"},
    ).seal(med_r)

    with pytest.raises(IntegrityViolationError):
        update_user_role(med_env)

    assert db_writes == 0


def test_sink_gate_blocks_missing_capability_even_with_high_integrity() -> None:
    _, _, high_r, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM)

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        return payload["user_id"]

    env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:billing",
            allowed_sink_capabilities=["api:invoice_read"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "guest_01"},
    ).seal(high_r)

    with pytest.raises(CapabilityViolationError):
        update_user_role(env)


def test_sink_gate_blocks_raw_dict_bypass() -> None:
    _, _, _, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM)

    @gate.secure_tool(IntegrityLevel.LOW, capability_name="ticket:reply")
    def reply(payload: dict[str, Any]) -> str:
        return payload["msg"]

    with pytest.raises(UnenvelopedPayloadError):
        reply({"msg": "bypass"})  # type: ignore[arg-type]


def test_sink_gate_blocks_payload_swap_on_valid_high_envelope() -> None:
    _, _, high_r, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM)

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        return payload["user_id"]

    valid = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "alice", "new_role": "lead_support"},
    ).seal(high_r)

    swapped = valid.model_copy(
        update={"payload": {"user_id": "guest_01", "new_role": "admin"}}
    )
    with pytest.raises(TamperedEnvelopeError):
        update_user_role(swapped)


def test_sink_gate_blocks_unauthorized_low_key_minting_disallowed_low_capability() -> None:
    """A compromised LOW ingest key cannot mint 'payments:refund' to invoke a LOW refund sink."""
    low_r, _, _, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM)

    @gate.secure_tool(IntegrityLevel.LOW, capability_name="payments:refund")
    def issue_refund(payload: dict[str, Any]) -> str:
        return str(payload["amount"])

    ctx = SecurityContext(
        integrity=IntegrityLevel.LOW,
        origin_channel="webhook:support",
        allowed_sink_capabilities=["payments:refund"],
        target_stream=TEST_STREAM,
        target_tool="issue_refund",
        expires_at=time.time() + 60,
    )
    payload = {"amount": 999}
    low_key = low_r.signing_key()
    p_hash = compute_payload_hash(payload)
    forged = StreamEnvelope(
        context=ctx,
        payload=payload,
        kid=low_key.kid,
        payload_hash=p_hash,
        signature=compute_envelope_hmac(low_key, ctx, p_hash),
    )

    with pytest.raises(UnauthorizedIssuerError):
        issue_refund(forged)


def test_sink_gate_enforces_tool_and_stream_audience_binding() -> None:
    _, _, high_r, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM, require_tool_audience=True)

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        return payload["user_id"]

    # 1. Valid HIGH envelope signed for 'reply_to_ticket' redirected to 'update_user_role' -> BLOCKED
    wrong_tool = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role", "ticket:reply"],
            target_stream=TEST_STREAM,
            target_tool="reply_to_ticket",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)
    with pytest.raises(AudienceMismatchError, match="targets tool 'reply_to_ticket'"):
        update_user_role(wrong_tool)

    # 2. Valid HIGH envelope signed for another stream -> BLOCKED
    wrong_stream = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream="stream:other_pipeline",
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)
    with pytest.raises(AudienceMismatchError, match="Stream audience mismatch"):
        update_user_role(wrong_stream)

    # 3. Missing target_stream -> BLOCKED (fail-closed)
    missing_stream = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=None,
            target_tool="update_user_role",
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)
    with pytest.raises(AudienceMismatchError, match="Stream audience mismatch"):
        update_user_role(missing_stream)

    # 4. Missing target_tool audience binding -> BLOCKED
    missing_tool = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool=None,
            expires_at=time.time() + 60,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)
    with pytest.raises(AudienceMismatchError, match="Missing signed target_tool"):
        update_user_role(missing_tool)


def test_replay_ttl_invariant_and_missing_expiry_rejection() -> None:
    """replay_ttl = ceil(expires_at - now) + clock_skew_seconds, and missing expires_at is rejected."""
    _, _, high_r, exec_r = _setup_rings()
    replay_store = InMemoryReplayStore()
    clock_skew = 90
    gate = SinkGate(
        keyring=exec_r,
        expected_stream=TEST_STREAM,
        replay_store=replay_store,
        clock_skew_seconds=clock_skew,
        require_expiry_for_replay=True,
    )

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        return payload["user_id"]

    no_exp = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=None,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)
    with pytest.raises(ContextExpiredError, match="requires explicit expires_at"):
        update_user_role(no_exp)

    before = time.time()
    expires_at = before + 5000.0
    long_lived = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=expires_at,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)

    assert update_user_role(long_lived) == "alice"
    after = time.time()
    assert replay_store.last_ttl_seconds is not None
    assert replay_store.last_ttl_seconds >= math.ceil(expires_at - after) + clock_skew


def test_at_most_once_semantics_nonce_consumed_even_if_tool_fails() -> None:
    """Documents & tests at-most-once semantics: if tool throws after SET NX, redelivery is blocked."""
    _, _, high_r, exec_r = _setup_rings()
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM, replay_store=InMemoryReplayStore())
    attempts = 0

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def flaky_db_write(payload: dict[str, Any]) -> str:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("DB connection dropped mid-commit")

    env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="flaky_db_write",
            expires_at=time.time() + 120,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)

    with pytest.raises(RuntimeError, match="DB connection dropped"):
        flaky_db_write(env)
    assert attempts == 1

    with pytest.raises(ReplayDetectedError):
        flaky_db_write(env)
    assert attempts == 1


def test_sink_gate_fails_closed_when_redis_replay_store_is_down() -> None:
    """If Redis is unreachable, SinkGate must refuse execution (fail-closed) with ReplayStoreUnavailableError."""
    _, _, high_r, exec_r = _setup_rings()

    class BrokenRedis:
        def set(self, *args: Any, **kwargs: Any) -> Any:
            raise redis.exceptions.ConnectionError("Connection refused: Redis is down")

    broken_store = RedisReplayStore(BrokenRedis())  # type: ignore[arg-type]
    gate = SinkGate(keyring=exec_r, expected_stream=TEST_STREAM, replay_store=broken_store)
    db_writes = 0

    @gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
    def update_user_role(payload: dict[str, Any]) -> str:
        nonlocal db_writes
        db_writes += 1
        return payload["user_id"]

    env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream=TEST_STREAM,
            target_tool="update_user_role",
            expires_at=time.time() + 120,
        ),
        payload={"user_id": "alice"},
    ).seal(high_r)

    with pytest.raises(ReplayStoreUnavailableError) as exc_info:
        update_user_role(env)
    assert db_writes == 0
    assert exc_info.value.audit is not None
    assert exc_info.value.audit.allowed is False
