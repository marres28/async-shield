"""Unit tests for SecurityContext, Biba lattice join, capability-scoped KeyRing, kid rotation, and payload-bound HMAC."""

from __future__ import annotations

import datetime
import time
from decimal import Decimal

import pytest
from pydantic import ValidationError

from shield import (
    EnvelopeVerificationError,
    IntegrityLevel,
    KeyRing,
    KeySpec,
    MissingSecretKeyError,
    SecurityContext,
    StreamEnvelope,
    canonical_json_bytes,
    compute_envelope_hmac,
    compute_payload_hash,
)


def _make_keyrings() -> tuple[KeyRing, KeyRing, KeyRing]:
    ingest_k = KeySpec.create(
        "ingest-v1",
        "test-ingest-secret-key-000001",
        IntegrityLevel.LOW,
        allowed_capabilities=("ticket:reply", "ticket:tag"),
        role="ingest",
    )
    planner_k = KeySpec.create(
        "planner-v1",
        "test-planner-secret-key-00002",
        IntegrityLevel.LOW,
        allowed_capabilities=("ticket:reply", "ticket:tag"),
        role="planner",
    )
    admin_k = KeySpec.create(
        "admin-v1",
        "test-admin-secret-key-0000003",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role", "api:payout", "ticket:reply"),
        role="admin_sso",
    )
    ingest_ring = KeyRing([ingest_k], default_signing_kid="ingest-v1")
    planner_ring = KeyRing([ingest_k, planner_k], default_signing_kid="planner-v1")
    executor_ring = KeyRing([ingest_k, planner_k, admin_k])
    return ingest_ring, planner_ring, executor_ring


def test_fail_closed_keyring_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASYNC_SHIELD_KEYS_JSON", raising=False)
    monkeypatch.delenv("ASYNC_SHIELD_SECRET_KEY", raising=False)
    monkeypatch.delenv("ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS", raising=False)

    with pytest.raises(MissingSecretKeyError):
        KeyRing.from_env(role="executor")

    with pytest.raises(MissingSecretKeyError):
        KeySpec.create("short-v1", "too-short", IntegrityLevel.LOW)

    monkeypatch.setenv("ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS", "1")
    dev_ring = KeyRing.from_env(role="ingest")
    assert dev_ring.signing_key().max_integrity == IntegrityLevel.LOW
    assert dev_ring.signing_key().allowed_capabilities == ("ticket:reply", "ticket:tag")


def test_integrity_level_lattice_ordering() -> None:
    assert IntegrityLevel.LOW < IntegrityLevel.MEDIUM < IntegrityLevel.HIGH
    assert IntegrityLevel.HIGH.satisfies(IntegrityLevel.HIGH)
    assert IntegrityLevel.HIGH.satisfies(IntegrityLevel.MEDIUM)
    assert IntegrityLevel.HIGH.satisfies(IntegrityLevel.LOW)
    assert not IntegrityLevel.MEDIUM.satisfies(IntegrityLevel.HIGH)
    assert not IntegrityLevel.LOW.satisfies(IntegrityLevel.MEDIUM)
    assert IntegrityLevel.meet([IntegrityLevel.HIGH, IntegrityLevel.LOW]) == IntegrityLevel.LOW


def test_security_context_is_immutable() -> None:
    ctx = SecurityContext(
        integrity=IntegrityLevel.LOW,
        origin_channel="webhook:support",
        allowed_sink_capabilities=["ticket:reply"],
    )
    with pytest.raises(ValidationError):
        ctx.integrity = IntegrityLevel.HIGH  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ctx.nonce = "forged"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ctx.target_tool = "update_user_role"  # type: ignore[misc]
    assert isinstance(ctx.allowed_sink_capabilities, tuple)


def test_lattice_join_enforces_taint_monotonicity_and_capability_attenuation() -> None:
    now = round(time.time(), 6)
    high_ctx = SecurityContext(
        integrity=IntegrityLevel.HIGH,
        origin_channel="internal:config",
        allowed_sink_capabilities=["db:write_role", "ticket:reply", "ticket:tag"],
        created_at=now - 10,
        expires_at=now + 300,
    )
    low_ctx = SecurityContext(
        integrity=IntegrityLevel.LOW,
        origin_channel="webhook:ticket",
        allowed_sink_capabilities=["ticket:reply", "ticket:tag"],
        created_at=now - 2,
        expires_at=now + 60,
    )

    joined = SecurityContext.join([high_ctx, low_ctx], target_stream="stream:actions", target_tool="reply_to_ticket")
    assert joined.integrity == IntegrityLevel.LOW
    assert set(joined.allowed_sink_capabilities) == {"ticket:reply", "ticket:tag"}
    assert "db:write_role" not in joined.allowed_sink_capabilities
    assert joined.target_stream == "stream:actions"
    assert joined.target_tool == "reply_to_ticket"
    assert joined.origin_channel == "join(internal:config,webhook:ticket)"
    assert joined.created_at == now - 10
    assert joined.expires_at == now + 60


def test_payload_hash_binding_catches_payload_swap_on_valid_high_envelope() -> None:
    _, _, exec_ring = _make_keyrings()
    admin_key = exec_ring.get("admin-v1")
    assert admin_key is not None
    admin_ring = KeyRing([admin_key], default_signing_kid="admin-v1")

    env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
            target_stream="stream:actions",
            target_tool="update_user_role",
        ),
        payload={"tool": "update_user_role", "user_id": "alice", "new_role": "lead_support"},
    ).seal(admin_ring)

    assert env.verify(exec_ring)

    swapped = env.model_copy(
        update={
            "payload": {"tool": "update_user_role", "user_id": "attacker", "new_role": "admin"},
        }
    )
    with pytest.raises(EnvelopeVerificationError, match="Payload SHA-256 digest mismatch"):
        swapped.verify_strict(exec_ring)


def test_role_separation_prevents_low_key_from_minting_high() -> None:
    ingest_ring, _, exec_ring = _make_keyrings()
    high_ctx = SecurityContext(
        integrity=IntegrityLevel.HIGH,
        origin_channel="internal:admin_sso",
        allowed_sink_capabilities=["ticket:reply"],
    )
    forged_env = StreamEnvelope(context=high_ctx, payload={"user_id": "guest_01"})

    with pytest.raises(EnvelopeVerificationError) as exc_seal:
        forged_env.seal(ingest_ring)
    assert exc_seal.value.unauthorized_issuer is True

    ingest_key = ingest_ring.signing_key()
    p_hash = compute_payload_hash(forged_env.payload)
    manually_signed = forged_env.model_copy(
        update={
            "kid": ingest_key.kid,
            "payload_hash": p_hash,
            "signature": compute_envelope_hmac(ingest_key, high_ctx, p_hash),
        }
    )
    with pytest.raises(EnvelopeVerificationError) as exc_verify:
        manually_signed.verify_strict(exec_ring)
    assert exc_verify.value.unauthorized_issuer is True


def test_capability_scoped_key_prevents_low_key_from_minting_disallowed_low_capability() -> None:
    """A compromised LOW ingest worker cannot mint arbitrary LOW capabilities like 'payments:refund'."""
    ingest_ring, _, exec_ring = _make_keyrings()
    ctx = SecurityContext(
        integrity=IntegrityLevel.LOW,
        origin_channel="webhook:support_ticket",
        allowed_sink_capabilities=["payments:refund"],
        target_stream="stream:actions",
        target_tool="issue_refund",
    )
    env = StreamEnvelope(context=ctx, payload={"amount": 500})

    # Blocked locally at seal()
    with pytest.raises(EnvelopeVerificationError) as exc_seal:
        env.seal(ingest_ring)
    assert exc_seal.value.unauthorized_issuer is True
    assert "payments:refund" in exc_seal.value.reason

    # Even if attacker manually computes HMAC using ingest-v1 secret, verifier rejects it!
    ingest_key = ingest_ring.signing_key()
    p_hash = compute_payload_hash(env.payload)
    forged = env.model_copy(
        update={
            "kid": ingest_key.kid,
            "payload_hash": p_hash,
            "signature": compute_envelope_hmac(ingest_key, ctx, p_hash),
        }
    )
    with pytest.raises(EnvelopeVerificationError) as exc_verify:
        forged.verify_strict(exec_ring)
    assert exc_verify.value.unauthorized_issuer is True


def test_key_rotation_with_kid() -> None:
    old_k = KeySpec.create(
        "admin-v1",
        "old-admin-secret-key-000000001",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role",),
        role="admin_sso",
        active_for_signing=True,
    )
    new_k = KeySpec.create(
        "admin-v2",
        "new-admin-secret-key-000000002",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role",),
        role="admin_sso",
        active_for_signing=True,
    )
    pre_rot_ring = KeyRing([old_k], default_signing_kid="admin-v1")
    in_flight = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
        ),
        payload={"user_id": "alice", "new_role": "lead_support"},
    ).seal(pre_rot_ring)
    assert in_flight.kid == "admin-v1"

    retired_old_k = KeySpec.create(
        "admin-v1",
        "old-admin-secret-key-000000001",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role",),
        role="admin_sso",
        active_for_signing=False,
    )
    rotated_ring = KeyRing([retired_old_k, new_k], default_signing_kid="admin-v2")
    assert in_flight.verify(rotated_ring)

    post_rot = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:admin_sso",
            allowed_sink_capabilities=["db:write_role"],
        ),
        payload={"user_id": "bob", "new_role": "support"},
    ).seal(rotated_ring)
    assert post_rot.kid == "admin-v2"
    assert post_rot.verify(rotated_ring)

    with pytest.raises(ValueError, match="retired"):
        post_rot.seal(rotated_ring, kid="admin-v1")


def test_deterministic_canonical_serialization() -> None:
    d1 = {
        "b": 1,
        "a": datetime.datetime(2026, 11, 24, 9, 30, 0, tzinfo=datetime.timezone.utc),
        "c": Decimal("10.50"),
        "z": -0.0,
    }
    d2 = {
        "z": 0.0,
        "c": Decimal("10.5"),
        "a": datetime.datetime(2026, 11, 24, 9, 30, 0),
        "b": 1.0,
    }
    assert canonical_json_bytes(d1) == canonical_json_bytes(d2)
    assert compute_payload_hash(d1) == compute_payload_hash(d2)


def test_derive_re_seals_with_worker_key_and_clamps_integrity_and_capabilities() -> None:
    ingest_ring, planner_ring, exec_ring = _make_keyrings()
    upstream = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.LOW,
            origin_channel="webhook:ticket",
            allowed_sink_capabilities=["ticket:reply"],
            target_stream="stream:tickets",
        ),
        payload={"ticket_id": "T-1"},
    ).seal(ingest_ring)

    derived = upstream.derive(
        {"tool": "update_user_role", "user_id": "guest_01"},
        keyring=planner_ring,
        worker_name="worker-planner",
        target_stream="stream:actions",
        target_tool="update_user_role",
    )
    assert derived.kid == "planner-v1"
    assert derived.context.integrity == IntegrityLevel.LOW
    assert derived.context.target_stream == "stream:actions"
    assert derived.context.target_tool == "update_user_role"
    assert derived.context.trace_id == upstream.context.trace_id
    assert derived.context.nonce != upstream.context.nonce
    assert derived.verify(exec_ring)
