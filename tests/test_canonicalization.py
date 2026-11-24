"""Property-based tests for deterministic canonical JSON serialization and HMAC stability.

Targets the classic edge cases where HMAC canonicalization breaks:
- Integer vs float equivalence (1 vs 1.0, -0.0 vs 0.0 vs 0).
- Unicode NFC vs NFD normalization in both dictionary keys and string values.
- Ambiguous duplicate dictionary keys colliding after NFC normalization.
- Nested dictionary key permutation invariance and JSON round-trip stability.
- Non-finite float rejection (NaN, +Inf, -Inf).
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from shield import (
    IntegrityLevel,
    KeyRing,
    KeySpec,
    SecurityContext,
    StreamEnvelope,
    canonical_json_bytes,
    compute_payload_hash,
)

# Recursive JSON-safe strategy (finite floats, NFC-distinct keys)
_json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**50), max_value=2**50),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e12, max_value=1e12),
    st.text(max_size=20),
)

_json_values: st.SearchStrategy[Any] = st.recursive(
    _json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(
            st.text(max_size=12).map(lambda s: unicodedata.normalize("NFC", s)),
            children,
            max_size=5,
        ),
    ),
    max_leaves=15,
)


@given(n=st.integers(min_value=-(2**52), max_value=2**52))
def test_int_and_integral_float_canonicalize_identically(n: int) -> None:
    """1 and 1.0 (and any exact IEEE-754 integer float) must produce identical digests."""
    assert canonical_json_bytes({"v": n}) == canonical_json_bytes({"v": float(n)})
    assert compute_payload_hash({"v": n}) == compute_payload_hash({"v": float(n)})


def test_negative_zero_positive_zero_and_int_zero_canonicalize_identically() -> None:
    h_int = compute_payload_hash({"z": 0})
    h_pos = compute_payload_hash({"z": 0.0})
    h_neg = compute_payload_hash({"z": -0.0})
    assert h_int == h_pos == h_neg


@given(
    key=st.text(min_size=1, max_size=20),
    val=st.text(max_size=40),
)
def test_unicode_nfc_and_nfd_canonicalize_identically(key: str, val: str) -> None:
    """Equivalent NFC and NFD Unicode representations must hash identically."""
    nfc_payload = {unicodedata.normalize("NFC", key): unicodedata.normalize("NFC", val)}
    nfd_payload = {unicodedata.normalize("NFD", key): unicodedata.normalize("NFD", val)}
    assert canonical_json_bytes(nfc_payload) == canonical_json_bytes(nfd_payload)
    assert compute_payload_hash(nfc_payload) == compute_payload_hash(nfd_payload)


def test_unicode_nfc_key_collision_rejected_fail_closed() -> None:
    """Two distinct Python keys collapsing to the same NFC key must be rejected."""
    nfc_key = unicodedata.normalize("NFC", "caf\u00e9")
    nfd_key = unicodedata.normalize("NFD", "caf\u00e9")
    assert nfc_key != nfd_key

    with pytest.raises(ValueError, match="Ambiguous duplicate dictionary key"):
        canonical_json_bytes({nfc_key: 1, nfd_key: 2})


@settings(max_examples=100)
@given(
    payload=st.dictionaries(
        st.text(min_size=1, max_size=12).map(lambda s: unicodedata.normalize("NFC", s)),
        _json_values,
        min_size=1,
        max_size=8,
    )
)
def test_key_permutation_and_json_roundtrip_preserve_hmac(payload: dict[str, Any]) -> None:
    """Shuffling keys and JSON-roundtripping arbitrary payloads must preserve HMAC verification."""
    reversed_payload = dict(reversed(list(payload.items())))
    assert compute_payload_hash(payload) == compute_payload_hash(reversed_payload)

    key = KeySpec.create(
        "prop-v1",
        "property-test-secret-key-0000001",
        IntegrityLevel.HIGH,
        allowed_capabilities=("db:write_role",),
    )
    ring = KeyRing([key], default_signing_kid="prop-v1")
    env = StreamEnvelope(
        context=SecurityContext(
            integrity=IntegrityLevel.HIGH,
            origin_channel="internal:test",
            allowed_sink_capabilities=("db:write_role",),
            target_stream="stream:actions",
            target_tool="update_user_role",
        ),
        payload=payload,
    ).seal(ring)

    # Full JSON wire round-trip (as occurs through Redis Streams)
    wire_json = env.model_dump_json()
    restored = StreamEnvelope.model_validate_json(wire_json)
    assert restored.verify(ring)

    # Raw payload JSON re-parse also yields identical payload hash
    reparsed_payload = json.loads(json.dumps(payload))
    assert compute_payload_hash(reparsed_payload) == env.payload_hash


@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_rejected(bad_val: float) -> None:
    with pytest.raises(ValueError, match="Non-finite"):
        canonical_json_bytes({"x": bad_val})
