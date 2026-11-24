"""Role- and capability-scoped HMAC keyring with key-ID (``kid``) rotation and fail-closed loading.

Security properties:
- **Fail-closed startup**: missing key configuration raises ``MissingSecretKeyError``
  instead of falling back to a hardcoded secret. Development keys are only loaded
  when explicitly opted in via ``ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS=1`` or
  ``allow_insecure_dev_keys=True``.
- **Integrity & capability scoping per ``kid``**: each key carries both a
  ``max_integrity`` ceiling and an explicit ``allowed_capabilities`` allowlist.
  A compromised ``LOW`` worker cannot mint ``HIGH`` envelopes OR arbitrary
  ``LOW`` capabilities (such as ``payments:refund``) outside its key's allowlist.
- **Zero-downtime rotation**: every envelope embeds ``kid``. Retiring keys can
  remain verify-only (``active_for_signing=False``) while a new ``kid`` signs.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Iterable

from shield.types import IntegrityLevel

MIN_SECRET_BYTES = 16


class MissingSecretKeyError(RuntimeError):
    """Raised on startup when no signing/verification keys are configured."""


@dataclass(frozen=True)
class KeySpec:
    """Single HMAC key entry scoped to a maximum integrity level and capability allowlist."""

    kid: str
    secret: bytes
    max_integrity: IntegrityLevel
    allowed_capabilities: tuple[str, ...] = ()
    role: str = "generic"
    active_for_signing: bool = True

    def can_mint_capabilities(self, capabilities: Iterable[str]) -> bool:
        """Return True iff every requested capability is permitted by this key."""
        if "*" in self.allowed_capabilities:
            return True
        allowed = set(self.allowed_capabilities)
        return all(cap in allowed for cap in capabilities)

    @classmethod
    def create(
        cls,
        kid: str,
        secret: str | bytes,
        max_integrity: IntegrityLevel | str,
        *,
        allowed_capabilities: Iterable[str] = (),
        role: str = "generic",
        active_for_signing: bool = True,
        allow_short_secret: bool = False,
    ) -> KeySpec:
        raw_secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not raw_secret:
            raise MissingSecretKeyError(f"Secret for kid='{kid}' cannot be empty.")
        if not allow_short_secret and len(raw_secret) < MIN_SECRET_BYTES:
            raise MissingSecretKeyError(
                f"Secret for kid='{kid}' must be at least {MIN_SECRET_BYTES} bytes."
            )
        level = (
            max_integrity
            if isinstance(max_integrity, IntegrityLevel)
            else IntegrityLevel(str(max_integrity).lower())
        )
        caps = tuple(dict.fromkeys(str(c) for c in allowed_capabilities))
        return cls(
            kid=kid,
            secret=raw_secret,
            max_integrity=level,
            allowed_capabilities=caps,
            role=role,
            active_for_signing=active_for_signing,
        )


class KeyRing:
    """Collection of role- and capability-scoped HMAC keys indexed by ``kid``."""

    def __init__(
        self,
        keys: Iterable[KeySpec],
        *,
        default_signing_kid: str | None = None,
    ) -> None:
        key_map: dict[str, KeySpec] = {}
        for spec in keys:
            if spec.kid in key_map:
                raise ValueError(f"Duplicate kid '{spec.kid}' in KeyRing.")
            key_map[spec.kid] = spec

        if not key_map:
            raise MissingSecretKeyError("KeyRing requires at least one KeySpec.")

        self._keys = key_map
        if default_signing_kid is not None:
            if default_signing_kid not in self._keys:
                raise KeyError(f"default_signing_kid '{default_signing_kid}' not in KeyRing.")
            self._default_signing_kid: str | None = default_signing_kid
        else:
            active = [k.kid for k in self._keys.values() if k.active_for_signing]
            self._default_signing_kid = active[0] if len(active) == 1 else None

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(self._keys.keys())

    def get(self, kid: str) -> KeySpec | None:
        return self._keys.get(kid)

    def signing_key(self, kid: str | None = None) -> KeySpec:
        target_kid = kid or self._default_signing_kid
        if target_kid is None:
            raise KeyError(
                "No signing kid specified and KeyRing has multiple active keys; "
                "pass an explicit 'kid' or set 'default_signing_kid'."
            )
        spec = self._keys.get(target_kid)
        if spec is None:
            raise KeyError(f"Unknown signing kid '{target_kid}'.")
        if not spec.active_for_signing:
            raise ValueError(
                f"Key '{target_kid}' is retired (active_for_signing=False) and cannot sign."
            )
        return spec

    @classmethod
    def from_json(
        cls,
        raw_json: str,
        *,
        default_signing_kid: str | None = None,
        allow_short_secret: bool = False,
    ) -> KeyRing:
        """Load a KeyRing from a JSON array of key specifications."""
        parsed = json.loads(raw_json)
        if not isinstance(parsed, list) or not parsed:
            raise MissingSecretKeyError("ASYNC_SHIELD_KEYS_JSON must be a non-empty JSON array.")
        specs = [
            KeySpec.create(
                kid=item["kid"],
                secret=item["secret"],
                max_integrity=item["max_integrity"],
                allowed_capabilities=item.get("allowed_capabilities", ()),
                role=item.get("role", "generic"),
                active_for_signing=item.get("active_for_signing", True),
                allow_short_secret=allow_short_secret,
            )
            for item in parsed
        ]
        return cls(specs, default_signing_kid=default_signing_kid)

    @classmethod
    def insecure_dev_keyring(
        cls,
        *,
        role: str = "all",
        warn: bool = True,
    ) -> KeyRing:
        """Explicit opt-in keyring for local demos/tests ONLY (never use in production)."""
        if warn:
            print(
                "[ASYNC-SHIELD WARNING] Using insecure development keys "
                "(ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS=1). Do NOT use in production.",
                file=sys.stderr,
            )
        all_specs = {
            "ingest": KeySpec.create(
                "ingest-dev-v1",
                "dev-only-ingest-key-not-for-prod-01",
                IntegrityLevel.LOW,
                allowed_capabilities=("ticket:reply", "ticket:tag"),
                role="ingest",
            ),
            "planner": KeySpec.create(
                "planner-dev-v1",
                "dev-only-planner-key-not-for-prod-02",
                IntegrityLevel.LOW,
                allowed_capabilities=("ticket:reply", "ticket:tag"),
                role="planner",
            ),
            "admin": KeySpec.create(
                "admin-dev-v1",
                "dev-only-admin-key-not-for-prod-03",
                IntegrityLevel.HIGH,
                allowed_capabilities=("db:write_role", "api:payout", "ticket:reply"),
                role="admin_sso",
            ),
        }
        if role == "all":
            return cls(all_specs.values(), default_signing_kid="ingest-dev-v1")
        if role == "executor":
            return cls(all_specs.values())
        if role not in all_specs:
            raise ValueError(
                f"Unknown dev role '{role}'. Expected ingest, planner, admin, executor, or all."
            )
        spec = all_specs[role]
        return cls([spec], default_signing_kid=spec.kid)

    @classmethod
    def from_env(
        cls,
        *,
        role: str = "all",
        keys_env: str = "ASYNC_SHIELD_KEYS_JSON",
        signing_kid_env: str = "ASYNC_SHIELD_SIGNING_KID",
        single_secret_env: str = "ASYNC_SHIELD_SECRET_KEY",
        single_kid_env: str = "ASYNC_SHIELD_KEY_ID",
        single_max_integrity_env: str = "ASYNC_SHIELD_KEY_MAX_INTEGRITY",
        single_caps_env: str = "ASYNC_SHIELD_KEY_CAPABILITIES",
        allow_insecure_dev_keys: bool = False,
    ) -> KeyRing:
        """Load keys fail-closed from environment variables.

        Refuses to start if neither ``ASYNC_SHIELD_KEYS_JSON`` nor
        ``ASYNC_SHIELD_SECRET_KEY`` is configured, unless the caller explicitly
        opts into insecure dev keys via ``allow_insecure_dev_keys=True`` or
        ``ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS=1``.
        """
        default_kid = os.getenv(signing_kid_env) or None
        raw_json = os.getenv(keys_env)
        if raw_json:
            return cls.from_json(raw_json, default_signing_kid=default_kid)

        single_secret = os.getenv(single_secret_env)
        if single_secret:
            kid = os.getenv(single_kid_env, f"{role}-v1")
            max_lvl = os.getenv(single_max_integrity_env, IntegrityLevel.LOW.value)
            raw_caps = os.getenv(single_caps_env, "")
            caps = tuple(c.strip() for c in raw_caps.split(",") if c.strip())
            spec = KeySpec.create(
                kid=kid,
                secret=single_secret,
                max_integrity=max_lvl,
                allowed_capabilities=caps,
                role=role,
            )
            return cls([spec], default_signing_kid=kid)

        dev_opt_in = allow_insecure_dev_keys or (
            os.getenv("ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS", "").strip() == "1"
        )
        if dev_opt_in:
            return cls.insecure_dev_keyring(role=role)

        raise MissingSecretKeyError(
            "Async-Shield refused to start (fail-closed): no HMAC keys configured. "
            "Set ASYNC_SHIELD_KEYS_JSON (recommended for role separation & rotation) "
            "or ASYNC_SHIELD_SECRET_KEY. For local development ONLY, explicitly set "
            "ASYNC_SHIELD_ALLOW_INSECURE_DEV_KEYS=1."
        )
