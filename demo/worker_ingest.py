"""Worker 1 (Ingest): receives untrusted tickets/webhooks and publishes to Redis Streams.

Role separation:
- In ``protected`` mode, ``worker_ingest`` holds ONLY a ``LOW``-integrity signing
  key (e.g. ``ingest-v1``). Even if compromised, it cannot mint a ``HIGH`` envelope.
- Authoritative admin commands must be minted by a separate Admin/SSO service
  holding a ``HIGH``-integrity key (e.g. ``admin-v1``).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import redis

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shield import IntegrityLevel, KeyRing, ShieldBroker, StreamEnvelope


class IngestWorker:
    """Ingests external support tickets (capped at LOW integrity via role key)."""

    def __init__(
        self,
        client: redis.Redis,
        *,
        mode: str = "protected",
        keyring: KeyRing | None = None,
        signing_kid: str | None = None,
        raw_ingress_stream: str = "stream:raw_webhooks",
        tickets_stream: str = "stream:tickets",
    ) -> None:
        self.client = client
        self.mode = mode
        self.raw_ingress_stream = raw_ingress_stream
        self.tickets_stream = tickets_stream
        self.broker: ShieldBroker | None = None
        if mode == "protected":
            if keyring is None:
                raise ValueError("protected mode requires an explicit KeyRing (fail-closed).")
            self.broker = ShieldBroker(client, keyring=keyring, signing_kid=signing_kid)

    def ingest_ticket(self, ticket: dict[str, Any]) -> tuple[str, StreamEnvelope | None]:
        """Publish an untrusted external ticket onto the tickets stream."""
        if self.mode == "vulnerable":
            msg_id = self.client.xadd(
                self.tickets_stream,
                {"payload": json.dumps(ticket)},
            )
            return str(msg_id), None

        assert self.broker is not None
        msg_id, envelope = self.broker.publish_ingress(
            self.tickets_stream,
            payload=ticket,
            origin_channel="webhook:support_ticket",
            integrity=IntegrityLevel.LOW,
            allowed_sink_capabilities=["ticket:reply", "ticket:tag"],
            ttl_seconds=300.0,
            worker_name="worker-ingest",
        )
        return msg_id, envelope

    def run_forever(self, consumer_name: str = "ingest-1") -> None:
        """Daemon loop for Docker Compose: forwards raw webhook entries into tickets_stream."""
        group = "ingest-group"
        try:
            self.client.xgroup_create(self.raw_ingress_stream, group, id="0", mkstream=True)
        except redis.exceptions.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

        print(
            f"[INGEST] Started (mode={self.mode}, "
            f"in={self.raw_ingress_stream} -> out={self.tickets_stream})",
            flush=True,
        )
        while True:
            entries = self.client.xreadgroup(
                groupname=group,
                consumername=consumer_name,
                streams={self.raw_ingress_stream: ">"},
                count=10,
                block=1000,
            )
            if not entries:
                continue
            for _, msgs in entries:
                for msg_id, fields in msgs:
                    raw_payload = fields.get("payload", "{}")
                    ticket = json.loads(raw_payload)
                    out_id, env = self.ingest_ticket(ticket)
                    self.client.xack(self.raw_ingress_stream, group, msg_id)
                    label = (
                        f"{env.context.integrity.value.upper()} (kid={env.kid})"
                        if env
                        else "NONE (RAW)"
                    )
                    print(
                        f"[INGEST] Forwarded ticket={ticket.get('ticket_id')} "
                        f"-> {self.tickets_stream} ({out_id}) | integrity={label}",
                        flush=True,
                    )


class AdminGateway:
    """Separate authoritative issuer holding a HIGH-integrity signing key."""

    def __init__(
        self,
        client: redis.Redis,
        *,
        keyring: KeyRing,
        signing_kid: str | None = None,
        actions_stream: str = "stream:actions",
    ) -> None:
        self.actions_stream = actions_stream
        self.broker = ShieldBroker(client, keyring=keyring, signing_kid=signing_kid)

    def dispatch_admin_action(
        self,
        action: dict[str, Any],
        *,
        ttl_seconds: float = 60.0,
    ) -> tuple[str, StreamEnvelope]:
        return self.broker.publish_ingress(
            self.actions_stream,
            payload=action,
            origin_channel="internal:admin_sso",
            integrity=IntegrityLevel.HIGH,
            allowed_sink_capabilities=["db:write_role", "api:payout", "ticket:reply"],
            target_tool=str(action.get("tool", "")) or None,
            ttl_seconds=ttl_seconds,
            worker_name="admin-sso-gateway",
        )


def main() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    mode = os.getenv("SHIELD_MODE", "protected")
    keyring = KeyRing.from_env(role="ingest") if mode == "protected" else None

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    for _ in range(20):
        try:
            client.ping()
            break
        except redis.exceptions.ConnectionError:
            time.sleep(0.5)

    worker = IngestWorker(client, mode=mode, keyring=keyring)
    worker.run_forever()


if __name__ == "__main__":
    main()
