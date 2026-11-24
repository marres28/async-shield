"""Worker 3 (Executor): executes privileged DB tools behind the fail-closed SinkGate.

- Verifies role-scoped ``KeyRing`` authority, payload SHA-256 hash, constant-time
  HMAC-SHA256, TTL freshness, Biba integrity level, capability membership, and
  atomic single-use nonces via ``RedisReplayStore``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import redis

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.mock_db import MockUserDB
from shield import (
    AuditRecord,
    IntegrityLevel,
    KeyRing,
    RedisReplayStore,
    ReplayStore,
    SecurityException,
    ShieldBroker,
    SinkGate,
)


@dataclass
class ExecutionOutcome:
    """Result of executing or blocking a single action message."""

    tool: str
    user_id: str | None
    allowed: bool
    status_lines: list[str]
    audit: AuditRecord | None = None
    result: dict[str, Any] | None = None


class ExecutorWorker:
    """Consumes planned actions and invokes DB tools behind SinkGate + ReplayStore."""

    def __init__(
        self,
        client: redis.Redis,
        db: MockUserDB,
        *,
        mode: str = "protected",
        keyring: KeyRing | None = None,
        replay_store: ReplayStore | None = None,
        actions_stream: str = "stream:actions",
        group: str = "executor-group",
        consumer: str = "executor-1",
    ) -> None:
        self.client = client
        self.db = db
        self.mode = mode
        self.actions_stream = actions_stream
        self.group = group
        self.consumer = consumer
        self.broker: ShieldBroker | None = None
        self.gate: SinkGate | None = None

        if mode == "protected":
            if keyring is None:
                raise ValueError("protected mode requires an explicit KeyRing (fail-closed).")
            self.broker = ShieldBroker(client, keyring=keyring, verify_on_read=True)
            self.broker.ensure_group(self.actions_stream, self.group)
            active_replay = replay_store or RedisReplayStore(client)
            self.gate = SinkGate(
                keyring=keyring,
                replay_store=active_replay,
                expected_stream=self.actions_stream,
                require_tool_audience=True,
            )

            @self.gate.secure_tool(IntegrityLevel.HIGH, capability_name="db:write_role")
            def update_user_role(payload: dict[str, Any]) -> dict[str, Any]:
                return self.db.update_role(payload["user_id"], payload["new_role"])

            @self.gate.secure_tool(IntegrityLevel.LOW, capability_name="ticket:reply")
            def reply_to_ticket(payload: dict[str, Any]) -> dict[str, Any]:
                return self.db.record_reply(
                    ticket_id=str(payload.get("ticket_id", "TKT-000")),
                    user_id=str(payload.get("user_id", "unknown")),
                    message=str(payload.get("message", "")),
                )

            self._protected_tools = {
                "update_user_role": update_user_role,
                "reply_to_ticket": reply_to_ticket,
            }
        else:
            try:
                self.client.xgroup_create(self.actions_stream, self.group, id="0", mkstream=True)
            except redis.exceptions.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
            self._protected_tools = {}

    def _execute_vulnerable(self, action: dict[str, Any]) -> ExecutionOutcome:
        tool_name = str(action.get("tool", "unknown"))
        user_id = action.get("user_id")

        if tool_name == "update_user_role":
            res = self.db.update_role(str(user_id), str(action["new_role"]))
            lines = [
                f"[EXECUTOR] Received call '{tool_name}' for '{user_id}' (no security context check).",
                f"[EXPLOIT SUCCESS] Role '{res['new_role']}' assigned to '{user_id}' "
                f"(was: '{res['previous_role']}', db_writes: {res['write_count']}).",
            ]
            return ExecutionOutcome(
                tool=tool_name,
                user_id=str(user_id),
                allowed=True,
                status_lines=lines,
                result=res,
            )

        if tool_name == "reply_to_ticket":
            res = self.db.record_reply(
                ticket_id=str(action.get("ticket_id", "TKT-000")),
                user_id=str(user_id),
                message=str(action.get("message", "")),
            )
            return ExecutionOutcome(
                tool=tool_name,
                user_id=str(user_id),
                allowed=True,
                status_lines=[f"[EXECUTOR] Reply recorded for ticket {res['ticket_id']}."],
                result=res,
            )

        return ExecutionOutcome(
            tool=tool_name,
            user_id=str(user_id) if user_id else None,
            allowed=False,
            status_lines=[f"[EXECUTOR] Unknown tool: '{tool_name}'."],
        )

    def _execute_protected(self, msg: Any) -> ExecutionOutcome:
        assert self.gate is not None
        envelope = msg.envelope
        payload = envelope.payload
        tool_name = str(payload.get("tool", "unknown"))
        user_id = payload.get("user_id")
        tool_fn = self._protected_tools.get(tool_name)

        if tool_fn is None:
            return ExecutionOutcome(
                tool=tool_name,
                user_id=str(user_id) if user_id else None,
                allowed=False,
                status_lines=[f"[SECURITY GATE] Unregistered tool: '{tool_name}'."],
            )

        try:
            res = tool_fn(envelope)
            audit = self.gate.audit_log[-1]
            if tool_name == "update_user_role":
                lines = [
                    f"[SECURITY GATE] Allowed '{tool_name}' for '{user_id}' "
                    f"(integrity={audit.context_integrity.value.upper()}, kid={audit.kid}, "
                    f"origin={audit.origin_channel}).",
                    f"[ACTION ALLOWED] Role updated to '{res['new_role']}'. "
                    f"Verification overhead: {audit.overhead_ms:.3f} ms.",
                ]
            else:
                lines = [
                    f"[SECURITY GATE] Allowed '{tool_name}' for '{user_id}' "
                    f"(integrity={audit.context_integrity.value.upper()}, kid={audit.kid}).",
                    f"[ACTION ALLOWED] Reply recorded for ticket {res['ticket_id']}. "
                    f"Verification overhead: {audit.overhead_ms:.3f} ms.",
                ]
            return ExecutionOutcome(
                tool=tool_name,
                user_id=str(user_id) if user_id else None,
                allowed=True,
                status_lines=lines,
                audit=audit,
                result=res,
            )
        except SecurityException as exc:
            audit = exc.audit
            overhead_str = f"{audit.overhead_ms:.3f} ms" if audit else "n/a"
            reason_str = audit.reason if audit else str(exc)
            lines = [
                f"[SECURITY GATE] Intercepted call '{tool_name}' for '{user_id}'.",
                f"[VIOLATION] {reason_str}",
                "[ACTION BLOCKED] Execution halted. Zero database writes.",
                f"Verification overhead: {overhead_str}.",
            ]
            return ExecutionOutcome(
                tool=tool_name,
                user_id=str(user_id) if user_id else None,
                allowed=False,
                status_lines=lines,
                audit=audit,
            )

    def process_once(self, block_ms: int = 500) -> list[ExecutionOutcome]:
        """Consume and process available action messages once."""
        outcomes: list[ExecutionOutcome] = []

        if self.mode == "vulnerable":
            entries = self.client.xreadgroup(
                groupname=self.group,
                consumername=self.consumer,
                streams={self.actions_stream: ">"},
                count=10,
                block=block_ms,
            )
            if not entries:
                return outcomes
            for _, msgs in entries:
                for msg_id, fields in msgs:
                    action = json.loads(fields.get("payload", "{}"))
                    outcome = self._execute_vulnerable(action)
                    self.client.xack(self.actions_stream, self.group, msg_id)
                    outcomes.append(outcome)
            return outcomes

        assert self.broker is not None
        messages = self.broker.consume(
            self.actions_stream,
            self.group,
            self.consumer,
            count=10,
            block=block_ms,
        )
        for msg in messages:
            outcome = self._execute_protected(msg)
            self.broker.ack(self.actions_stream, self.group, msg.message_id)
            outcomes.append(outcome)

        return outcomes

    def run_forever(self) -> None:
        print(
            f"[EXECUTOR] Started (mode={self.mode}, in={self.actions_stream})",
            flush=True,
        )
        while True:
            for outcome in self.process_once(block_ms=1000):
                for line in outcome.status_lines:
                    print(line, flush=True)


def main() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    mode = os.getenv("SHIELD_MODE", "protected")
    keyring = KeyRing.from_env(role="executor") if mode == "protected" else None

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    for _ in range(20):
        try:
            client.ping()
            break
        except redis.exceptions.ConnectionError:
            time.sleep(0.5)

    db = MockUserDB(client)
    db.reset()
    worker = ExecutorWorker(client, db, mode=mode, keyring=keyring)
    worker.run_forever()


if __name__ == "__main__":
    main()
