"""Redis-backed mock database shared by demo workers and test harnesses."""

from __future__ import annotations

import json
import time
from typing import Any

import redis


class MockUserDB:
    """Minimal user/role store persisted in Redis for cross-container demo visibility."""

    def __init__(self, client: redis.Redis, namespace: str = "demo") -> None:
        self.client = client
        self.users_key = f"mock_db:{namespace}:users"
        self.writes_key = f"mock_db:{namespace}:role_writes"
        self.replies_key = f"mock_db:{namespace}:replies"

    def reset(self) -> None:
        """Reset mock database to initial least-privilege state."""
        pipe = self.client.pipeline()
        pipe.delete(self.users_key, self.writes_key, self.replies_key)
        pipe.hset(
            self.users_key,
            mapping={
                "guest_01": "guest",
                "alice": "support_agent",
                "root_admin": "admin",
            },
        )
        pipe.set(self.writes_key, 0)
        pipe.execute()

    def get_role(self, user_id: str) -> str | None:
        val = self.client.hget(self.users_key, user_id)
        if isinstance(val, bytes):
            return val.decode("utf-8")
        return val

    def get_all_users(self) -> dict[str, str]:
        raw = self.client.hgetall(self.users_key)
        return {
            (k.decode() if isinstance(k, bytes) else str(k)): (
                v.decode() if isinstance(v, bytes) else str(v)
            )
            for k, v in raw.items()
        }

    def update_role(self, user_id: str, new_role: str) -> dict[str, Any]:
        previous_role = self.get_role(user_id)
        pipe = self.client.pipeline()
        pipe.hset(self.users_key, user_id, new_role)
        pipe.incr(self.writes_key)
        _, write_count = pipe.execute()
        return {
            "user_id": user_id,
            "previous_role": previous_role,
            "new_role": new_role,
            "write_count": int(write_count),
        }

    def record_reply(self, ticket_id: str, user_id: str, message: str) -> dict[str, Any]:
        entry = {
            "ticket_id": ticket_id,
            "user_id": user_id,
            "message": message,
            "ts": time.time(),
        }
        self.client.rpush(self.replies_key, json.dumps(entry))
        return entry

    def role_write_count(self) -> int:
        val = self.client.get(self.writes_key)
        return int(val) if val is not None else 0

    def reply_count(self) -> int:
        return int(self.client.llen(self.replies_key))
