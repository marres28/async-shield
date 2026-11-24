"""Shared core types and exceptions for Async-Shield."""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class IntegrityLevel(str, Enum):
    """Ordered Biba integrity levels for pipeline data provenance."""

    LOW = "low"        # Untrusted external data: tickets, webhooks, user prompts
    MEDIUM = "medium"  # Enriched/parsed by internal services (non-authoritative)
    HIGH = "high"      # Authoritative data: verified admin SSO, signed internal commands

    @property
    def rank(self) -> int:
        return _INTEGRITY_RANK[self]

    def satisfies(self, required: IntegrityLevel) -> bool:
        """Return True iff this integrity level is at least ``required``."""
        return self.rank >= required.rank

    def __lt__(self, other: object) -> bool:
        if isinstance(other, IntegrityLevel):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, IntegrityLevel):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, IntegrityLevel):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, IntegrityLevel):
            return self.rank >= other.rank
        return NotImplemented

    @classmethod
    def meet(cls, levels: Iterable[IntegrityLevel]) -> IntegrityLevel:
        """Lattice meet (greatest lower bound): lowest integrity dominates."""
        collected = list(levels)
        if not collected:
            return cls.LOW
        return min(collected, key=lambda lvl: lvl.rank)


_INTEGRITY_RANK: dict[IntegrityLevel, int] = {
    IntegrityLevel.LOW: 0,
    IntegrityLevel.MEDIUM: 1,
    IntegrityLevel.HIGH: 2,
}
