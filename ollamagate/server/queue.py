"""A priority gate in front of Ollama.

At most ``capacity`` requests are forwarded at once. Waiting requests are
admitted in priority order (high, normal, low), first come first served
within a priority. A waiter that gives up (client gone, device suspended) is
simply cancelled and never takes a slot.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
from contextlib import asynccontextmanager
from typing import AsyncIterator

PRIORITY_RANK = {"high": 0, "normal": 1, "low": 2}


class Ticket:
    """Records whether a slot was granted, so the holder can always release it -
    even if it was cancelled in the instant between the grant and resuming."""

    held = False


class PriorityGate:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.active = 0
        self._waiters: list[tuple[int, int, asyncio.Future[None], Ticket]] = []
        self._order = itertools.count()

    @property
    def queued(self) -> int:
        return len(self._waiters)

    async def acquire(self, priority: str, ticket: Ticket | None = None) -> None:
        ticket = ticket or Ticket()
        if self.active < self.capacity and not self._waiters:
            self.active += 1
            ticket.held = True
            return
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        entry = (PRIORITY_RANK.get(priority, 1), next(self._order), fut, ticket)
        heapq.heappush(self._waiters, entry)
        try:
            await fut
        except asyncio.CancelledError:
            if entry in self._waiters:  # still waiting: just leave the queue
                self._waiters.remove(entry)
                heapq.heapify(self._waiters)
            raise

    def release(self, ticket: Ticket | None = None) -> None:
        if ticket is not None:
            if not ticket.held:
                return
            ticket.held = False
        self.active -= 1
        self._wake()

    def _wake(self) -> None:
        while self._waiters and self.active < self.capacity:
            *_, fut, ticket = heapq.heappop(self._waiters)
            if fut.done():
                # Cancelled, but its task hasn't run its cleanup yet: skip it
                # (set_result would raise and strand everyone queued behind it).
                continue
            self.active += 1
            ticket.held = True  # the waiter now owns a slot, even if it gets cancelled
            fut.set_result(None)

    @asynccontextmanager
    async def slot(self, priority: str) -> AsyncIterator[None]:
        ticket = Ticket()
        try:
            await self.acquire(priority, ticket)
            yield
        finally:
            self.release(ticket)
