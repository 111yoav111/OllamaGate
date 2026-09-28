"""A priority gate in front of Ollama.

At most ``capacity`` requests are forwarded at once. Waiting requests are
admitted in priority order (high, normal, low), first come first served
within a priority. A waiter that gives up (client gone, device kicked) is
simply cancelled and never takes a slot.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
from contextlib import asynccontextmanager
from typing import AsyncIterator

PRIORITY_RANK = {"high": 0, "normal": 1, "low": 2}


class PriorityGate:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.active = 0
        self._waiters: list[tuple[int, int, asyncio.Future[None]]] = []
        self._order = itertools.count()

    @property
    def queued(self) -> int:
        return sum(1 for *_, fut in self._waiters if not fut.done())

    async def acquire(self, priority: str) -> None:
        if self.active < self.capacity and not self.queued:
            self.active += 1
            return
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        heapq.heappush(self._waiters, (PRIORITY_RANK.get(priority, 1), next(self._order), fut))
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                # We were handed a slot just as we were cancelled: pass it on.
                self.active -= 1
                self._wake()
            raise

    def release(self) -> None:
        self.active -= 1
        self._wake()

    def _wake(self) -> None:
        while self._waiters and self.active < self.capacity:
            *_, fut = heapq.heappop(self._waiters)
            if not fut.done():
                self.active += 1
                fut.set_result(None)

    @asynccontextmanager
    async def slot(self, priority: str) -> AsyncIterator[None]:
        await self.acquire(priority)
        try:
            yield
        finally:
            self.release()
