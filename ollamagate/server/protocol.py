"""Connection-level guards on top of uvicorn's h11 protocol.

uvicorn has no deadline for receiving request headers and no per-IP
connection cap, so a slowloris client could hold thousands of half-open
sockets without ever sending a token. This subclass adds both. It relies on
a few uvicorn internals (``cycle``, ``client``, ``loop``); the tests exercise
them so an incompatible uvicorn upgrade fails loudly.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Sequence

from uvicorn.protocols.http.h11_impl import H11Protocol

from .netutil import IPNetwork, is_trusted
from .tls import peer_cert_fingerprint

# Scope key carrying the SHA-256 of the verified client certificate (mTLS).
# Set here from the TLS connection itself, so no request header can forge it.
CLIENT_CERT_SCOPE = "ollamagate.client_cert"


def make_guarded_protocol(
    *, header_timeout: float, max_connections_per_ip: int, trusted: Sequence[IPNetwork]
) -> type[H11Protocol]:
    per_ip: Counter[str] = Counter()

    class GuardedH11Protocol(H11Protocol):
        _counted_ip: str | None = None
        _header_timer: asyncio.TimerHandle | None = None

        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            super().connection_made(transport)
            ip = self.client[0] if self.client else None
            # Behind a tunnel every connection comes from the proxy; don't cap it.
            if ip is not None and not is_trusted(ip, trusted):
                if per_ip[ip] >= max_connections_per_ip:
                    transport.close()
                    return
                per_ip[ip] += 1
                self._counted_ip = ip
            self._arm_header_timer()
            cert_fp = peer_cert_fingerprint(transport.get_extra_info("ssl_object"))
            if cert_fp is not None:
                app = self.app

                async def with_client_cert(scope, receive, send):  # type: ignore[no-untyped-def]
                    scope[CLIENT_CERT_SCOPE] = cert_fp
                    await app(scope, receive, send)

                self.app = with_client_cert

        def connection_lost(self, exc: Exception | None) -> None:
            if self._header_timer is not None:
                self._header_timer.cancel()
                self._header_timer = None
            if self._counted_ip is not None:
                per_ip[self._counted_ip] -= 1
                if per_ip[self._counted_ip] <= 0:
                    del per_ip[self._counted_ip]
                self._counted_ip = None
            super().connection_lost(exc)

        def on_response_complete(self) -> None:
            super().on_response_complete()
            self._arm_header_timer()  # the next request's headers get a fresh deadline

        def _arm_header_timer(self) -> None:
            if self._header_timer is not None:
                self._header_timer.cancel()
            self._header_timer = self.loop.call_later(header_timeout, self._on_header_timeout)

        def _on_header_timeout(self) -> None:
            self._header_timer = None
            request_in_progress = self.cycle is not None and not self.cycle.response_complete
            if not request_in_progress and not self.transport.is_closing():
                self.transport.close()

    return GuardedH11Protocol

