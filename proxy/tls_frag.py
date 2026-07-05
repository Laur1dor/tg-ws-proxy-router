"""
DPI evasion via TLS ClientHello fragmentation.

Telegram's WS front (kwsN.web.telegram.org @ 149.154.167.220) is reachable, but
many ISPs (e.g. in RU) inject a TCP RST when they see the SNI hostname in the
ClientHello. We defeat that the same way zapret/GoodbyeDPI do: drive the TLS
handshake manually over a memory BIO and write the ClientHello split across two
TCP segments right inside the SNI hostname. Each segment alone no longer
contains the full "...telegram.org" string, so the DPI string match misses,
while the server reassembles the segments normally.

This module is standalone (no imports from raw_websocket) to avoid an import
cycle; raw_websocket calls open_tls_fragmented() when proxy_config.tls_fragment
is enabled.
"""
from __future__ import annotations

import asyncio
import socket as _socket
import ssl
from typing import Optional, Tuple

_READ = 65536


def _split_at_sni(data: bytes, domain: str) -> Tuple[bytes, bytes]:
    """Split the ClientHello so the SNI hostname is cut across two segments."""
    host = domain.encode('ascii', 'ignore')
    cut = -1
    if len(host) >= 4:
        idx = data.find(host)
        if idx != -1:
            cut = idx + len(host) // 2
    if cut <= 0 or cut >= len(data):
        cut = min(max(1, len(data) // 2), 64)
    return data[:cut], data[cut:]


class FragTlsStream:
    """Reader+writer adapter around a manually-driven TLS connection.

    Exposes the subset of StreamReader/StreamWriter used by RawWebSocket, so a
    single instance is passed as both `reader` and `writer`.
    """

    def __init__(self, reader, writer, sslobj, incoming, outgoing,
                 domain: str, fragment: bool):
        self._reader = reader
        self._writer = writer
        self._ssl = sslobj
        self._in = incoming
        self._out = outgoing
        self._domain = domain
        self._fragment = fragment
        self._buf = bytearray()
        self._eof = False

    # ---- handshake ----
    async def _send_outgoing(self, frag: bool):
        out = self._out.read()
        if not out:
            return
        if frag and self._fragment:
            a, b = _split_at_sni(out, self._domain)
            self._writer.write(a)
            await self._writer.drain()
            self._writer.write(b)
            await self._writer.drain()
        else:
            self._writer.write(out)
            await self._writer.drain()

    async def _feed_incoming(self) -> bool:
        data = await self._reader.read(_READ)
        if not data:
            return False
        self._in.write(data)
        return True

    async def do_handshake(self):
        first = True
        while True:
            try:
                self._ssl.do_handshake()
                await self._send_outgoing(first)
                return
            except ssl.SSLWantReadError:
                await self._send_outgoing(first)
                first = False
                if not await self._feed_incoming():
                    raise ConnectionError("EOF during TLS handshake")
            except ssl.SSLWantWriteError:
                await self._send_outgoing(first)
                first = False

    # ---- app data: write ----
    def write(self, data: bytes) -> None:
        mv = memoryview(bytes(data))
        off = 0
        while off < len(mv):
            try:
                off += self._ssl.write(mv[off:])
            except ssl.SSLWantReadError:
                break
        out = self._out.read()
        if out:
            self._writer.write(out)

    async def drain(self) -> None:
        await self._writer.drain()

    # ---- app data: read ----
    async def _fill(self) -> bool:
        while True:
            try:
                chunk = self._ssl.read(_READ)
                if not chunk:
                    self._eof = True
                    return False
                self._buf.extend(chunk)
                return True
            except ssl.SSLWantReadError:
                if not await self._feed_incoming():
                    self._eof = True
                    return False
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                self._eof = True
                return False

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            if not await self._fill():
                raise asyncio.IncompleteReadError(bytes(self._buf), n)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read(self, n: int = _READ) -> bytes:
        if not self._buf and not self._eof:
            if not await self._fill():
                return b''
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def readline(self) -> bytes:
        while b'\n' not in self._buf:
            if not await self._fill():
                break
        idx = self._buf.find(b'\n')
        if idx == -1:
            out = bytes(self._buf)
            self._buf.clear()
            return out
        out = bytes(self._buf[:idx + 1])
        del self._buf[:idx + 1]
        return out

    # ---- lifecycle / passthrough ----
    def close(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass

    async def wait_closed(self) -> None:
        try:
            await self._writer.wait_closed()
        except Exception:
            pass

    def is_closing(self) -> bool:
        return self._writer.is_closing()

    def get_extra_info(self, name, default=None):
        return self._writer.get_extra_info(name, default)

    @property
    def transport(self):
        return self._writer.transport


async def open_tls_fragmented(host: str, port: int, server_hostname: str,
                              ctx: ssl.SSLContext, timeout: float,
                              buffer_size: int,
                              fragment: bool = True) -> FragTlsStream:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=min(timeout, 10))

    sock = writer.transport.get_extra_info('socket')
    if sock is not None:
        try:
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
        except OSError:
            pass

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)

    stream = FragTlsStream(reader, writer, sslobj, incoming, outgoing,
                           server_hostname, fragment)
    try:
        await asyncio.wait_for(stream.do_handshake(), timeout=timeout)
    except Exception:
        stream.close()
        raise
    return stream
