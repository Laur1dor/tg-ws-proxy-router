"""
Raw relays for the SOCKS5 inbound.

Unlike the MTProto-proxy inbound (proxy/bridge.py), the SOCKS5 inbound does
NOT re-encrypt: the Telegram client speaks its native obfuscated MTProto
transport directly to the DC, and we only transport those bytes. For the
Cloudflare WS bridge we still split the stream into individual MTProto packets
so each becomes its own WS frame (reusing bridge.MsgSplitter).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from .stats import stats
from .utils import human_bytes
from .raw_websocket import RawWebSocket
from .bridge import MsgSplitter

log = logging.getLogger('tg-mtproto-proxy')

_CHUNK = 65536


async def raw_ws_bridge(client_reader, client_writer, ws: RawWebSocket,
                        label: str, init_data: bytes,
                        splitter: Optional[MsgSplitter] = None,
                        dc_tag: str = 'DC?') -> None:
    """Bidirectional client TCP <-> Telegram WS, no re-encryption."""
    up_bytes = down_bytes = up_packets = down_packets = 0
    start = asyncio.get_running_loop().time()

    async def tcp_to_ws():
        nonlocal up_bytes, up_packets
        try:
            while True:
                chunk = await client_reader.read(_CHUNK)
                if not chunk:
                    if splitter:
                        for part in splitter.flush():
                            await ws.send(part)
                    break
                up_bytes += len(chunk)
                up_packets += 1
                stats.bytes_up += len(chunk)
                if splitter:
                    parts = splitter.split(chunk)
                    if not parts:
                        continue
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(chunk)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log.debug("[%s] tcp->ws ended: %s", label, exc)

    async def ws_to_tcp():
        nonlocal down_bytes, down_packets
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                down_bytes += len(data)
                down_packets += 1
                stats.bytes_down += len(data)
                client_writer.write(data)
                await client_writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log.debug("[%s] ws->tcp ended: %s", label, exc)

    await ws.send(init_data)
    tasks = [asyncio.create_task(tcp_to_ws()),
             asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_running_loop().time() - start
        log.info("[%s] %s WS closed: ^%s (%d) v%s (%d) in %.1fs",
                 label, dc_tag, human_bytes(up_bytes), up_packets,
                 human_bytes(down_bytes), down_packets, elapsed)
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except BaseException:
            pass


async def raw_tcp_passthrough(client_reader, client_writer,
                              remote_reader, remote_writer,
                              label: str, tag: str = 'direct') -> None:
    """Plain bidirectional byte copy between client and an already-open remote."""
    up_bytes = down_bytes = 0
    start = asyncio.get_running_loop().time()

    async def forward(src, dst_w, is_up):
        nonlocal up_bytes, down_bytes
        try:
            while True:
                data = await src.read(_CHUNK)
                if not data:
                    break
                if is_up:
                    up_bytes += len(data)
                    stats.bytes_up += len(data)
                else:
                    down_bytes += len(data)
                    stats.bytes_down += len(data)
                dst_w.write(data)
                await dst_w.drain()
        except (asyncio.CancelledError, ConnectionError, OSError,
                BrokenPipeError):
            pass

    tasks = [
        asyncio.create_task(forward(client_reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, client_writer, False)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_running_loop().time() - start
        log.info("[%s] %s closed: ^%s v%s in %.1fs", label, tag,
                 human_bytes(up_bytes), human_bytes(down_bytes), elapsed)
        for w in (client_writer, remote_writer):
            try:
                if not w.is_closing():
                    w.close()
                    await w.wait_closed()
            except BaseException:
                pass
