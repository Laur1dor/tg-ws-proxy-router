"""
SOCKS5 inbound.

This is the entry point that carries BOTH data and calls: when Telegram
Desktop is configured to use a SOCKS5 proxy, it routes every connection
(including the voice/video reflector connections) through here, which gives us
the chance to send each category out via its own exit chain.

Note: only the CONNECT command is supported. Telegram Desktop falls back to
TCP-reflector mode for calls whenever a proxy is set, so UDP ASSOCIATE is not
required.
"""
from __future__ import annotations

import asyncio
import logging
import socket as _socket
import struct
from typing import Optional, Tuple

from .config import (proxy_config, ExitDef, EXIT_CLOUDFLARE_WS, EXIT_DIRECT,
                     EXIT_SOCKS5, EXIT_BLOCK, CATEGORY_DATA, CATEGORY_CALLS,
                     CATEGORY_BOT_API, CATEGORY_OTHER)
from .utils import ZERO_64, resolve_dc_from_ip, HANDSHAKE_LEN
from .stats import stats
from .raw_websocket import set_sock_opts
from .relay import raw_ws_bridge, raw_tcp_passthrough
from .bridge import MsgSplitter
from . import router, exits
from ._aes import Cipher, algorithms, modes

log = logging.getLogger('tg-mtproto-proxy')

_st_H = struct.Struct('>H')
_st_Ih = struct.Struct('<Ih')

_PROTO_ABRIDGED = 0xEFEFEFEF
_PROTO_INTERMEDIATE = 0xEEEEEEEE
_PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD
_VALID_PROTOS = frozenset(
    (_PROTO_ABRIDGED, _PROTO_INTERMEDIATE, _PROTO_PADDED_INTERMEDIATE))

# First bytes that mean "this is not native MTProto" (browser TLS / HTTP).
_NON_MTPROTO_FIRST = frozenset((0x16, 0x47, 0x50, 0x48, 0x4F))

_SOCKS5_REPLIES = {
    s: bytes([0x05, s, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    for s in (0x00, 0x01, 0x07, 0x08)
}


def _reply(status: int) -> bytes:
    return _SOCKS5_REPLIES[status]


def _dc_from_init(data: bytes) -> Tuple[Optional[int], bool, Optional[int]]:
    """Extract (dc, is_media, proto) from a native 64-byte MTProto init."""
    try:
        enc = Cipher(algorithms.AES(data[8:40]),
                     modes.CTR(data[40:56])).encryptor()
        ks = enc.update(ZERO_64)
        plain = (int.from_bytes(data[56:64], 'big') ^
                 int.from_bytes(ks[56:64], 'big')).to_bytes(8, 'big')
        proto, dc_raw = _st_Ih.unpack(plain[:6])
        if proto in _VALID_PROTOS:
            dc = abs(dc_raw)
            if 1 <= dc <= 5 or dc == 203:
                return dc, (dc_raw < 0), proto
    except Exception as exc:
        log.debug("DC extraction failed: %s", exc)
    return None, False, None


async def _socks5_negotiate(reader, writer) -> bool:
    """SOCKS5 greeting + optional username/password auth (RFC 1929).

    Returns True if the client may proceed. Replies are written here.
    """
    hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
    if hdr[0] != 0x05:
        return False
    nmethods = hdr[1]
    methods = await reader.readexactly(nmethods) if nmethods else b''

    if proxy_config.socks5_username:
        if 0x02 not in methods:
            writer.write(b'\x05\xff')  # no acceptable methods
            await writer.drain()
            return False
        writer.write(b'\x05\x02')  # user/pass
        await writer.drain()
        ver = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if ver[0] != 0x01:
            return False
        ulen = ver[1]
        user = await reader.readexactly(ulen)
        plen = (await reader.readexactly(1))[0]
        passwd = await reader.readexactly(plen)
        ok = (user.decode('utf-8', 'ignore') == proxy_config.socks5_username
              and passwd.decode('utf-8', 'ignore')
              == proxy_config.socks5_password)
        writer.write(b'\x01\x00' if ok else b'\x01\x01')
        await writer.drain()
        return ok

    # No-auth.
    writer.write(b'\x05\x00')
    await writer.drain()
    return True


async def handle_socks5_client(reader, writer) -> None:
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    set_sock_opts(writer.transport, proxy_config.buffer_size)
    stats.connections_total += 1
    stats.connections_active += 1

    try:
        # 1) Greeting + optional auth
        if not await _socks5_negotiate(reader, writer):
            log.debug("[%s] socks5 negotiation/auth failed", label)
            writer.close()
            return

        # 2) CONNECT request
        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        _ver, cmd, _rsv, atyp = req
        if cmd != 0x01:  # only CONNECT
            writer.write(_reply(0x07))
            await writer.drain()
            writer.close()
            return
        if atyp == 0x01:
            dst = _socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            dlen = (await reader.readexactly(1))[0]
            raw_host = await reader.readexactly(dlen)
            # The 'idna' codec does NOT accept an errors handler ('ignore'
            # raises UnicodeError), and some clients send raw punycode/ASCII.
            # Try IDNA, then fall back to the ASCII form (resolvable as-is).
            try:
                dst = raw_host.decode('idna')
            except Exception:
                dst = raw_host.decode('ascii', 'ignore')
        elif atyp == 0x04:
            await reader.readexactly(16)
            writer.write(_reply(0x08))  # IPv6 unsupported
            await writer.drain()
            writer.close()
            return
        else:
            writer.write(_reply(0x08))
            await writer.drain()
            writer.close()
            return
        port = _st_H.unpack(await reader.readexactly(2))[0]

        # Grant the SOCKS5 request now: Telegram will start sending the
        # MTProto init, which we need to read to learn the DC.
        writer.write(_reply(0x00))
        await writer.drain()

        category = router.classify(dst, port)

        prefix = b''
        dc = is_media = proto = None

        if category == CATEGORY_DATA:
            first = await asyncio.wait_for(reader.read(1), timeout=15)
            if not first:
                writer.close()
                return
            if first[0] in _NON_MTPROTO_FIRST:
                # Browser/TLS/HTTP to a Telegram IP -> just pass it through.
                category = CATEGORY_OTHER
                prefix = first
            else:
                rest = await asyncio.wait_for(
                    reader.readexactly(HANDSHAKE_LEN - 1), timeout=10)
                init = first + rest
                prefix = init
                dc, is_media, proto = _dc_from_init(init)
                if dc is None:
                    dc, is_media = resolve_dc_from_ip(dst)
                    proto = None  # unknown framing -> splitter disabled

        await _serve(category, reader, writer, dst, port, label,
                     prefix, dc, is_media, proto)

    except asyncio.TimeoutError:
        log.debug("[%s] socks5 timeout", label)
    except asyncio.IncompleteReadError:
        log.debug("[%s] socks5 client disconnected", label)
    except Exception as exc:
        log.error("[%s] socks5 unexpected: %s", label, exc, exc_info=True)
    finally:
        stats.connections_active -= 1
        try:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        except BaseException:
            pass


async def _serve(category, reader, writer, dst, port, label,
                 prefix, dc, is_media, proto) -> None:
    chain = router.exit_chain(category)
    dc_tag = f"DC{dc}{'m' if is_media else ''}" if dc else category

    for ex in chain:
        if ex.type == EXIT_SOCKS5 and not exits.health.is_healthy(ex.name):
            log.debug("[%s] skip unhealthy exit '%s'", label, ex.name)
            continue

        if ex.type == EXIT_BLOCK:
            log.info("[%s] %s -> blocked by route", label, category)
            return

        if ex.type == EXIT_CLOUDFLARE_WS:
            if category != CATEGORY_DATA or dc is None:
                continue  # WS bridge only carries MTProto data
            ws = await exits.open_cloudflare_ws(dc, is_media)
            if ws is None:
                log.warning("[%s] %s exit '%s' (CF-WS) failed -> next",
                            label, dc_tag, ex.name)
                continue
            splitter = None
            if proto is not None:
                try:
                    splitter = MsgSplitter(prefix, proto)
                except Exception:
                    splitter = None
            stats.connections_ws += 1
            log.info("[%s] %s (%s:%d) -> exit '%s' (CF-WS)",
                     label, dc_tag, dst, port, ex.name)
            await raw_ws_bridge(reader, writer, ws, label, prefix,
                                splitter=splitter, dc_tag=dc_tag)
            return

        if ex.type == EXIT_DIRECT:
            remote = await exits.open_direct(dst, port)
            if remote is None:
                continue
            rr, rw = remote
            if prefix:
                rw.write(prefix)
                await rw.drain()
            stats.connections_tcp_fallback += 1
            log.info("[%s] %s (%s:%d) -> exit '%s' (direct)",
                     label, category, dst, port, ex.name)
            await raw_tcp_passthrough(reader, writer, rr, rw, label,
                                      tag=f"direct->{dst}:{port}")
            return

        if ex.type == EXIT_SOCKS5:
            remote = await exits.open_socks5(ex, dst, port)
            if remote is None:
                exits.health.mark_down(ex.name)
                continue
            rr, rw = remote
            if prefix:
                rw.write(prefix)
                await rw.drain()
            stats.connections_cfproxy += 1
            log.info("[%s] %s (%s:%d) -> exit '%s' (upstream %s:%d)",
                     label, category, dst, port, ex.name, ex.host, ex.port)
            await raw_tcp_passthrough(reader, writer, rr, rw, label,
                                      tag=f"{ex.name}->{dst}:{port}")
            return

    log.warning("[%s] %s (%s:%d): no working exit in chain",
                label, category, dst, port)
