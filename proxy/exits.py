"""
Exit implementations + health tracking.

An exit is a way to leave the proxy toward the real destination:
  * cloudflare_ws : tunnel MTProto data through the Telegram/Cloudflare WS
                    bridge (web.telegram.org fronting, user CF domains, or CF
                    workers). Data category only.
  * direct        : plain TCP from this host.
  * socks5        : connect through an upstream SOCKS5 proxy (e.g. a foreign
                    VPS) so call/reflector traffic exits from a clean network.

The health monitor lets the router skip an upstream exit that is currently
down (the user's VPS may "burp") and fail over to the next exit instantly
instead of waiting for a timeout on every connection.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket as _socket
import struct
import time
from typing import Dict, Optional, Tuple

from .config import proxy_config, ExitDef
from .utils import ws_domains, DC_DEFAULT_IPS, build_networks, ip_in_networks
from .raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts
from .balancer import balancer

log = logging.getLogger('tg-mtproto-proxy')

_st_H = struct.Struct('>H')

# Universal Telegram WS front IP: SNI (kwsN.web.telegram.org) selects the DC,
# so a single reachable front IP works for every DC.
_UNIVERSAL_FRONT_IP = '149.154.167.220'

# Adaptive front skipping: on networks where the Telegram-IP front is blocked
# (RST/EOF even with TLS fragmentation), don't waste a timeout on it for every
# connection — skip it for a cooldown and go straight to the CF-proxied domains.
_FRONT_COOLDOWN = 120.0
_front_fail_until: Dict[int, float] = {}


# ==========================================================================
#  Health tracking
# ==========================================================================
class ExitHealthMonitor:
    def __init__(self):
        self._down_until: Dict[str, float] = {}
        self._tasks = []

    def is_healthy(self, name: str) -> bool:
        until = self._down_until.get(name)
        return until is None or time.monotonic() >= until

    def mark_down(self, name: str, cooldown: float = 30.0) -> None:
        self._down_until[name] = time.monotonic() + cooldown

    def mark_up(self, name: str) -> None:
        self._down_until.pop(name, None)

    async def _probe_loop(self, ex: ExitDef):
        interval = max(5.0, ex.health_interval)
        while True:
            ok = await _tcp_probe(ex.host, ex.port, timeout=5.0)
            if ok:
                if not self.is_healthy(ex.name):
                    log.info("exit '%s' is back up", ex.name)
                self.mark_up(ex.name)
            else:
                if self.is_healthy(ex.name):
                    log.warning("exit '%s' (%s:%d) health check failed",
                                ex.name, ex.host, ex.port)
                self.mark_down(ex.name, cooldown=interval * 2)
            await asyncio.sleep(interval)

    def start(self) -> None:
        for ex in proxy_config.exits.values():
            if ex.type == 'socks5' and ex.health_check and ex.host and ex.port:
                self._tasks.append(asyncio.create_task(self._probe_loop(ex)))
        if self._tasks:
            log.info("started %d exit health probe(s)", len(self._tasks))

    def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()


health = ExitHealthMonitor()


async def _tcp_probe(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


# ==========================================================================
#  Cloudflare WS exit (data only)
# ==========================================================================
async def open_cloudflare_ws(dc: int, is_media: bool,
                             timeout: float = 10.0) -> Optional[RawWebSocket]:
    """Open a WS tunnel to the DC.

    Try the optional Telegram web front, configured Workers, then the public
    CF domain pool. Availability of each path depends on the proxy host's ISP.
    Set skip_front behind a Telegram-redirecting router to avoid self-capture;
    a configured Worker then becomes the first path.
    """
    # 1) web.telegram.org fronting (primary path where Telegram IPs are
    #    reachable). Skipped for a cooldown on networks where it just fails.
    # Skip the Telegram-IP front entirely when skip_front is set, or when TLS
    # fragmentation is on (we're behind DPI: the front IP is dead and dialing it
    # just adds latency and can loop with a router redirect like podkop/NetShift
    # that forwards Telegram IPs back to this proxy). Matches mtproto_inbound.
    if not (proxy_config.skip_front or proxy_config.tls_fragment) and \
            time.monotonic() >= _front_fail_until.get(dc, 0.0):
        domains = ws_domains(dc, is_media)
        front_ips = []
        for ip in (proxy_config.dc_redirects.get(dc), DC_DEFAULT_IPS.get(dc),
                   _UNIVERSAL_FRONT_IP):
            if ip and ip not in front_ips:
                front_ips.append(ip)
        front_timeout = min(timeout, 5.0)
        for front_ip in front_ips:
            for domain in domains:
                try:
                    return await RawWebSocket.connect(front_ip, domain,
                                                      timeout=front_timeout)
                except WsHandshakeError as exc:
                    if exc.is_redirect:
                        continue
                except Exception:
                    pass
        _front_fail_until[dc] = time.monotonic() + _FRONT_COOLDOWN
        log.debug("DC%d front unreachable -> skipping it for %ds",
                  dc, int(_FRONT_COOLDOWN))

    # 2) Cloudflare Worker domains.
    fallback_dst = DC_DEFAULT_IPS.get(dc)
    if fallback_dst and proxy_config.cfproxy_worker_domains:
        from urllib.parse import urlencode
        for worker_domain in proxy_config.cfproxy_worker_domains:
            path = f'/apiws?{urlencode({"dst": fallback_dst, "dc": str(dc)})}'
            try:
                return await RawWebSocket.connect(worker_domain, worker_domain,
                                                  timeout=timeout, path=path)
            except Exception:
                pass

    # 3) Cloudflare-proxied domains (user-supplied or community defaults).
    if proxy_config.fallback_cfproxy:
        for base_domain in balancer.get_domains_for_dc(dc):
            domain = f'kws{dc if dc != 203 else 2}.{base_domain}'
            try:
                ws = await RawWebSocket.connect(domain, domain, timeout=timeout)
                balancer.update_domain_for_dc(dc, base_domain)
                return ws
            except Exception:
                pass

    return None


# ==========================================================================
#  Direct / upstream-SOCKS5 exits  -> (reader, writer)
# ==========================================================================
_tg_nets_cache: Optional[list] = None


def _is_telegram_dst(dst: str) -> bool:
    """True if dst is a Telegram data/reflector IP. Dialing these directly
    from a box behind a router that redirects Telegram IPs back to this proxy
    (podkop/NetShift) forms an infinite loop, so `direct` must refuse them."""
    global _tg_nets_cache
    if _tg_nets_cache is None:
        _tg_nets_cache = build_networks(
            list(proxy_config.data_cidrs) + list(proxy_config.call_cidrs))
    try:
        return ip_in_networks(dst, _tg_nets_cache)
    except Exception:
        return False


async def open_direct(dst: str, port: int,
                      timeout: float = 10.0) -> Optional[Tuple]:
    # Behind a Telegram-redirecting router (tls_fragment/skip_front), a direct
    # dial to a Telegram IP is bounced straight back into this proxy -> loop
    # storm. Refuse it: the connection fails cleanly instead of amplifying.
    if (proxy_config.skip_front or proxy_config.tls_fragment) \
            and _is_telegram_dst(dst):
        log.debug("direct refused for Telegram IP %s:%d (router would loop it)",
                  dst, port)
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(dst, port), timeout=timeout)
        set_sock_opts(writer.transport, proxy_config.buffer_size)
        return reader, writer
    except Exception as exc:
        log.warning("direct connect to %s:%d failed: %s", dst, port, repr(exc))
        return None


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


async def open_socks5(ex: ExitDef, dst: str, port: int,
                      timeout: float = 10.0) -> Optional[Tuple]:
    """CONNECT to dst:port through an upstream SOCKS5 proxy."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ex.host, ex.port), timeout=timeout)
    except Exception as exc:
        log.warning("upstream '%s' (%s:%d) unreachable: %s",
                    ex.name, ex.host, ex.port, repr(exc))
        return None

    try:
        set_sock_opts(writer.transport, proxy_config.buffer_size)

        # Greeting: offer no-auth, and user/pass if creds present.
        if ex.username:
            writer.write(b'\x05\x02\x00\x02')
        else:
            writer.write(b'\x05\x01\x00')
        await writer.drain()

        ver_method = await asyncio.wait_for(reader.readexactly(2),
                                            timeout=timeout)
        if ver_method[0] != 0x05:
            raise ConnectionError("upstream is not SOCKS5")
        method = ver_method[1]

        if method == 0x02:
            if not ex.username:
                raise ConnectionError("upstream requires auth, none configured")
            u = ex.username.encode()
            p = ex.password.encode()
            writer.write(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2),
                                          timeout=timeout)
            if auth[1] != 0x00:
                raise ConnectionError("upstream auth rejected")
        elif method != 0x00:
            raise ConnectionError(f"upstream chose unsupported method {method}")

        # CONNECT request.
        if _is_ipv4(dst):
            addr = b'\x01' + _socket.inet_aton(dst)
        else:
            host_b = dst.encode()
            addr = b'\x03' + bytes([len(host_b)]) + host_b
        writer.write(b'\x05\x01\x00' + addr + _st_H.pack(port))
        await writer.drain()

        rep = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if rep[1] != 0x00:
            raise ConnectionError(f"upstream CONNECT failed (rep={rep[1]})")
        # Drain the bound address in the reply.
        atyp = rep[3]
        if atyp == 0x01:
            await reader.readexactly(4 + 2)
        elif atyp == 0x03:
            dlen = (await reader.readexactly(1))[0]
            await reader.readexactly(dlen + 2)
        elif atyp == 0x04:
            await reader.readexactly(16 + 2)

        return reader, writer
    except Exception as exc:
        log.warning("upstream '%s' CONNECT to %s:%d failed: %s",
                    ex.name, dst, port, repr(exc))
        try:
            writer.close()
        except Exception:
            pass
        return None
