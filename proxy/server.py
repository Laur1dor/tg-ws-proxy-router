"""
Entry point: loads the YAML "menu", starts the SOCKS5 and/or MTProto inbounds,
the exit health monitor, the CF-proxy domain refresher and the WS pools.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket as _socket
import sys

from .config import (proxy_config, load_yaml_config,
                     start_cfproxy_domain_refresh)
from .balancer import balancer
from .utils import get_link_host
from .stats import stats
from .pool import ws_pool, cf_worker_pool
from . import router, exits
from .socks5_inbound import handle_socks5_client
from .mtproto_inbound import handle_mtproto_client

log = logging.getLogger('tg-mtproto-proxy')

# Keep strong references to in-flight client tasks so the GC does not destroy
# them mid-connection ("Task was destroyed but it is pending").
_client_tasks: set = set()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter('%(asctime)s  %(levelname)-5s  %(message)s',
                            datefmt='%H:%M:%S')
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        root.addHandler(console)
    logging.getLogger('asyncio').setLevel(logging.WARNING)


def mtproto_link(listener, link_host: str | None = None) -> str:
    """Build the tg://proxy link for an MTProto listener."""
    host = link_host or get_link_host(listener.host)
    if listener.fake_tls_domain:
        domain_hex = listener.fake_tls_domain.encode('ascii').hex()
        return (f"tg://proxy?server={host}&port={listener.port}"
                f"&secret=ee{listener.secret}{domain_hex}")
    return (f"tg://proxy?server={host}&port={listener.port}"
            f"&secret=dd{listener.secret}")


def _print_banner() -> None:
    log.info("=" * 64)
    log.info("  TG WS/SOCKS5 Proxy  (data via Cloudflare-WS, calls routable)")
    log.info("-" * 64)
    if proxy_config.socks5_enabled:
        auth = (f"  auth {proxy_config.socks5_username}:***"
                if proxy_config.socks5_username else "  no auth")
        log.info("  SOCKS5 inbound : %s:%d  (data AND calls)%s",
                 proxy_config.socks5_host, proxy_config.socks5_port, auth)
    for lst in proxy_config.mtproto_listeners:
        if not lst.enabled:
            continue
        kind = f"Fake TLS [{lst.fake_tls_domain}]" if lst.fake_tls_domain \
            else "plain"
        log.info("  MTProto inbound: %s:%d  (%s, data only)",
                 lst.host, lst.port, kind)
        log.info("    %s", mtproto_link(lst))
    log.info("-" * 64)
    log.info("  Routes:")
    for cat in ('data', 'calls', 'bot_api', 'other'):
        chain = proxy_config.routes.get(cat, [])
        log.info("    %-8s -> %s", cat, ' -> '.join(chain) or '(none)')
    log.info("  Exits:")
    for name, ex in proxy_config.exits.items():
        if ex.type == 'socks5':
            log.info("    %-10s : socks5 %s:%d%s", name, ex.host, ex.port,
                     ' (health-checked)' if ex.health_check else '')
        else:
            log.info("    %-10s : %s", name, ex.type)
    log.info("  TLS fragment   : %s",
             "ON (ClientHello split @ SNI, DPI evasion)"
             if proxy_config.tls_fragment else "off")
    log.info("=" * 64)


async def _serve_forever(stop_event: asyncio.Event) -> None:
    router.init_router()

    if proxy_config.fallback_cfproxy:
        if proxy_config.cfproxy_user_domains:
            balancer.update_domains_list(proxy_config.cfproxy_user_domains)
        else:
            start_cfproxy_domain_refresh()

    exits.health.start()

    servers = []

    if proxy_config.socks5_enabled:
        s = await asyncio.start_server(
            handle_socks5_client,
            proxy_config.socks5_host, proxy_config.socks5_port)
        servers.append(s)

    for lst in proxy_config.mtproto_listeners:
        if not lst.enabled:
            continue
        if not lst.secret:
            lst.secret = os.urandom(16).hex()
            log.info("generated secret for MTProto listener '%s'", lst.name)
        secret_bytes = bytes.fromhex(lst.secret)

        def mt_cb(r, w, sb=secret_bytes, ftls=lst.fake_tls_domain):
            t = asyncio.create_task(handle_mtproto_client(r, w, sb, ftls))
            _client_tasks.add(t)
            t.add_done_callback(_client_tasks.discard)

        try:
            s = await asyncio.start_server(mt_cb, lst.host, lst.port)
        except OSError as exc:
            log.error("MTProto listener '%s' on %s:%d failed to bind: %s",
                      lst.name, lst.host, lst.port, exc)
            continue
        servers.append(s)

    if not servers:
        log.error("No inbound enabled (listen.socks5 and listen.mtproto both "
                  "disabled). Nothing to do.")
        return

    for server in servers:
        for sock in server.sockets:
            try:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass

    _print_banner()

    # When fragmentation is on the Telegram-IP front is unused, so don't waste
    # background connects (and avoid podkop loops) prewarming it.
    if not proxy_config.tls_fragment:
        await ws_pool.warmup()
    await cf_worker_pool.warmup()

    async def log_stats():
        try:
            while True:
                await asyncio.sleep(60)
                log.info("stats: %s", stats.summary())
        except asyncio.CancelledError:
            raise

    stats_task = asyncio.create_task(log_stats())

    serve_tasks = [asyncio.create_task(s.serve_forever()) for s in servers]
    stop_task = asyncio.create_task(stop_event.wait())
    try:
        await asyncio.wait([stop_task, *serve_tasks],
                           return_when=asyncio.FIRST_COMPLETED)
    finally:
        stats_task.cancel()
        exits.health.stop()
        for t in serve_tasks:
            t.cancel()
        for server in servers:
            server.close()
        for server in servers:
            try:
                await server.wait_closed()
            except BaseException:
                pass


def run(config_path: str | None = None,
        stop_event: asyncio.Event | None = None) -> None:
    async def _main():
        ev = stop_event or asyncio.Event()
        await _serve_forever(ev)

    asyncio.run(_main())


def main() -> None:
    ap = argparse.ArgumentParser(
        description='Telegram WS/SOCKS5 proxy with routing')
    ap.add_argument('-c', '--config', default=os.environ.get(
        'TGWS_CONFIG', 'config.yml'),
        help='Path to YAML config (default: config.yml or $TGWS_CONFIG)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Debug logging')
    args = ap.parse_args()

    if os.path.isfile(args.config):
        try:
            load_yaml_config(args.config)
        except Exception as exc:
            print(f"Failed to load config {args.config!r}: {exc}",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Config {args.config!r} not found; using built-in defaults "
              f"(SOCKS5 + MTProto, data->CF-WS, calls->direct).",
              file=sys.stderr)
        proxy_config.ensure_routing_defaults()

    verbose = args.verbose or proxy_config.verbose
    _setup_logging(verbose)

    problems = proxy_config.validate_routing()
    for p in problems:
        log.warning("config: %s", p)

    try:
        run(args.config)
    except KeyboardInterrupt:
        log.info("Shutting down. Final stats: %s", stats.summary())


if __name__ == '__main__':
    if __package__ in (None, ''):
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _root not in sys.path:
            sys.path.insert(0, _root)
        __package__ = 'proxy'
    main()
