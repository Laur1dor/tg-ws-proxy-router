"""
Routing engine: classify a destination and hand back the ordered exit chain.

Classification (in priority order):
  bot_api : api.telegram.org            -> Bot API endpoint
  calls   : dst IP in call CIDRs        -> reflector / voice traffic
  data    : dst IP in data/DC CIDRs     -> messages, media, files
  other   : everything else             -> pass through directly

The exit chain for a category is the failover order configured in the YAML
"routes" section, resolved to ExitDef objects.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from .config import (proxy_config, ExitDef, CATEGORY_DATA, CATEGORY_CALLS,
                     CATEGORY_BOT_API, CATEGORY_OTHER)
from .utils import build_networks, ip_in_networks

log = logging.getLogger('tg-mtproto-proxy')

_BOT_API_HOSTS = ('api.telegram.org', 'api.telegram.org.')

_data_nets: list = []
_call_nets: list = []


def init_router() -> None:
    """Compile CIDR lists from the current config. Call after load."""
    global _data_nets, _call_nets
    _data_nets = build_networks(proxy_config.data_cidrs)
    _call_nets = build_networks(proxy_config.call_cidrs)
    log.info("router: %d data CIDR(s), %d call CIDR(s)",
             len(_data_nets), len(_call_nets))


def classify(dst: str, port: int) -> str:
    """Return the traffic category for a destination host/IP."""
    host = dst.lower().rstrip('.')
    if host in ('api.telegram.org',):
        return CATEGORY_BOT_API

    # Hostnames we cannot CIDR-match -> treat api.* as bot_api, rest as other.
    if any(host == h.rstrip('.') for h in _BOT_API_HOSTS):
        return CATEGORY_BOT_API

    if ip_in_networks(dst, _call_nets):
        return CATEGORY_CALLS
    if ip_in_networks(dst, _data_nets):
        return CATEGORY_DATA
    return CATEGORY_OTHER


def exit_chain(category: str) -> List[ExitDef]:
    """Resolve the configured exit-name chain for a category to ExitDefs."""
    names = proxy_config.routes.get(category) or proxy_config.routes.get(
        CATEGORY_OTHER, [])
    chain: List[ExitDef] = []
    for name in names:
        ex = proxy_config.exits.get(name)
        if ex is not None:
            chain.append(ex)
    if not chain:
        # Absolute last resort: a synthetic direct exit.
        from .config import EXIT_DIRECT
        chain.append(ExitDef(EXIT_DIRECT, EXIT_DIRECT))
    return chain
