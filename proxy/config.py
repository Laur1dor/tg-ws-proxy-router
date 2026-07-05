import logging
import os
import string
import random
import socket as _socket
import threading

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.request import Request

from .balancer import balancer
from .utils import build_github_opener, DEFAULT_DATA_CIDRS, DEFAULT_CALL_CIDRS

log = logging.getLogger('tg-mtproto-proxy')

CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main"
    "/.github/cfproxy-domains.txt"
)

_CFPROXY_ENC: List[str] = [
    'virkgj.com',
    'vmmzovy.com',
    'mkuosckvso.com',
    'zaewayzmplad.com',
    'twdmbzcm.com',
    'awzwsldi.com',
    'clngqrflngqin.com',
    'tjacxbqtj.com',
    'bxaxtxmrw.com',
    'dmohrsgmohcrwb.com',
    'vwbmtmoi.com',
    'khgrre.com',
    'ulihssf.com',
    'tmhqsdqmfpmk.com',
    'xwuwoqbm.com'
]
_S = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _dd(s: str) -> str:
    """Only for decoding CF proxy domains"""
    if not s[-4:] == '.com':
        return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 + (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S


CFPROXY_DEFAULT_DOMAINS: List[str] = [_dd(d) for d in _CFPROXY_ENC]
_CFPROXY_MIN_VALID_DOMAINS = 3


# ==========================================================================
#  Routing model (the "menu")
# ==========================================================================
#
# An *exit* is a named way to leave the proxy: the Cloudflare WS bridge, a
# direct TCP connection, or an upstream SOCKS5 proxy (e.g. a foreign VPS).
# A *route* maps a traffic category -> an ordered list of exit names that are
# tried in turn (failover). Categories: data, calls, bot_api, other.

EXIT_CLOUDFLARE_WS = 'cloudflare_ws'
EXIT_DIRECT = 'direct'
EXIT_SOCKS5 = 'socks5'
EXIT_BLOCK = 'block'

VALID_EXIT_TYPES = frozenset(
    (EXIT_CLOUDFLARE_WS, EXIT_DIRECT, EXIT_SOCKS5, EXIT_BLOCK))

CATEGORY_DATA = 'data'
CATEGORY_CALLS = 'calls'
CATEGORY_BOT_API = 'bot_api'
CATEGORY_OTHER = 'other'

VALID_CATEGORIES = (CATEGORY_DATA, CATEGORY_CALLS, CATEGORY_BOT_API,
                    CATEGORY_OTHER)


@dataclass
class ExitDef:
    name: str
    type: str  # one of VALID_EXIT_TYPES
    host: str = ''
    port: int = 0
    username: str = ''
    password: str = ''
    health_check: bool = True
    health_interval: float = 30.0


@dataclass
class MtprotoListener:
    """One MTProto inbound. The proxy can run several at once (e.g. a plain
    one and a Fake-TLS one on separate ports)."""
    name: str = 'mtproto'
    enabled: bool = True
    host: str = '0.0.0.0'
    port: int = 1443
    secret: str = ''            # 32 hex chars; '' -> generated at start
    fake_tls_domain: str = ''   # '' -> plain (dd link); set -> Fake TLS (ee)
    proxy_protocol: bool = False


@dataclass
class ProxyConfig:
    # --- MTProto inbounds (classic tg://proxy link, plain and/or Fake TLS) ---
    mtproto_listeners: List[MtprotoListener] = field(default_factory=list)
    proxy_protocol: bool = False

    # Legacy/shared defaults (kept for back-compat; not the source of truth).
    port: int = 1443
    host: str = '0.0.0.0'
    secret: str = field(default_factory=lambda: os.urandom(16).hex())
    fake_tls_domain: str = ''
    mtproto_enabled: bool = True

    # --- SOCKS5 inbound (carries data AND calls) ---
    socks5_enabled: bool = True
    socks5_host: str = '0.0.0.0'
    socks5_port: int = 1080
    socks5_username: str = ''
    socks5_password: str = ''

    # --- WS bridge tuning (shared) ---
    dc_redirects: Dict[int, str] = field(
        default_factory=lambda: {2: '149.154.167.220', 4: '149.154.167.220'})
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    fallback_cfproxy: bool = True
    cfproxy_user_domains: List[str] = field(default_factory=list)
    cfproxy_worker_domains: List[str] = field(default_factory=list)
    # Never dial the Telegram-IP web front (149.154.167.220 / DC IPs); go
    # straight to the Cloudflare-proxied domains. Required on boxes behind a
    # router whose Telegram redirect (podkop/NetShift -> this proxy) would
    # otherwise catch the proxy's own front egress and loop it back.
    skip_front: bool = False

    # --- Routing (the menu) ---
    exits: Dict[str, ExitDef] = field(default_factory=dict)
    routes: Dict[str, List[str]] = field(default_factory=dict)
    data_cidrs: List[str] = field(
        default_factory=lambda: list(DEFAULT_DATA_CIDRS))
    call_cidrs: List[str] = field(
        default_factory=lambda: list(DEFAULT_CALL_CIDRS))
    bot_api_ip: str = '149.154.167.220'

    # DPI evasion: split the upstream TLS ClientHello at the SNI so a DPI that
    # RSTs on the Telegram hostname can't match it. Lets the tool reach
    # Telegram on its own, without relying on zapret/podkop on the router.
    tls_fragment: bool = False

    verbose: bool = False

    def default_exits(self) -> Dict[str, ExitDef]:
        return {
            EXIT_CLOUDFLARE_WS: ExitDef(EXIT_CLOUDFLARE_WS, EXIT_CLOUDFLARE_WS),
            EXIT_DIRECT: ExitDef(EXIT_DIRECT, EXIT_DIRECT),
        }

    def default_routes(self) -> Dict[str, List[str]]:
        return {
            CATEGORY_DATA: [EXIT_CLOUDFLARE_WS, EXIT_DIRECT],
            CATEGORY_CALLS: [EXIT_DIRECT],
            CATEGORY_BOT_API: [EXIT_DIRECT],
            CATEGORY_OTHER: [EXIT_DIRECT],
        }

    def default_mtproto_listeners(self) -> List[MtprotoListener]:
        return [
            MtprotoListener(name='mtproto', enabled=True, host='0.0.0.0',
                            port=1443, secret='', fake_tls_domain=''),
            MtprotoListener(name='mtproto_faketls', enabled=True,
                            host='0.0.0.0', port=1444, secret='',
                            fake_tls_domain='www.cloudflare.com'),
        ]

    def ensure_routing_defaults(self) -> None:
        """Fill in exits/routes/listeners if the config left them empty."""
        if not self.exits:
            self.exits = self.default_exits()
        if not self.routes:
            self.routes = self.default_routes()
        # Guarantee a 'direct' exit always exists as a last resort.
        if EXIT_DIRECT not in self.exits:
            self.exits[EXIT_DIRECT] = ExitDef(EXIT_DIRECT, EXIT_DIRECT)
        for cat in VALID_CATEGORIES:
            self.routes.setdefault(cat, [EXIT_DIRECT])
        if not self.mtproto_listeners:
            self.mtproto_listeners = self.default_mtproto_listeners()

    def validate_routing(self) -> List[str]:
        """Return a list of human-readable problems with the routing config."""
        problems: List[str] = []
        for name, ex in self.exits.items():
            if ex.type not in VALID_EXIT_TYPES:
                problems.append(
                    f"exit '{name}': unknown type '{ex.type}' "
                    f"(expected one of {sorted(VALID_EXIT_TYPES)})")
            if ex.type == EXIT_SOCKS5 and (not ex.host or not ex.port):
                problems.append(
                    f"exit '{name}': socks5 exit needs host and port")
        for cat, chain in self.routes.items():
            if cat not in VALID_CATEGORIES:
                problems.append(
                    f"route '{cat}': unknown category "
                    f"(expected one of {list(VALID_CATEGORIES)})")
            for exit_name in chain:
                if exit_name not in self.exits:
                    problems.append(
                        f"route '{cat}': references undefined exit "
                        f"'{exit_name}'")
        return problems


proxy_config = ProxyConfig()


def coerce_domain_list(value) -> List[str]:
    if isinstance(value, str):
        items = value.replace(',', ' ').replace(';', ' ').split()
    elif isinstance(value, (list, tuple)):
        items: List[str] = []
        for entry in value:
            if isinstance(entry, str):
                items.extend(entry.replace(',', ' ').replace(';', ' ').split())
    else:
        return []
    seen = set()
    result: List[str] = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


# ==========================================================================
#  YAML config loading (the "menu" file)
# ==========================================================================

def _parse_exits(raw: dict) -> Dict[str, ExitDef]:
    exits: Dict[str, ExitDef] = {}
    if not isinstance(raw, dict):
        return exits
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            continue
        exits[str(name)] = ExitDef(
            name=str(name),
            type=str(spec.get('type', EXIT_DIRECT)),
            host=str(spec.get('host', '') or ''),
            port=int(spec.get('port', 0) or 0),
            username=str(spec.get('username', '') or ''),
            password=str(spec.get('password', '') or ''),
            health_check=bool(spec.get('health_check', True)),
            health_interval=float(spec.get('health_interval', 30.0) or 30.0),
        )
    return exits


def _parse_routes(raw: dict) -> Dict[str, List[str]]:
    routes: Dict[str, List[str]] = {}
    if not isinstance(raw, dict):
        return routes
    for cat, chain in raw.items():
        if isinstance(chain, str):
            chain = [chain]
        if isinstance(chain, (list, tuple)):
            routes[str(cat)] = [str(x) for x in chain]
    return routes


def _parse_mtproto_listener(name: str, spec, default_port: int,
                            default_ftls: str) -> Optional['MtprotoListener']:
    if not isinstance(spec, dict):
        return None
    secret = str(spec.get('secret', '') or '').strip()
    if secret:
        if len(secret) != 32:
            raise ValueError(f"listen.{name}.secret must be 32 hex chars")
        bytes.fromhex(secret)  # validate
    return MtprotoListener(
        name=name,
        enabled=bool(spec.get('enabled', True)),
        host=str(spec.get('host', '0.0.0.0')),
        port=int(spec.get('port', default_port)),
        secret=secret,
        fake_tls_domain=str(
            spec.get('fake_tls_domain', default_ftls) or '').strip(),
        proxy_protocol=bool(spec.get('proxy_protocol', False)),
    )


def load_yaml_config(path: str) -> None:
    """Load the YAML 'menu' into the global proxy_config. Raises on bad YAML."""
    import yaml  # local import: only needed when a config file is used

    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}

    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")

    listen = data.get('listen', {}) or {}
    socks5 = listen.get('socks5', {}) or {}

    proxy_config.socks5_enabled = bool(socks5.get('enabled', True))
    proxy_config.socks5_host = str(socks5.get('host', '0.0.0.0'))
    proxy_config.socks5_port = int(socks5.get('port', 1080))
    proxy_config.socks5_username = str(socks5.get('username', '') or '')
    proxy_config.socks5_password = str(socks5.get('password', '') or '')

    # Two MTProto inbounds: plain (dd) and Fake TLS (ee), each on its own port.
    listeners: List[MtprotoListener] = []
    plain = _parse_mtproto_listener('mtproto', listen.get('mtproto'), 1443, '')
    if plain is not None:
        plain.fake_tls_domain = ''  # plain listener never uses Fake TLS
        listeners.append(plain)
    ftls = _parse_mtproto_listener('mtproto_faketls',
                                   listen.get('mtproto_faketls'), 1444,
                                   'www.cloudflare.com')
    if ftls is not None:
        listeners.append(ftls)
    if listeners:
        proxy_config.mtproto_listeners = listeners
    proxy_config.proxy_protocol = bool(
        (listen.get('mtproto') or {}).get('proxy_protocol', False))

    proxy_config.exits = _parse_exits(data.get('exits', {}))
    proxy_config.routes = _parse_routes(data.get('routes', {}))
    proxy_config.ensure_routing_defaults()

    adv = data.get('advanced', {}) or {}
    proxy_config.fallback_cfproxy = bool(adv.get('cfproxy_fallback', True))
    proxy_config.cfproxy_user_domains = coerce_domain_list(
        adv.get('cfproxy_user_domain', []))
    proxy_config.cfproxy_worker_domains = coerce_domain_list(
        adv.get('cfproxy_worker_domain', []))
    proxy_config.pool_size = max(0, int(adv.get('pool_size', 4)))
    proxy_config.buffer_size = max(4, int(adv.get('buf_kb', 256))) * 1024
    proxy_config.verbose = bool(adv.get('verbose', False))
    proxy_config.tls_fragment = bool(adv.get('tls_fragment', False))
    proxy_config.skip_front = bool(adv.get('skip_front', False))
    if adv.get('data_cidrs'):
        proxy_config.data_cidrs = [str(c) for c in adv['data_cidrs']]
    if adv.get('call_cidrs'):
        proxy_config.call_cidrs = [str(c) for c in adv['call_cidrs']]
    if adv.get('bot_api_ip'):
        proxy_config.bot_api_ip = str(adv['bot_api_ip'])
    if adv.get('dc_ip'):
        try:
            proxy_config.dc_redirects = parse_dc_ip_list(list(adv['dc_ip']))
        except ValueError as exc:
            raise ValueError(f"advanced.dc_ip: {exc}")


def _fetch_cfproxy_domain_list() -> List[str]:
    try:
        req = Request(CFPROXY_DOMAINS_URL + "?" + "".join(random.choices(string.ascii_letters, k=7)),
                       headers={'User-Agent': 'tg-ws-proxy'})
        with build_github_opener().open(req, timeout=10) as resp:
            text = resp.read().decode('utf-8', errors='replace')
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        return [_dd(d) for d in encoded]
    except Exception as exc:
        log.warning("Failed to fetch CF proxy domain list: %s", repr(exc))
        return []


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False
        if not all(ch.isalnum() or ch == '-' for ch in label):
            return False
    # TLD should contain letters and be at least 2 chars.
    tld = labels[-1]
    if len(tld) < 2 or not any(ch.isalpha() for ch in tld):
        return False
    return True


def _normalize_domain_pool(domains: List[str]) -> List[str]:
    seen = set()
    normalized: List[str] = []
    for domain in domains:
        item = domain.strip().lower()
        if not _is_valid_domain(item):
            continue
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def refresh_cfproxy_domains() -> None:
    if proxy_config.cfproxy_user_domains:
        return

    fetched = _fetch_cfproxy_domain_list()
    pool = _normalize_domain_pool(fetched)
    if len(pool) >= _CFPROXY_MIN_VALID_DOMAINS:
        balancer.update_domains_list(pool)
        log.info("CF proxy domain pool updated from GitHub (%d domains)", len(pool))
        return

    if fetched:
        log.warning(
            "Ignoring fetched CF proxy domains due to low-quality payload "
            "(total=%d, valid=%d, required>=%d); keeping current domain pool",
            len(fetched), len(pool), _CFPROXY_MIN_VALID_DOMAINS,
        )
    else:
        log.warning(
            "CF proxy domain refresh failed or empty response; "
            "keeping current domain pool",
        )


_refresh_stop: threading.Event = threading.Event()


def start_cfproxy_domain_refresh() -> None:
    global _refresh_stop
    _refresh_stop.set()
    _refresh_stop = threading.Event()
    stop = _refresh_stop

    balancer.update_domains_list(CFPROXY_DEFAULT_DOMAINS)

    def _loop():
        refresh_cfproxy_domains()
        while not stop.wait(timeout=3600):
            refresh_cfproxy_domains()

    threading.Thread(target=_loop, daemon=True, name='cfproxy-domains-refresh').start()


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            raise ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError):
            raise ValueError(f"Invalid --dc-ip {entry!r}")
        dc_redirects[dc_n] = ip_s
    return dc_redirects
