import socket as _socket
import ipaddress
import urllib.request
import http.client

from typing import Optional, Dict, List, Tuple
from urllib.request import Request


ZERO_64 = b'\x00' * 64
HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'
PROTO_TAG_SECURE = b'\xdd\xdd\xdd\xdd'

PROTO_ABRIDGED_INT = 0xEFEFEFEF
PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD

RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54',
                    b'\x47\x45\x54\x20', b'\xee\xee\xee\xee',
                    b'\xdd\xdd\xdd\xdd', b'\x16\x03\x01\x02'}
RESERVED_CONTINUE = b'\x00\x00\x00\x00'

_GITHUB_IPS: Dict[str, str] = {
    "release-assets.githubusercontent.com": "185.199.109.133",
    "raw.githubusercontent.com": "185.199.109.133",
}

DC_DEFAULT_IPS: Dict[int, str] = {
    1: '149.154.175.50',
    2: '149.154.167.51',
    3: '149.154.175.100',
    4: '149.154.167.91',
    5: '149.154.171.5',
    203: '91.105.192.100'
}

# --- Telegram traffic classification (used by SOCKS5 inbound + router) ---
#
# Telegram splits its infrastructure into two kinds of endpoints that must be
# routed differently:
#   * DATA (messages, media, files) -> the data centers (DC). These can be
#     tunneled through the Cloudflare WebSocket bridge.
#   * CALLS (voice/video) -> the reflector/relay servers. These are NOT
#     MTProto-over-WS, so they cannot go through the CF bridge; they need a
#     clean exit (direct, or an upstream SOCKS5/VPS).
#
# Default CIDR lists. They can be overridden from the YAML config (the
# "routing menu") via advanced.data_cidrs / advanced.call_cidrs.

DEFAULT_DATA_CIDRS: List[str] = [
    '149.154.160.0/20',
    '149.154.164.0/22',
    '149.154.172.0/22',
    '91.108.56.0/22',
    '95.161.64.0/20',
    '185.76.151.0/24',
    '91.105.192.0/23',
    '5.28.195.0/24',
]

DEFAULT_CALL_CIDRS: List[str] = [
    '91.108.4.0/22',
    '91.108.8.0/22',
    '91.108.12.0/22',
    '91.108.16.0/22',
    '91.108.20.0/22',
]

# DC subnet -> (dc_id, is_media). Best-effort resolution of the target DC from
# the destination IP, used only when the native MTProto init packet does not
# carry the DC index. Call ranges are intentionally absent here: call traffic
# is classified as "calls" and never reaches DC resolution.
_DC_SUBNETS_RAW: List[Tuple[str, int, bool]] = [
    ('185.76.151.0/24', 1, False),
    ('149.154.172.0/22', 1, False),
    ('5.28.195.0/24', 2, False),
    ('95.161.64.0/20', 2, False),
    ('149.154.160.0/20', 2, False),
    ('149.154.164.0/22', 4, False),
    ('91.108.56.0/22', 5, False),
    ('91.105.192.0/23', 203, False),
]


def build_networks(cidrs: List[str]) -> list:
    """Compile a CIDR string list into ip_network objects, skipping bad ones."""
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    return nets


_DC_SUBNET_NETS = [
    (ipaddress.ip_network(cidr), dc, is_media)
    for cidr, dc, is_media in _DC_SUBNETS_RAW
]


def ip_in_networks(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def resolve_dc_from_ip(ip: str) -> Tuple[int, bool]:
    """Fallback DC resolution from a destination IP. Defaults to DC2."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 2, False
    for net, dc, is_media in _DC_SUBNET_NETS:
        if addr in net:
            return dc, is_media
    return 2, False


def ws_domains(dc: int, is_media) -> List[str]:
    if dc == 203:
        dc = 2
    if is_media is None or is_media:
        return [f'kws{dc}-1.web.telegram.org', f'kws{dc}.web.telegram.org']
    return [f'kws{dc}.web.telegram.org', f'kws{dc}-1.web.telegram.org']


def human_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024  # type: ignore
    return f"{n:.1f}TB"


def get_link_host(host: str) -> Optional[str]:
    if host == '0.0.0.0':
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                _s.connect(('8.8.8.8', 80))
                link_host = _s.getsockname()[0]
        except OSError:
            link_host = '127.0.0.1'
        return link_host
    else:
        return host


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: Request):
        host = req.host.split(":")[0]
        ip = _GITHUB_IPS.get(host)
        if not ip:
            return super().https_open(req)
        pinned = ip

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = _socket.create_connection(
                    (pinned, self.port or 443),
                    self.timeout,
                    self.source_address,
                )
                if self._tunnel_host:
                    self._tunnel()
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=self._tunnel_host or self.host
                )

        try:
            return self.do_open(_Conn, req)
        except Exception:
            return super().https_open(req)


def build_github_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_PinnedHTTPSHandler())