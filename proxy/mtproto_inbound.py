"""
MTProto-proxy inbound (classic tg://proxy link, with optional Fake TLS).

This is the original Flowseal tg-ws-proxy client handler, refactored into an
importable handler. It carries DATA only (messages/media) and re-encrypts the
client MTProto layer onto a fresh relay obfuscation tunneled through the
Cloudflare WS bridge, with CF-worker / direct-TCP fallbacks.

Voice calls do NOT travel through an MTProto proxy (Telegram routes them to the
reflectors directly), so the SOCKS5 inbound is what carries calls.
"""
from __future__ import annotations

import os
import time
import struct
import asyncio
import hashlib
import logging

from typing import Dict, Optional, Set, Tuple

from .utils import *
from .stats import stats
from .config import proxy_config
from .bridge import MsgSplitter, CryptoCtx, do_fallback, bridge_ws_reencrypt
from .raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts
from .fake_tls import (proxy_to_masking_domain, verify_client_hello,
                       build_server_hello, FakeTlsStream, TLS_RECORD_HANDSHAKE)
from .pool import ws_pool
from ._aes import Cipher, algorithms, modes


log = logging.getLogger('tg-mtproto-proxy')

DC_FAIL_COOLDOWN = 30.0
WS_FAIL_TIMEOUT = 2.0
ws_blacklist: Set[str] = set()
dc_fail_until: Dict[str, float] = {}


def _try_handshake(handshake: bytes, secret: bytes) -> Optional[Tuple[int, bool, bytes, bytes]]:
    dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec_prekey = dec_prekey_and_iv[:PREKEY_LEN]
    dec_iv = dec_prekey_and_iv[PREKEY_LEN:]

    dec_key = hashlib.sha256(dec_prekey + secret).digest()

    dec_iv_int = int.from_bytes(dec_iv, 'big')
    decryptor = Cipher(
        algorithms.AES(dec_key), modes.CTR(dec_iv_int.to_bytes(16, 'big'))
    ).encryptor()
    decrypted = decryptor.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
    if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE,
                         PROTO_TAG_SECURE):
        return None

    dc_idx = int.from_bytes(
        decrypted[DC_IDX_POS:DC_IDX_POS + 2], 'little', signed=True)

    dc_id = abs(dc_idx)
    is_media = dc_idx < 0

    return dc_id, is_media, proto_tag, dec_prekey_and_iv


def _generate_relay_init(proto_tag: bytes, dc_idx: int) -> bytes:
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    rnd_bytes = bytes(rnd)

    enc_key = rnd_bytes[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    enc_iv = rnd_bytes[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]

    encryptor = Cipher(
        algorithms.AES(enc_key), modes.CTR(enc_iv)
    ).encryptor()

    dc_bytes = struct.pack('<h', dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    encrypted_full = encryptor.update(rnd_bytes)
    keystream_tail = bytes(
        encrypted_full[i] ^ rnd_bytes[i] for i in range(56, 64))
    encrypted_tail = bytes(
        tail_plain[i] ^ keystream_tail[i] for i in range(8))

    result = bytearray(rnd_bytes)
    result[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(result)


async def _read_client_init(reader, writer, secret, label, masking):
    if proxy_config.proxy_protocol:
        try:
            pp_line = await asyncio.wait_for(
                reader.readline(), timeout=10)
        except asyncio.IncompleteReadError:
            log.debug("[%s] disconnected during PROXY header", label)
            return None
        pp_text = pp_line.decode('ascii', errors='replace').strip()
        if pp_text.startswith('PROXY '):
            parts = pp_text.split()
            if len(parts) >= 6:
                label = f"{parts[2]}:{parts[4]}"
            log.debug("[%s] PROXY protocol: %s", label, pp_text)
        else:
            log.debug("[%s] expected PROXY header, got: %r", label,
                      pp_text[:60])

    try:
        first_byte = await asyncio.wait_for(
            reader.readexactly(1), timeout=10)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected before handshake", label)
        return None

    if first_byte[0] == TLS_RECORD_HANDSHAKE and masking:
        try:
            hdr_rest = await asyncio.wait_for(
                reader.readexactly(4), timeout=10)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete TLS record header", label)
            return None

        tls_header = first_byte + hdr_rest
        record_len = struct.unpack('>H', tls_header[3:5])[0]

        try:
            record_body = await asyncio.wait_for(
                reader.readexactly(record_len), timeout=10)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete TLS record body", label)
            return None

        client_hello = tls_header + record_body

        tls_result = verify_client_hello(client_hello, secret)

        if tls_result is None:
            log.debug("[%s] Fake TLS verify failed (size=%d rec=%d) "
                      "-> masking",
                      label, len(client_hello), record_len)
            await proxy_to_masking_domain(
                reader, writer, client_hello, masking, label)
            return None

        client_random, session_id, ts = tls_result
        log.debug("[%s] Fake TLS handshake ok (ts=%d)", label, ts)

        server_hello = build_server_hello(secret, client_random, session_id)
        writer.write(server_hello)
        await writer.drain()

        tls_stream = FakeTlsStream(reader, writer)

        try:
            handshake = await asyncio.wait_for(
                tls_stream.readexactly(HANDSHAKE_LEN), timeout=10)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete obfs2 init inside TLS", label)
            return None

        return handshake, tls_stream, tls_stream, label

    elif masking:
        log.debug("[%s] non-TLS byte 0x%02X -> HTTP redirect", label,
                  first_byte[0])
        redirect = (
            f"HTTP/1.1 301 Moved Permanently\r\n"
            f"Location: https://{masking}/\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(redirect)
        await writer.drain()
        return None

    else:
        try:
            rest = await asyncio.wait_for(
                reader.readexactly(HANDSHAKE_LEN - 1), timeout=10)
        except asyncio.IncompleteReadError:
            log.debug("[%s] client disconnected before handshake", label)
            return None
        return first_byte + rest, reader, writer, label


def _build_crypto_ctx(client_dec_prekey_iv, secret, relay_init):
    # key = SHA256(prekey + secret), iv from handshake
    # "dec" = decrypt data from client; "enc" = encrypt data to client
    clt_dec_prekey = client_dec_prekey_iv[:PREKEY_LEN]
    clt_dec_iv = client_dec_prekey_iv[PREKEY_LEN:]
    clt_dec_key = hashlib.sha256(clt_dec_prekey + secret).digest()

    clt_enc_prekey_iv = client_dec_prekey_iv[::-1]
    clt_enc_key = hashlib.sha256(
        clt_enc_prekey_iv[:PREKEY_LEN] + secret).digest()
    clt_enc_iv = clt_enc_prekey_iv[PREKEY_LEN:]

    clt_decryptor = Cipher(
        algorithms.AES(clt_dec_key), modes.CTR(clt_dec_iv)
    ).encryptor()
    clt_encryptor = Cipher(
        algorithms.AES(clt_enc_key), modes.CTR(clt_enc_iv)
    ).encryptor()

    # fast-forward client decryptor past the 64-byte init
    clt_decryptor.update(ZERO_64)

    # relay side: standard obfuscation (no secret hash, raw key)
    relay_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:
                              SKIP_LEN + PREKEY_LEN + IV_LEN]

    relay_dec_prekey_iv = relay_init[SKIP_LEN:
                                     SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    relay_dec_key = relay_dec_prekey_iv[:KEY_LEN]
    relay_dec_iv = relay_dec_prekey_iv[KEY_LEN:]

    tg_encryptor = Cipher(
        algorithms.AES(relay_enc_key), modes.CTR(relay_enc_iv)
    ).encryptor()
    tg_decryptor = Cipher(
        algorithms.AES(relay_dec_key), modes.CTR(relay_dec_iv)
    ).encryptor()

    tg_encryptor.update(ZERO_64)

    return CryptoCtx(clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor)


async def handle_mtproto_client(reader, writer, secret: bytes,
                                fake_tls_domain: str = ''):
    stats.connections_total += 1
    stats.connections_active += 1
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"

    set_sock_opts(writer.transport, proxy_config.buffer_size)

    try:
        init = await _read_client_init(
            reader, writer, secret, label, fake_tls_domain)
        if init is None:
            return

        handshake, clt_reader, clt_writer, label = init

        result = _try_handshake(handshake, secret)
        if result is None:
            stats.connections_bad += 1
            log.warning("[%s] bad handshake (wrong secret or proto)", label)
            try:
                while await clt_reader.read(4096):
                    pass
            except Exception:
                pass
            return

        dc, is_media, proto_tag, client_dec_prekey_iv = result

        if proto_tag == PROTO_TAG_ABRIDGED:
            proto_int = PROTO_ABRIDGED_INT
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            proto_int = PROTO_INTERMEDIATE_INT
        else:
            proto_int = PROTO_PADDED_INTERMEDIATE_INT

        dc_idx = -dc if is_media else dc

        log.debug("[%s] handshake ok: DC%d%s proto=0x%08X",
                  label, dc, ' media' if is_media else '', proto_int)

        relay_init = _generate_relay_init(proto_tag, dc_idx)
        ctx = _build_crypto_ctx(client_dec_prekey_iv, secret, relay_init)

        dc_key = f'{dc}{"m" if is_media else ""}'
        media_tag = " media" if is_media else ""

        # Go straight to CF when:
        #  - TLS fragmentation is on (we're behind DPI; the Telegram-IP front
        #    is dead and probing it just adds latency + can loop with podkop),
        #  - the DC has no direct front configured, or
        #  - this DC/is_media was WS-blacklisted.
        if (proxy_config.skip_front or proxy_config.tls_fragment
                or dc not in proxy_config.dc_redirects
                or dc_key in ws_blacklist):
            if proxy_config.skip_front or proxy_config.tls_fragment:
                log.debug("[%s] DC%d%s tls_fragment -> CF (skip front)",
                          label, dc, media_tag)
            elif dc not in proxy_config.dc_redirects:
                log.info("[%s] DC%d not in config -> fallback",
                         label, dc)
            else:
                log.info("[%s] DC%d%s WS blacklisted -> fallback",
                         label, dc, media_tag)
            splitter = None
            try:
                splitter = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                clt_reader, clt_writer, relay_init, label,
                dc, is_media, media_tag,
                ctx, splitter=splitter)
            if not ok:
                log.warning("[%s] DC%d%s no fallback available",
                            label, dc, media_tag)
            return

        now = time.monotonic()
        fail_until = dc_fail_until.get(dc_key, 0)
        ws_timeout = WS_FAIL_TIMEOUT if now < fail_until else 10.0

        domains = ws_domains(dc, is_media)
        target = proxy_config.dc_redirects[dc]
        ws = None
        ws_failed_redirect = False
        all_redirects = True

        ws = await ws_pool.get(dc, is_media, target, domains)
        if ws:
            log.info("[%s] DC%d%s -> pool hit via %s",
                     label, dc, media_tag, target)
        else:
            for domain in domains:
                url = f'wss://{domain}/apiws'
                log.info("[%s] DC%d%s -> %s via %s",
                         label, dc, media_tag, url, target)
                try:
                    ws = await RawWebSocket.connect(target, domain,
                                                    timeout=ws_timeout)
                    all_redirects = False
                    break
                except WsHandshakeError as exc:
                    stats.ws_errors += 1
                    if exc.is_redirect:
                        ws_failed_redirect = True
                        log.warning("[%s] DC%d%s got %d from %s -> %s",
                                    label, dc, media_tag,
                                    exc.status_code, domain,
                                    exc.location or '?')
                        continue
                    else:
                        all_redirects = False
                        log.warning("[%s] DC%d%s WS handshake: %s",
                                    label, dc, media_tag, exc.status_line)
                except Exception as exc:
                    stats.ws_errors += 1
                    all_redirects = False
                    log.warning("[%s] DC%d%s WS connect failed: %s",
                                label, dc, media_tag, repr(exc))

        # WS failed -> fallback
        if ws is None:
            if ws_failed_redirect and all_redirects:
                ws_blacklist.add(dc_key)
                log.warning("[%s] DC%d%s blacklisted for WS (all 302)",
                            label, dc, media_tag)
            elif ws_failed_redirect:
                dc_fail_until[dc_key] = now + DC_FAIL_COOLDOWN
            else:
                dc_fail_until[dc_key] = now + DC_FAIL_COOLDOWN
                log.info("[%s] DC%d%s WS cooldown for %ds",
                         label, dc, media_tag, int(DC_FAIL_COOLDOWN))

            splitter_fb = None
            try:
                splitter_fb = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                clt_reader, clt_writer, relay_init, label,
                dc, is_media, media_tag,
                ctx, splitter=splitter_fb)
            if ok:
                log.info("[%s] DC%d%s fallback closed",
                         label, dc, media_tag)
            return

        dc_fail_until.pop(dc_key, None)
        stats.connections_ws += 1

        splitter = None
        try:
            splitter = MsgSplitter(relay_init, proto_int)
            log.debug("[%s] MsgSplitter activated for proto 0x%08X",
                      label, proto_int)
        except Exception:
            pass

        await ws.send(relay_init)

        await bridge_ws_reencrypt(clt_reader, clt_writer, ws, label, ctx,
                                   dc=dc, is_media=is_media,
                                   splitter=splitter)

    except asyncio.TimeoutError:
        log.warning("[%s] timeout during handshake", label)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected", label)
    except asyncio.CancelledError:
        log.debug("[%s] cancelled", label)
    except ConnectionResetError:
        log.debug("[%s] connection reset", label)
    except OSError as exc:
        if getattr(exc, 'winerror', None) == 1236:
            log.debug("[%s] connection aborted by local system", label)
        else:
            log.error("[%s] unexpected OS error: %s", label, repr(exc))
    except Exception as exc:
        log.error("[%s] unexpected: %s", label, exc, exc_info=True)
    finally:
        stats.connections_active -= 1
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass
