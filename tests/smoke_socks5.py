"""
Offline functional smoke test for the SOCKS5 inbound + routing/failover.

Does NOT touch Telegram. It stands up a local echo server and drives traffic
through the proxy's SOCKS5 handler:
  1. CONNECT to a non-Telegram IP  -> classified 'other' -> exit 'direct'.
  2. Same, but the route is [dead_upstream, direct] -> failover to 'direct'.

Run: python -m tests.smoke_socks5
"""
import asyncio
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.config import proxy_config, ExitDef
from proxy import router, exits
from proxy.socks5_inbound import handle_socks5_client


async def echo_server():
    async def handle(r, w):
        while True:
            data = await r.read(4096)
            if not data:
                break
            w.write(data)
            await w.drain()
        w.close()
    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    asyncio.create_task(server.serve_forever())
    return port


async def socks5_roundtrip(proxy_port, target_ip, target_port, payload):
    r, w = await asyncio.open_connection('127.0.0.1', proxy_port)
    # greeting
    w.write(b'\x05\x01\x00')
    await w.drain()
    assert await r.readexactly(2) == b'\x05\x00', "greeting failed"
    # CONNECT
    w.write(b'\x05\x01\x00\x01' + socket.inet_aton(target_ip)
            + struct.pack('>H', target_port))
    await w.drain()
    reply = await r.readexactly(10)
    assert reply[1] == 0x00, f"CONNECT rejected rep={reply[1]}"
    # data
    w.write(payload)
    await w.drain()
    got = await asyncio.wait_for(r.readexactly(len(payload)), timeout=5)
    w.close()
    return got


async def start_proxy():
    server = await asyncio.start_server(
        handle_socks5_client, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    asyncio.create_task(server.serve_forever())
    return port


async def main():
    router.init_router()
    echo_port = await echo_server()
    proxy_port = await start_proxy()
    payload = b'hello-telegram-proxy-' * 10

    # --- Test 1: direct exit ---
    proxy_config.exits = {'direct': ExitDef('direct', 'direct')}
    proxy_config.routes = {'other': ['direct']}
    got = await socks5_roundtrip(proxy_port, '127.0.0.1', echo_port, payload)
    assert got == payload, "echo mismatch via direct"
    print("PASS: SOCKS5 -> classify 'other' -> exit 'direct' -> echo ok")

    # --- Test 2: failover from dead upstream to direct ---
    proxy_config.exits = {
        'deadvps': ExitDef('deadvps', 'socks5', host='127.0.0.1', port=1,
                            health_check=False),
        'direct': ExitDef('direct', 'direct'),
    }
    proxy_config.routes = {'other': ['deadvps', 'direct']}
    got = await socks5_roundtrip(proxy_port, '127.0.0.1', echo_port, payload)
    assert got == payload, "echo mismatch via failover"
    print("PASS: dead upstream -> failover -> exit 'direct' -> echo ok")

    print("\nAll smoke tests passed.")


if __name__ == '__main__':
    asyncio.run(main())
