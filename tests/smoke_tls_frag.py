"""
Offline test of the manual fragmented-TLS client (proxy/tls_frag.py).

Stands up a local self-signed TLS echo server, then connects to it with
open_tls_fragmented() (which splits the ClientHello at the SNI) and verifies a
full handshake + bidirectional app data + readline work. This validates the
manual TLS driving + fragmentation mechanics (not real DPI evasion).

Run: python -m tests.smoke_tls_frag
"""
import asyncio
import datetime
import os
import ssl
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from proxy.tls_frag import open_tls_fragmented, _split_at_sni


def _make_cert(tmpdir):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(tmpdir, 'c.pem')
    key_path = os.path.join(tmpdir, 'k.pem')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    return cert_path, key_path


async def main():
    # unit-check the splitter cuts inside the SNI
    ch = b'\x16\x03\x01..stuff..kws2.web.telegram.org..more..'
    a, b = _split_at_sni(ch, 'kws2.web.telegram.org')
    assert a + b == ch and b'telegram.org' not in a and b'kws2.web' not in b, \
        "splitter did not cut inside the SNI"
    print("PASS: ClientHello splitter cuts inside the SNI hostname")

    tmp = tempfile.mkdtemp()
    cert_path, key_path = _make_cert(tmp)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)

    async def handle(r, w):
        data = await r.readexactly(11)
        w.write(b'echo:' + data + b'\n')
        await w.drain()
        w.close()

    server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    asyncio.create_task(server.serve_forever())

    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE

    stream = await open_tls_fragmented(
        '127.0.0.1', port, 'kws2.web.telegram.org', client_ctx,
        timeout=10, buffer_size=256 * 1024, fragment=True)
    print("PASS: fragmented-TLS handshake completed")

    stream.write(b'hello world')
    await stream.drain()
    line = await stream.readline()
    assert line == b'echo:hello world\n', f"bad echo: {line!r}"
    print("PASS: app data round-trip over fragmented TLS (write + readline)")

    stream.close()
    await stream.wait_closed()
    print("\nAll TLS-fragmentation smoke tests passed.")


if __name__ == '__main__':
    asyncio.run(main())
