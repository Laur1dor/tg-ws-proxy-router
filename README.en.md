# TG WS/SOCKS5 Proxy — with routing and calls

2026-11-02: configured Workers now precede the public CF pool on the SOCKS
path, and TLS certificate/hostname verification is enabled. The repository
includes a Telegram-only [Worker](./cloudflare-worker.mjs), offline tests and
[deployment notes](./docs/CfWorker.md). Cloudflare must be reachable from the
TGWS host; remote MTProto clients do not connect to Cloudflare themselves.

**Fork of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)**
(built on top of upstream at commit
[`ed46ecc`](https://github.com/Flowseal/tg-ws-proxy/commit/ed46ecce5a21f3bc5cb232e33809d84179b4b4c1),
June 2026) — keeps the original Telegram-data WS bridge over Cloudflare and
adds what upstream doesn't have: a **SOCKS5 inbound** (which also carries
voice/video calls), a **routing engine** (which traffic category takes which
exit, with failover), and an **interactive TUI panel** instead of the desktop
GUI, since this project targets headless deployment on a server/VPS/LXC
rather than Windows/macOS with a tray icon. The SOCKS5+calls idea partly draws
on [DimaXA97/TG-CF-proxy](https://github.com/DimaXA97/TG-CF-proxy) (commit
[`99d06fb`](https://github.com/DimaXA97/TG-CF-proxy/commit/99d06fbb9cdc77862fd927013a0e182b8879edd0)).

📖 **The full, actively-maintained documentation is the [Russian README](./README.md)**
— routing config reference, the complete panel menu walkthrough, the
OpenWRT/podkop/NetShift LAN-wide guide, and the 3x-ui SOCKS5-chaining guide
all live there. This file is a condensed overview for English readers.

---

## What it combines

- **MTProto over Cloudflare WebSocket** — data (messages/media) via the
  Telegram web front + Cloudflare domains/Worker, with TLS ClientHello
  fragmentation to evade DPI. This is upstream tg-ws-proxy's core.
- **SOCKS5 inbound** (optional login/password) — carries **both data and
  calls** (unlike the MTProto inbound, which cannot carry calls at all).
- **Two MTProto inbounds** on separate ports: plain (`dd` link) and
  **Fake TLS** (`ee` link, with RU / foreign domain presets).
- **Routing engine** (`router.py` / `exits.py`) — traffic is classified
  (`data` / `calls` / `bot_api` / `other`) and sent through a configured exit
  chain with automatic **failover** (e.g. an unreliable foreign VPS for calls
  falls back to `direct` the moment it goes down).
- **Interactive TUI panel** in the style of 3x-ui / zapret-manager — one
  command, everything configured from a menu, no manual YAML editing needed.

Designed for headless deployment on a home server/LXC/VPS (Docker or systemd).

---

## ⚠️ About calls (read this first)

Telegram voice/video doesn't go through data centers — it goes over **UDP**
directly to reflector servers (`91.108.4.0/22` … `91.108.20.0/22`), bypassing
proxy settings entirely if the connection method doesn't support it.

- The **MTProto inbound cannot carry calls** — a protocol/client limitation,
  not a bug here.
- The **SOCKS5 inbound can carry calls**, but only if the reflectors are
  reachable from wherever the configured exit points:
  - only data is blocked (reflectors reachable) → `calls: [direct]` is enough,
    no VPS needed;
  - both data and calls are blocked → you need a **foreign exit**
    (upstream SOCKS5 / VPS), e.g. `calls: [finland, direct]`.
- Cloudflare-WS cannot carry calls at all — Cloudflare Workers only support
  **TCP**, and call media over reflectors is **UDP**.

---

## Quick start

```bash
# one-liner, no Docker (LXC/VPS/bare Linux):
curl -fsSL https://github.com/Laur1dor/tg-ws-proxy-router/archive/refs/heads/main.tar.gz | tar xz \
  && cd tg-ws-proxy-router-main && sudo bash deploy/install.sh

# or Docker Compose:
git clone https://github.com/Laur1dor/tg-ws-proxy-router.git && cd tg-ws-proxy-router
cp config.example.yml config.yml
docker compose up -d --build
```
Then run the panel:
```bash
tgws                      # or: ./tgws.sh  /  python3 -m proxy.menu
```
It generates secrets, prints ready `tg://proxy?...` links, and lets you
configure ports, SOCKS5 auth, Fake TLS domain presets, the calls exit
(with health-checked failover), and service management (systemd or Docker,
auto-detected) — all from the menu, applied with an in-panel restart.

For the full routing-config reference (`exits` / `routes` / `advanced`),
the complete panel menu table, the LAN-wide OpenWRT/podkop/NetShift
walkthrough (and the routing-loop pitfall to avoid), and the 3x-ui
SOCKS5-chaining guide — see the **[Russian README](./README.md)** and
[`docs/`](./docs/).

## License

MIT (inherited from Flowseal/tg-ws-proxy, see [LICENSE](LICENSE)).
