# TG WS/SOCKS5 Proxy — с маршрутизацией и звонками

**Форк [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)** (собран
поверх состояния апстрима на коммит [`ed46ecc`](https://github.com/Flowseal/tg-ws-proxy/commit/ed46ecce5a21f3bc5cb232e33809d84179b4b4c1),
июнь 2026) — сохраняет оригинальный WS-мост Telegram-данных через Cloudflare
и добавляет то, чего в оригинале нет: **SOCKS5-вход** (через него звонки тоже
доезжают), **движок маршрутизации** (какой трафик каким выходом идёт, с
failover) и **интерактивную TUI-панель** вместо десктоп-GUI, поскольку проект
рассчитан на headless-запуск на сервере/VPS/LXC, а не на Windows/macOS с
трей-иконкой. Идея SOCKS5+звонков частично опирается на форк
[DimaXA97/TG-CF-proxy](https://github.com/DimaXA97/TG-CF-proxy) (коммит
[`99d06fb`](https://github.com/DimaXA97/TG-CF-proxy/commit/99d06fbb9cdc77862fd927013a0e182b8879edd0)).

📖 **[English README](./README.en.md)**

Доступна также **[локальная HTTPS веб-панель](./docs/WebUI.md)** с отдельным
паролем администратора, настройками входов/Worker/маршрутов, ссылками,
журналом и откатом конфигурации. TUI сохраняется. Установка веб-панели
отдельная; публичный доступ не включается автоматически.

Обновление 02.11.2026: собственный Worker получает приоритет перед публичным
CF-пулом в SOCKS-пути; TLS-сертификаты и имя сервера теперь проверяются.
В репозитории есть ограниченный Telegram-реле [Worker](./cloudflare-worker.mjs),
проверки и [инструкция](./docs/CfWorker.md), включая зависимость от доступности
Cloudflare на стороне TGWS и безопасное обновление существующей установки.

---

## Что это объединяет

- **MTProto через Cloudflare-WebSocket** — данные (сообщения/медиа) через
  Telegram-веб-фронт + Cloudflare-домены/Worker, с фрагментацией TLS
  ClientHello для обхода DPI. Это ядро оригинального tg-ws-proxy.
- **SOCKS5-вход** (с опциональным логином/паролем) — через него Telegram
  гонит **и данные, и звонки** (в отличие от MTProto-входа, который звонки в
  принципе не переносит).
- **Два MTProto-входа** на разных портах: обычный (`dd`-ссылка) и с
  **Fake TLS** (`ee`-ссылка, с пресетами доменов RU / зарубежных).
- **Движок маршрутизации** (`router.py` / `exits.py`) — трафик
  классифицируется (`data` / `calls` / `bot_api` / `other`) и идёт по цепочке
  выходов с автоматическим **failover** (например, ненадёжный зарубежный VPS
  для звонков → откат на `direct`, как только VPS «отрыгнёт»).
- **Интерактивная TUI-панель** в стиле 3x-ui / zapret-manager — одна команда,
  и всё настраивается из меню, без ручной правки YAML.

Рассчитан на headless-запуск на домашнем сервере/LXC/VPS (Docker или systemd).

---

## Панель управления — полный список возможностей

```bash
./tgws.sh          # или:  python3 -m proxy.menu   /   команда `tgws` после установки
```

| Пункт меню | Что делает |
|---|---|
| **1. Данные подключения** | Готовые `tg://proxy?...` ссылки (обычный + Fake TLS) и SOCKS5-реквизиты — сразу с текущим IP/портами/секретами. |
| **2. SOCKS5** | Порт, включить/выключить логин-пароль (по умолчанию без авторизации). |
| **3. MTProto обычный** | Порт, свой/сгенерированный секрет. |
| **4. MTProto + Fake TLS** | Порт, домен маскировки — **пресеты** RU-сайтов (vk.com, ozon.ru, gosuslugi.ru…) и зарубежных (cloudflare.com, google.com…), либо свой домен. |
| **5. Звонки и выходы** | Настройка зарубежного upstream-SOCKS5 (VPS) под звонки, health-check с авто-failover на `direct`, полная блокировка звонков при желании. |
| **6. Служба** | Старт/стоп/рестарт, логи, статус, автозапуск, деинсталляция. Панель сама определяет режим — **systemd** или **Docker** — и управляет им нужным способом. |
| **7. Расширенные** | Cloudflare fallback-домены / свой Cloudflare Worker, `tls_fragment` (встроенный обход DPI без zapret/podkop), `skip_front` (для схем с редиректом трафика на роутере — см. [docs/OpenWrt-NetShift.md](docs/OpenWrt-NetShift.md)), размер пула соединений, буфер. |

Все изменения сразу пишутся в `config.yml` и применяются рестартом службы
прямо из панели — вручную ничего перезапускать не нужно.

Чтобы вызывать одним словом из любого места:
```bash
sudo ln -s "$(pwd)/tgws.sh" /usr/local/bin/tgws   # потом просто:  tgws
```
(автоматически делает и `deploy/install.sh`).

---

## ⚠️ Главное про звонки (прочитай)

Голос/видео в Telegram идут **не через дата-центры**, а через отдельные
серверы-рефлекторы (подсети `91.108.4.0/22` … `91.108.20.0/22`), и клиент
Telegram шлёт их **по UDP мимо** прокси-настроек, если способ подключения
этого не поддерживает.

- **MTProto-вход физически не возит звонки** — это ограничение самого
  протокола/клиента, а не наша недоработка.
- **SOCKS5-вход возит звонки**, но только если рефлекторы доступны с той
  точки, куда указывает выход:
  - режут **только данные** (рефлекторы доступны) → достаточно `calls: [direct]`,
    VPS не нужен;
  - режут **и звонки** → нужен **зарубежный выход** (upstream-SOCKS5/VPS),
    например `calls: [finland, direct]`.
- Cloudflare-WS для звонков не подходит в принципе — Cloudflare Workers несут
  только **TCP**, а рефлекторный медиа-трафик звонка — **UDP**.

---

## Как это работает

```
                                    ┌─ data    → Cloudflare-WS  → Telegram DC
Telegram ─SOCKS5/MTProto→  ПРОКСИ ──┼─ calls   → VPS / direct   → рефлекторы
                                    ├─ bot_api → direct         → api.telegram.org
                                    └─ other   → direct
```

Каждое соединение классифицируется по адресу назначения и проводится по
цепочке выходов из `routes` (по порядку, с failover при сбое или падении VPS).

---

## Быстрый старт

### Одной строкой (LXC / VPS / голый Linux, без Docker)
```bash
curl -fsSL https://github.com/Laur1dor/tg-ws-proxy-router/archive/refs/heads/main.tar.gz | tar xz \
  && cd tg-ws-proxy-router-main && sudo bash deploy/install.sh
```
Установщик сам: поставит python3+venv, зависимости, сгенерирует `config.yml`
и секреты, включит `tls_fragment` (обход DPI), поднимет и автозапустит
systemd-службу `tgws`, положит команду `tgws` в `PATH`.
```bash
tgws                      # панель управления
journalctl -u tgws -f     # логи
systemctl status tgws     # статус
```

### Docker Compose
```bash
git clone https://github.com/Laur1dor/tg-ws-proxy-router.git && cd tg-ws-proxy-router
cp config.example.yml config.yml
# настрой через панель (./tgws.sh) или впиши IP VPS в exit 'finland' вручную
docker compose up -d --build
docker compose logs -f
```
Поднимутся порты: `1080` (SOCKS5), `1443` (MTProto обычный), `1444` (MTProto
Fake TLS). `docker-compose.yml` использует `network_mode: host` (Linux),
поэтому смена портов в панели применяется без правки compose.

**Вариант с WireGuard-выходом** (весь egress через VPS по L3): положи
`wg0.conf` рядом и запусти
```bash
docker compose -f docker-compose-vps.yml up -d --build
```

### Без Docker и без установщика
```bash
pip install -r requirements.txt
python -m proxy -c config.yml
```

---

## Настройка Telegram-клиента

- **Звонки + данные (рекомендуется): SOCKS5.**
  Настройки → Продвинутые → Тип соединения → Свой прокси → SOCKS5,
  `адрес = IP сервера`, `порт = 1080` (+ логин/пароль, если задал в панели).
- **Только данные, в один тап (телефон): MTProto.**
  Возьми ссылку `tg://proxy?...` из панели (пункт 1) — обычную (порт 1443)
  или с Fake TLS (порт 1444). Звонки через MTProto не пойдут.
- **LAN-wide, без настройки на каждом клиенте** — заверни Telegram-трафик
  роутером (podkop/NetShift на OpenWRT) на SOCKS5-вход tgws. Гайд с важными
  нюансами (иначе поймаете петлю): [docs/OpenWrt-NetShift.md](docs/OpenWrt-NetShift.md).
- **Клиентам VLESS/3x-ui на том же VPS** — можно завернуть их Telegram-трафик
  в локальный (не торчащий наружу) SOCKS5 tgws через chained outbound в Xray:
  [docs/3xui-chaining.md](docs/3xui-chaining.md).

---

## Меню маршрутизации (`config.yml`)

Три блока: **ВХОДЫ** (`listen`), **ВЫХОДЫ** (`exits`), **МАРШРУТЫ** (`routes`).

```yaml
exits:
  cf_ws:   { type: cloudflare_ws }          # MTProto-данные через Cloudflare
  direct:  { type: direct }                 # напрямую с этого сервера
  finland:                                  # зарубежный VPS как upstream
    type: socks5
    host: 1.2.3.4
    port: 1080
    health_check: true                      # авто-failover при падении VPS

routes:
  data:    [cf_ws, direct]
  calls:   [finland, direct]                # VPS, при падении — напрямую
  bot_api: [direct]
  other:   [direct]

advanced:
  tls_fragment: true   # встроенный обход DPI (режет ClientHello по SNI)
  skip_front: false     # true — никогда не набирать Telegram-IP напрямую
                         # (обязательно за роутером с редиректом Telegram, см.
                         # docs/OpenWrt-NetShift.md — иначе будет петля)
```

Категории: `data` (сообщения/медиа), `calls` (звонки), `bot_api`, `other`.
Список в `routes` — цепочка с failover: пробуем по порядку, при сбое —
следующий. `health_check` у socks5-выхода: прокси периодически проверяет VPS
и при его падении мгновенно уходит на следующий выход (решает проблему
«VPS ненадёжный»).

Полное описание всех опций — в комментариях `config.example.yml`.

---

## Структура

```
proxy/
  menu.py             интерактивная панель (TUI), не требует cryptography
  presets.py          пресеты доменов Fake TLS (RU / зарубежные)
  server.py           точка входа: грузит конфиг, поднимает входы
  config.py           YAML-конфиг + модель маршрутизации
  router.py           классификация назначения → цепочка выходов
  exits.py            выходы (cf_ws / direct / socks5) + health-check
  socks5_inbound.py   SOCKS5-вход (данные + звонки, опц. логин/пароль)
  mtproto_inbound.py  MTProto-вход (ссылка tg://proxy + Fake TLS)
  relay.py            «сырые» мосты для SOCKS5-режима
  bridge.py           WS-мост с перешифровкой (MTProto-режим)
  raw_websocket.py    клиент WebSocket
  pool.py balancer.py fake_tls.py stats.py utils.py _aes.py
tgws.sh  tgws.cmd      лаунчеры панели (Linux / Windows)
config.example.yml    справочник всех опций конфига
Dockerfile  docker-compose.yml  docker-compose-vps.yml
deploy/                install.sh / uninstall.sh / systemd-юнит (LXC/VPS)
docs/
  OpenWrt-NetShift.md  LAN-wide через podkop/NetShift — и как не поймать петлю
  3xui-chaining.md     цепочка VLESS(3x-ui) → локальный tgws на том же VPS
  CfProxy.md CfWorker.md  свой Cloudflare-домен/Worker (унаследовано из апстрима)
tests/smoke_socks5.py офлайн-тест SOCKS5 + маршрутизации
tests/smoke_tls_frag.py офлайн-тест фрагментации TLS
```

---

## Тесты

```bash
python -m tests.smoke_socks5
python -m tests.smoke_tls_frag
```

Проверяют SOCKS5-согласование, маршрут `other → direct`, failover с мёртвого
upstream на `direct` и корректность фрагментации TLS — всё офлайн, без
обращения к настоящему Telegram.

---

## Отношение к апстриму

Это независимый форк, а не PR в оригинал — изменения (SOCKS5, маршрутизация,
TUI-панель, отказ от desktop-GUI) достаточно объёмные и меняют способ
эксплуатации проекта (headless-сервер вместо десктоп-приложения), поэтому
живут отдельным репозиторием. WS-мост, Fake TLS и перешифровка — оригинальная
работа [Flowseal](https://github.com/Flowseal); там же стоит смотреть issues
и обсуждения по самому механизму WS-моста, если вопрос не касается SOCKS5/
маршрутизации/панели, добавленных в этом форке.

## Лицензия

MIT (наследуется от Flowseal/tg-ws-proxy, см. [LICENSE](LICENSE)).
