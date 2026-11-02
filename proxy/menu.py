#!/usr/bin/env python3
"""
Интерактивная панель управления (TUI) в стиле 3x-ui / zapret-manager.

Запуск:  python -m proxy.menu        (или ./tgws.sh)

Панель редактирует config.yml и управляет службой (docker compose). Она НЕ
зависит от cryptography — её можно запускать прямо на хосте.
"""
from __future__ import annotations

import os
import secrets as _secrets
import shutil
import subprocess
import sys

from .config import (proxy_config, load_yaml_config, MtprotoListener, ExitDef,
                     EXIT_DIRECT, EXIT_SOCKS5, EXIT_BLOCK, EXIT_CLOUDFLARE_WS,
                     CATEGORY_CALLS)
from .utils import get_link_host
from .presets import FAKE_TLS_PRESETS, PRESET_LABELS

COMPOSE_FILE = os.environ.get('TGWS_COMPOSE', 'docker-compose.yml')
CONTAINER = 'tgws-proxy'

def _init_io():
    """UTF-8 output so box-drawing/emoji don't crash on legacy consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def bold(t): return _c('1', t)
def dim(t): return _c('2', t)
def green(t): return _c('32', t)
def red(t): return _c('31', t)
def yellow(t): return _c('33', t)
def cyan(t): return _c('36', t)


def clear():
    if _USE_COLOR:
        sys.stdout.write('\033[2J\033[H')
    else:
        print('\n' * 2)


def pause():
    try:
        input(dim('\n  Enter — продолжить...'))
    except EOFError:
        pass


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        val = input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return val or (default if default is not None else '')


def ask_int(prompt, default):
    while True:
        v = ask(prompt, default)
        try:
            return int(v)
        except (ValueError, TypeError):
            print(red("  нужно число"))


def ask_port(prompt, default):
    while True:
        p = ask_int(prompt, default)
        if 1 <= p <= 65535:
            return p
        print(red("  порт должен быть 1..65535"))


def confirm(prompt, default=True):
    d = 'Y/n' if default else 'y/N'
    v = ask(f"{prompt} ({d})", '').lower()
    if not v:
        return default
    return v.startswith(('y', 'д'))


# ===================== config persistence ==============================
def _config_path() -> str:
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        return sys.argv[1]
    return os.environ.get('TGWS_CONFIG', 'config.yml')


def _ensure_listeners():
    names = {l.name for l in proxy_config.mtproto_listeners}
    if 'mtproto' not in names:
        proxy_config.mtproto_listeners.append(
            MtprotoListener(name='mtproto', enabled=True, port=1443))
    if 'mtproto_faketls' not in names:
        proxy_config.mtproto_listeners.append(
            MtprotoListener(name='mtproto_faketls', enabled=True, port=1444,
                            fake_tls_domain='www.cloudflare.com'))
    for l in proxy_config.mtproto_listeners:
        if not l.secret:
            l.secret = _secrets.token_hex(16)


def _plain() -> MtprotoListener:
    return next(l for l in proxy_config.mtproto_listeners
               if l.name == 'mtproto')


def _ftls() -> MtprotoListener:
    return next(l for l in proxy_config.mtproto_listeners
               if l.name == 'mtproto_faketls')


def load(path):
    if os.path.isfile(path):
        load_yaml_config(path)
    proxy_config.ensure_routing_defaults()
    _ensure_listeners()


def _to_dict():
    pc = proxy_config
    listen = {
        'socks5': {
            'enabled': pc.socks5_enabled, 'host': pc.socks5_host,
            'port': pc.socks5_port, 'username': pc.socks5_username,
            'password': pc.socks5_password,
        }
    }
    for l in pc.mtproto_listeners:
        d = {'enabled': l.enabled, 'host': l.host, 'port': l.port,
             'secret': l.secret}
        if l.name == 'mtproto_faketls' or l.fake_tls_domain:
            d['fake_tls_domain'] = l.fake_tls_domain
        listen[l.name] = d
    exits = {}
    for name, ex in pc.exits.items():
        if ex.type == EXIT_SOCKS5:
            exits[name] = {'type': 'socks5', 'host': ex.host, 'port': ex.port,
                           'username': ex.username, 'password': ex.password,
                           'health_check': ex.health_check,
                           'health_interval': ex.health_interval}
        else:
            exits[name] = {'type': ex.type}
    return {
        'listen': listen,
        'exits': exits,
        'routes': {k: list(v) for k, v in pc.routes.items()},
        'advanced': {
            'cfproxy_fallback': pc.fallback_cfproxy,
            'cfproxy_user_domain': pc.cfproxy_user_domains,
            'cfproxy_worker_domain': pc.cfproxy_worker_domains,
            'pool_size': pc.pool_size,
            'buf_kb': pc.buffer_size // 1024,
            'verbose': pc.verbose,
            'tls_fragment': pc.tls_fragment,
            'skip_front': pc.skip_front,
        },
    }


def save(path):
    import yaml
    # Keep options managed by the web UI or added by newer versions.
    current = {}
    if os.path.isfile(path):
        with open(path, encoding='utf-8') as existing:
            current = yaml.safe_load(existing) or {}
    updated = _to_dict()
    for group in ('advanced',):
        updated[group] = {**(current.get(group) or {}), **updated[group]}
    for group in ('listen', 'exits'):
        for name, value in updated[group].items():
            previous = (current.get(group) or {}).get(name)
            if isinstance(previous, dict):
                updated[group][name] = {**previous, **value}
    current.update(updated)
    header = ("# Сгенерировано панелью (python -m proxy.menu).\n"
              "# Все опции с описанием — в config.example.yml.\n\n")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(header)
        yaml.safe_dump(current, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False)


def save_and_offer_restart(path):
    save(path)
    print(green("\n  ✓ Сохранено в " + path))
    if _service_running() and confirm("  Перезапустить службу, чтобы "
                                       "применить?", True):
        _svc('restart')


# ===================== service (docker compose) ========================
SYSTEMD_UNIT = '/etc/systemd/system/tgws.service'


def _mode() -> str:
    """Pick how the service is managed: 'systemd', 'docker', or 'none'.

    systemd wins when the tgws unit exists — that's the explicit install marker
    (a host may also have docker installed without us using it)."""
    if shutil.which('systemctl') and os.path.exists(SYSTEMD_UNIT):
        return 'systemd'
    if shutil.which('docker') and os.path.isfile(COMPOSE_FILE):
        return 'docker'
    return 'none'


def _autostart_status() -> str:
    if _mode() == 'systemd':
        r = subprocess.run(['systemctl', 'is-enabled', 'tgws'],
                           capture_output=True, text=True)
        return r.stdout.strip() or 'unknown'
    if _mode() == 'docker':
        return 'restart: unless-stopped'
    return 'n/a'


def _service_running():
    m = _mode()
    if m == 'docker':
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', CONTAINER],
            capture_output=True, text=True)
        return r.returncode == 0 and r.stdout.strip() == 'true'
    if m == 'systemd':
        r = subprocess.run(['systemctl', 'is-active', 'tgws'],
                           capture_output=True, text=True)
        return r.stdout.strip() == 'active'
    return None


def _status_line() -> str:
    st = _service_running()
    label = {'docker': 'docker', 'systemd': 'systemd'}.get(_mode(), '')
    if st is True:
        return green(f'● служба запущена ({label})')
    if st is False:
        return yellow(f'○ служба остановлена ({label})')
    return dim('— служба не обнаружена (запусти вручную: '
               'python -m proxy -c config.yml)')


def _svc(action: str) -> int:
    """Run a service action ('start'|'restart'|'stop'|'logs'|'status')."""
    m = _mode()
    if m == 'docker':
        cmd = {
            'start': ['up', '-d', '--build'],
            'restart': ['restart'],
            'stop': ['down'],
            'logs': ['logs', '-f', '--tail', '100'],
            'status': ['ps'],
        }[action]
        return subprocess.run(['docker', 'compose', '-f', COMPOSE_FILE,
                               *cmd]).returncode
    if m == 'systemd':
        cmd = {
            'start': ['systemctl', 'restart', 'tgws'],
            'restart': ['systemctl', 'restart', 'tgws'],
            'stop': ['systemctl', 'stop', 'tgws'],
            'logs': ['journalctl', '-u', 'tgws', '-f', '-n', '100'],
            'status': ['systemctl', 'status', 'tgws', '--no-pager'],
        }[action]
        return subprocess.run(cmd).returncode
    print(red("  Служба не настроена (нет docker compose и systemd-юнита).\n"
              "  Запусти вручную:  python -m proxy -c config.yml"))
    return 1


# ===================== connection info =================================
def _mtproto_link(l: MtprotoListener, host: str) -> str:
    if l.fake_tls_domain:
        dh = l.fake_tls_domain.encode('ascii').hex()
        return (f"tg://proxy?server={host}&port={l.port}"
                f"&secret=ee{l.secret}{dh}")
    return f"tg://proxy?server={host}&port={l.port}&secret=dd{l.secret}"


def show_connection_info():
    clear()
    print(bold("  ДАННЫЕ ПОДКЛЮЧЕНИЯ\n"))
    host = get_link_host(proxy_config.socks5_host) or '127.0.0.1'
    print(dim(f"  (адрес определён как {host}; для доступа извне подставь "
              "свой публичный IP/домен)\n"))

    if proxy_config.socks5_enabled:
        print(cyan("  SOCKS5  (данные + ЗВОНКИ):"))
        print(f"    адрес : {host}")
        print(f"    порт  : {proxy_config.socks5_port}")
        if proxy_config.socks5_username:
            print(f"    логин : {proxy_config.socks5_username}")
            print(f"    пароль: {proxy_config.socks5_password}")
        else:
            print("    авторизация: нет")
        print()

    for l in proxy_config.mtproto_listeners:
        if not l.enabled:
            continue
        kind = (f"Fake TLS [{l.fake_tls_domain}]" if l.fake_tls_domain
                else "обычный")
        print(cyan(f"  MTProto ({kind}, только данные):"))
        print(f"    {_mtproto_link(l, host)}")
        print()
    pause()


# ===================== submenus =======================================
def menu_socks5(path):
    while True:
        clear()
        pc = proxy_config
        auth = (f"{pc.socks5_username}:{pc.socks5_password}"
                if pc.socks5_username else dim("нет"))
        print(bold("  SOCKS5 — вход для данных и звонков\n"))
        print(f"  Состояние : {green('вкл') if pc.socks5_enabled else red('выкл')}")
        print(f"  Порт      : {pc.socks5_port}")
        print(f"  Авторизация: {auth}\n")
        print("  1) Включить / выключить")
        print("  2) Сменить порт")
        print("  3) Задать логин и пароль")
        print("  4) Убрать пароль (без авторизации)")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            pc.socks5_enabled = not pc.socks5_enabled
            save_and_offer_restart(path)
        elif ch == '2':
            pc.socks5_port = ask_port("Новый порт SOCKS5", pc.socks5_port)
            save_and_offer_restart(path)
        elif ch == '3':
            pc.socks5_username = ask("Логин", pc.socks5_username or 'tg')
            pc.socks5_password = ask("Пароль", pc.socks5_password
                                     or _secrets.token_urlsafe(8))
            save_and_offer_restart(path)
        elif ch == '4':
            pc.socks5_username = ''
            pc.socks5_password = ''
            save_and_offer_restart(path)
        elif ch == '0':
            return


def menu_mtproto_plain(path):
    l = _plain()
    while True:
        clear()
        print(bold("  MTProto — обычный (ссылка dd, без Fake TLS)\n"))
        print(f"  Состояние: {green('вкл') if l.enabled else red('выкл')}")
        print(f"  Порт     : {l.port}")
        print(f"  Секрет   : {l.secret}\n")
        print("  1) Включить / выключить")
        print("  2) Сменить порт")
        print("  3) Перегенерировать секрет")
        print("  4) Ввести секрет вручную")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            l.enabled = not l.enabled
            save_and_offer_restart(path)
        elif ch == '2':
            l.port = ask_port("Новый порт MTProto", l.port)
            save_and_offer_restart(path)
        elif ch == '3':
            l.secret = _secrets.token_hex(16)
            save_and_offer_restart(path)
        elif ch == '4':
            s = ask("Секрет (32 hex)", l.secret)
            if len(s) == 32 and all(c in '0123456789abcdefABCDEF' for c in s):
                l.secret = s.lower()
                save_and_offer_restart(path)
            else:
                print(red("  секрет должен быть 32 hex-символа"))
                pause()
        elif ch == '0':
            return


def choose_fake_tls_domain(current):
    while True:
        clear()
        print(bold("  Выбор домена Fake TLS\n"))
        print(f"  Текущий: {current or dim('не задан')}\n")
        cats = list(FAKE_TLS_PRESETS.keys())
        for i, cat in enumerate(cats, 1):
            print(f"  {i}) {PRESET_LABELS.get(cat, cat)}")
        print(f"  {len(cats)+1}) Ввести свой домен")
        print("  0) Отмена")
        ch = ask("Выбор", '0')
        if ch == '0':
            return current
        if ch == str(len(cats) + 1):
            d = ask("Домен (SNI), напр. www.example.com", current)
            return d or current
        try:
            cat = cats[int(ch) - 1]
        except (ValueError, IndexError):
            continue
        domains = FAKE_TLS_PRESETS[cat]
        clear()
        print(bold(f"  {PRESET_LABELS.get(cat, cat)}\n"))
        for i, d in enumerate(domains, 1):
            print(f"  {i}) {d}")
        print("  0) Назад")
        sel = ask("Домен", '0')
        try:
            if sel != '0':
                return domains[int(sel) - 1]
        except (ValueError, IndexError):
            pass


def menu_mtproto_faketls(path):
    l = _ftls()
    while True:
        clear()
        print(bold("  MTProto — с Fake TLS (ссылка ee, маскировка под сайт)\n"))
        print(f"  Состояние: {green('вкл') if l.enabled else red('выкл')}")
        print(f"  Порт     : {l.port}")
        print(f"  Домен SNI: {l.fake_tls_domain or dim('не задан')}")
        print(f"  Секрет   : {l.secret}\n")
        print("  1) Включить / выключить")
        print("  2) Сменить порт")
        print("  3) Выбрать домен (пресеты RU / зарубежные / свой)")
        print("  4) Перегенерировать секрет")
        print("  5) Ввести секрет вручную")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            l.enabled = not l.enabled
            save_and_offer_restart(path)
        elif ch == '2':
            l.port = ask_port("Новый порт MTProto Fake TLS", l.port)
            save_and_offer_restart(path)
        elif ch == '3':
            l.fake_tls_domain = choose_fake_tls_domain(l.fake_tls_domain)
            save_and_offer_restart(path)
        elif ch == '4':
            l.secret = _secrets.token_hex(16)
            save_and_offer_restart(path)
        elif ch == '5':
            s = ask("Секрет (32 hex)", l.secret)
            if len(s) == 32 and all(c in '0123456789abcdefABCDEF' for c in s):
                l.secret = s.lower()
                save_and_offer_restart(path)
            else:
                print(red("  секрет должен быть 32 hex-символа"))
                pause()
        elif ch == '0':
            return


def menu_calls(path):
    pc = proxy_config
    while True:
        clear()
        print(bold("  ЗВОНКИ И ВЫХОДЫ\n"))
        print(f"  Маршрут звонков: {' → '.join(pc.routes.get(CATEGORY_CALLS, []))}\n")
        print("  Выходы:")
        for name, ex in pc.exits.items():
            if ex.type == EXIT_SOCKS5:
                print(f"    {name}: VPS {ex.host}:{ex.port}")
            else:
                print(f"    {name}: {ex.type}")
        print()
        print("  1) Настроить зарубежный VPS (upstream SOCKS5) для звонков")
        print("  2) Звонки напрямую (direct)")
        print("  3) Заблокировать звонки")
        print("  4) Удалить VPS-выход")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            host = ask("IP/домен VPS", '')
            if not host:
                continue
            port = ask_port("Порт SOCKS5 на VPS", 1080)
            user = ask("Логин (пусто = без авторизации)", '')
            pwd = ask("Пароль", '') if user else ''
            pc.exits['vps'] = ExitDef('vps', EXIT_SOCKS5, host=host, port=port,
                                      username=user, password=pwd,
                                      health_check=True)
            pc.routes[CATEGORY_CALLS] = ['vps', EXIT_DIRECT]
            save_and_offer_restart(path)
        elif ch == '2':
            pc.routes[CATEGORY_CALLS] = [EXIT_DIRECT]
            save_and_offer_restart(path)
        elif ch == '3':
            pc.exits.setdefault('block', ExitDef('block', EXIT_BLOCK))
            pc.routes[CATEGORY_CALLS] = ['block']
            save_and_offer_restart(path)
        elif ch == '4':
            pc.exits.pop('vps', None)
            pc.routes[CATEGORY_CALLS] = [EXIT_DIRECT]
            save_and_offer_restart(path)
        elif ch == '0':
            return


def _uninstall_service():
    """Stop + disable + remove the systemd unit and PATH symlink (keeps files)."""
    if _mode() != 'systemd':
        print(red("  Это меню удаляет systemd-службу; сейчас режим не systemd."))
        return
    if not confirm(red("  Остановить и удалить службу tgws?"), False):
        return
    subprocess.run(['systemctl', 'stop', 'tgws'])
    subprocess.run(['systemctl', 'disable', 'tgws'])
    try:
        os.remove(SYSTEMD_UNIT)
    except OSError:
        pass
    subprocess.run(['systemctl', 'daemon-reload'])
    try:
        os.remove('/usr/local/bin/tgws')
    except OSError:
        pass
    print(green("\n  ✓ Служба остановлена и удалена."))
    print(dim("  Файлы остались. Полностью удалить:  rm -rf "
              + os.getcwd()))


def menu_service(path):
    while True:
        clear()
        print(bold("  СЛУЖБА\n"))
        print(f"  {_status_line()}   ({dim('режим: ' + _mode())})")
        print(f"  Автозапуск при загрузке: {_autostart_status()}\n")
        print("  1) Запустить / применить")
        print("  2) Перезапустить (применить настройки)")
        print("  3) Остановить")
        print("  4) Логи (Ctrl+C — выйти)")
        print("  5) Статус")
        print("  6) Автозапуск: включить / выключить")
        print("  7) Удалить службу (деинсталляция)")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            _svc('start')
            pause()
        elif ch == '2':
            _svc('restart')
            pause()
        elif ch == '3':
            _svc('stop')
            pause()
        elif ch == '4':
            try:
                _svc('logs')
            except KeyboardInterrupt:
                pass
        elif ch == '5':
            _svc('status')
            pause()
        elif ch == '6':
            if _mode() == 'systemd':
                cur = _autostart_status()
                action = 'disable' if cur == 'enabled' else 'enable'
                subprocess.run(['systemctl', action, 'tgws'])
                print(green(f"\n  автозапуск -> {action}d"))
            else:
                print(dim("  Управление автозапуском доступно для systemd."))
            pause()
        elif ch == '7':
            _uninstall_service()
            pause()
        elif ch == '0':
            return


def menu_advanced(path):
    pc = proxy_config
    while True:
        clear()
        print(bold("  РАСШИРЕННЫЕ\n"))
        print(f"  1) Cloudflare-fallback для данных: "
              f"{green('вкл') if pc.fallback_cfproxy else red('выкл')}")
        print(f"  2) Подробный лог (verbose): "
              f"{green('вкл') if pc.verbose else red('выкл')}")
        print(f"  3) Размер пула WS: {pc.pool_size}")
        print(f"  4) Буфер сокета: {pc.buffer_size // 1024} КБ")
        print(f"  5) Cloudflare Worker домен (РФ, без VPS): "
              f"{', '.join(pc.cfproxy_worker_domains) or dim('—')}")
        print(f"  6) Фрагментация TLS ClientHello (обход DPI): "
              f"{green('вкл') if pc.tls_fragment else red('выкл')}")
        print("  0) Назад")
        ch = ask("Выбор", '0')
        if ch == '1':
            pc.fallback_cfproxy = not pc.fallback_cfproxy
            save_and_offer_restart(path)
        elif ch == '2':
            pc.verbose = not pc.verbose
            save_and_offer_restart(path)
        elif ch == '3':
            pc.pool_size = max(0, ask_int("Размер пула", pc.pool_size))
            save_and_offer_restart(path)
        elif ch == '4':
            pc.buffer_size = max(4, ask_int("Буфер, КБ",
                                            pc.buffer_size // 1024)) * 1024
            save_and_offer_restart(path)
        elif ch == '5':
            print(dim("  Деплой воркера: docs/CfWorker.md. Вставь домен вида"
                      " xxx.workers.dev. Несколько — через пробел."))
            val = ask("Worker-домен(ы) (пусто — очистить)",
                      ' '.join(pc.cfproxy_worker_domains))
            pc.cfproxy_worker_domains = [
                d.strip() for d in val.replace(',', ' ').split() if d.strip()]
            save_and_offer_restart(path)
        elif ch == '6':
            pc.tls_fragment = not pc.tls_fragment
            save_and_offer_restart(path)
        elif ch == '0':
            return


def main_menu(path):
    while True:
        clear()
        plain, ftls = _plain(), _ftls()
        print(bold(cyan("  ╔════════════════════════════════════════════╗")))
        print(bold(cyan("  ║      TG WS / SOCKS5 Proxy — панель          ║")))
        print(bold(cyan("  ╚════════════════════════════════════════════╝")))
        print(f"   {_status_line()}")
        s5 = (green(f"вкл :{proxy_config.socks5_port}")
              if proxy_config.socks5_enabled else red("выкл"))
        mp = (green(f"вкл :{plain.port}") if plain.enabled else red("выкл"))
        mf = (green(f"вкл :{ftls.port}") if ftls.enabled else red("выкл"))
        print(f"   SOCKS5 {s5}   MTProto {mp}   MTProto+FakeTLS {mf}\n")
        print("   1) Данные подключения (ссылки / реквизиты)")
        print("   2) SOCKS5 — порт, логин/пароль")
        print("   3) MTProto обычный — порт, секрет")
        print("   4) MTProto + Fake TLS — порт, домен (пресеты)")
        print("   5) Звонки и выходы (VPS)")
        print("   6) Служба (старт / рестарт / логи)")
        print("   7) Расширенные")
        print("   8) Веб-панель (адрес / пароль / служба / порт)")
        print("   0) Выход")
        ch = ask("Выбор", '0')
        if ch == '1':
            show_connection_info()
        elif ch == '2':
            menu_socks5(path)
        elif ch == '3':
            menu_mtproto_plain(path)
        elif ch == '4':
            menu_mtproto_faketls(path)
        elif ch == '5':
            menu_calls(path)
        elif ch == '6':
            menu_service(path)
        elif ch == '7':
            menu_advanced(path)
        elif ch == '8':
            from .webmenu import main as web_menu
            web_menu()
        elif ch == '0':
            return


def main():
    _init_io()
    path = _config_path()
    try:
        load(path)
    except Exception as exc:
        print(red(f"Не удалось загрузить {path}: {exc}"))
        sys.exit(1)
    if not os.path.isfile(path):
        save(path)
        print(green(f"Создан новый {path} со значениями по умолчанию."))
    try:
        main_menu(path)
    except (KeyboardInterrupt, EOFError):
        print()
    print(dim("Пока."))


if __name__ == '__main__':
    if __package__ in (None, ''):
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _root not in sys.path:
            sys.path.insert(0, _root)
        __package__ = 'proxy'
    main()
