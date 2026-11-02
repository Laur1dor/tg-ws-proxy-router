"""Console lifecycle/settings menu for the optional HTTPS web panel."""
import getpass
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

from . import menu
from .webui import ROOT, atomic_write, reset_password

STATE = ROOT / 'webui-state'
UNIT = Path('/etc/systemd/system/tgws-web.service')


def service(action):
    if action not in ('start', 'stop', 'restart', 'enable', 'disable', 'is-active', 'is-enabled'):
        raise ValueError('Неизвестная операция')
    return subprocess.run(['systemctl', action, 'tgws-web.service'], capture_output=True, text=True, timeout=20)


def show_info(state=STATE):
    options = json.loads((state/'settings.json').read_text())
    auth = json.loads((state/'auth.json').read_text())
    print(f"\n  URL: https://{options['bind']}:{options['port']}/")
    print('  Логин: ' + auth['username'])
    print('  Пароль хранится в виде хэша. Новый выдаётся пунктом 7.')
    print('  Прямой сброс: tgws web reset-password\n')


def web_ready(state, options):
    context = ssl.create_default_context(cafile=str(state/'cert.pem'))
    for _ in range(15):
        try:
            with socket.create_connection((options['bind'], options['port']), timeout=0.3) as tcp:
                with context.wrap_socket(tcp, server_hostname=options['bind']):
                    return True
        except OSError:
            time.sleep(0.2)
    return False


def change_port(state, port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Порт должен быть от 1024 до 65535')
    raw = (state/'settings.json').read_bytes()
    options = json.loads(raw)
    if port == options['port']:
        return 'Порт уже установлен; перезапуск не требуется'
    # Check availability before touching the settings or running panel.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((options['bind'], port))
    active = service('is-active').returncode == 0
    updated = dict(options, port=port)
    atomic_write(state/'settings.previous.json', raw)
    atomic_write(state/'settings.json', json.dumps(updated).encode())
    if active:
        try:
            if service('restart').returncode or not web_ready(state, updated):
                raise ValueError('Новый адрес не отвечает')
        except (OSError, ValueError, subprocess.SubprocessError):
            atomic_write(state/'settings.json', raw)
            recovered = service('restart').returncode == 0 and web_ready(state, options)
            raise ValueError('Порт восстановлен; ' + ('панель работает' if recovered else 'проверь службу tgws-web в консоли'))
    return f"Адрес панели: https://{options['bind']}:{port}/"


def initialize(state=STATE):
    if state != STATE:
        raise ValueError('Первичная установка доступна только для стандартного каталога')
    if (state/'settings.json').exists():
        raise ValueError('Панель уже настроена')
    address = menu.ask('LAN-адрес панели (только локальный IP)', '127.0.0.1')
    port = menu.ask_port('Порт HTTPS (1024–65535)', 8766)
    result = subprocess.run([sys.executable, '-m', 'proxy.webui', 'init', '--bind', address, '--port', str(port)], cwd=ROOT)
    if result.returncode:
        raise ValueError('Настройка не завершена')
    atomic_write(UNIT, (ROOT/'deploy/tgws-web.service').read_text().replace('__APP_DIR__', str(ROOT)).encode(), 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=20)
    if service('enable').returncode or service('start').returncode:
        raise ValueError('Настройки сохранены, но службу нужно проверить')
    show_info(state)


def main(state=STATE):
    menu._init_io()
    if os.geteuid() != 0:
        print(menu.red('Для управления панелью запусти tgws под root (sudo).'))
        return
    try:
        while True:
            menu.clear()
            print(menu.bold(menu.cyan('  TGWS — управление веб-панелью')))
            configured = (state/'settings.json').exists()
            if configured:
                active = service('is-active').returncode == 0
                enabled = service('is-enabled').returncode == 0
                print(f"  Служба: {'работает' if active else 'остановлена'} | Автозапуск: {'вкл' if enabled else 'выкл'}")
                options = json.loads((state/'settings.json').read_text())
                print(f"  https://{options['bind']}:{options['port']}/\n")
            else:
                print('  Веб-панель ещё не настроена. Начни с пункта 9.\n')
            print('  1) Адрес и логин панели')
            print('  2) Запустить веб-панель')
            print('  3) Остановить веб-панель')
            print('  4) Перезапустить веб-панель')
            print('  5) Включить / выключить автозапуск')
            print('  6) Изменить порт HTTPS')
            print('  7) Сменить логин / выдать новый пароль')
            print('  8) Журнал веб-панели')
            print('  9) Первичная настройка веб-панели')
            print('  0) Назад')
            choice = menu.ask('Выбор', '0')
            if choice == '0':
                return
            try:
                if choice == '9':
                    initialize(state)
                elif not configured:
                    print('Сначала настрой веб-панель пунктом 9.')
                elif choice == '1':
                    show_info(state)
                elif choice in ('2', '3', '4'):
                    action = {'2':'start', '3':'stop', '4':'restart'}[choice]
                    if choice == '2' or menu.confirm('Это затронет только веб-панель. Продолжить?'):
                        result = service(action)
                        print('Выполнено.' if not result.returncode else result.stderr)
                elif choice == '5':
                    result = service('disable' if enabled else 'enable')
                    print('Автозапуск изменён.' if not result.returncode else result.stderr)
                elif choice == '6':
                    port = menu.ask_port('Новый порт HTTPS', options['port'])
                    print(change_port(state, port))
                elif choice == '7':
                    auth = json.loads((state/'auth.json').read_text())
                    username = menu.ask('Логин администратора', auth['username'])
                    password = getpass.getpass('  Новый пароль (от 12 символов; Enter — случайный): ')
                    if password and password != getpass.getpass('  Повтори пароль: '):
                        raise ValueError('Пароли не совпали')
                    if menu.confirm('Сменить реквизиты и завершить прежние веб-сессии?'):
                        reset_password(state, username=username, password=password or None)
                        print('Сохрани новые реквизиты. Прокси не перезапускался.')
                elif choice == '8':
                    subprocess.run(['journalctl', '-u', 'tgws-web.service', '-n', '50', '--no-pager'], timeout=20)
                else:
                    continue
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                print(menu.red(str(exc)))
            menu.pause()
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == '__main__':
    main()
