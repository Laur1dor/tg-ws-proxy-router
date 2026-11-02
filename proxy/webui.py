"""Small LAN-only HTTPS administration UI. No additional dependencies."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode

import yaml

ROOT = Path(__file__).resolve().parent.parent
LAN = tuple(ipaddress.ip_network(n) for n in ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
CATEGORIES = ('data', 'calls', 'bot_api', 'other')


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    temp = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600_000).hex()


def private_address(value):
    try:
        address = ipaddress.ip_address(value)
        return any(address in network for network in LAN)
    except ValueError:
        return False


def validated_update(original, request, admin_port):
    data = copy.deepcopy(original)
    if not isinstance(request, dict) or set(request) - {'listen', 'advanced', 'routes', 'revision'}:
        raise ValueError('Недопустимые поля настроек')
    listeners = data.setdefault('listen', {})
    for name, patch in request.get('listen', {}).items():
        if name not in ('socks5', 'mtproto', 'mtproto_faketls') or not isinstance(patch, dict):
            raise ValueError('Неизвестный вход')
        allowed = {'enabled', 'port', 'username', 'password'} if name == 'socks5' else {'enabled', 'port', 'secret', 'fake_tls_domain'}
        if set(patch) - allowed:
            raise ValueError('Недопустимое поле входа')
        target = listeners.setdefault(name, {})
        for key, value in patch.items():
            if key == 'enabled' and type(value) is not bool:
                raise ValueError('enabled должен быть логическим')
            if key == 'port' and (type(value) is not int or not 1 <= value <= 65535 or value == admin_port):
                raise ValueError('Недопустимый порт')
            if key in ('username', 'password', 'secret', 'fake_tls_domain'):
                if not isinstance(value, str) or len(value) > 255 or any(ord(c) < 32 for c in value):
                    raise ValueError('Недопустимая строка')
                if key in ('password', 'secret') and not value:
                    continue  # Empty form fields preserve existing credentials.
                if key == 'secret' and not re.fullmatch('[0-9a-fA-F]{32}', value):
                    raise ValueError('Секрет MTProto: 32 шестнадцатеричных символа')
                if key == 'fake_tls_domain' and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', value):
                    raise ValueError('Недопустимое имя FakeTLS')
            target[key] = value
    ports = [v.get('port') for v in listeners.values() if isinstance(v, dict) and v.get('enabled', True)]
    if not ports or len(ports) != len(set(ports)):
        raise ValueError('Нужен хотя бы один вход, порты включённых входов должны отличаться')
    if listeners.get('socks5', {}).get('username') and not listeners.get('socks5', {}).get('password'):
        raise ValueError('Для логина SOCKS5 нужен пароль')
    advanced = data.setdefault('advanced', {})
    for key, value in request.get('advanced', {}).items():
        if key == 'cfproxy_worker_domain':
            if not isinstance(value, list) or len(value) > 8 or any(not isinstance(v, str) or len(v) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', v) for v in value):
                raise ValueError('Worker: список имён хостов без схемы и пути')
        elif key in ('cfproxy_fallback', 'skip_front', 'tls_fragment'):
            if type(value) is not bool:
                raise ValueError('Недопустимое логическое значение')
        elif key == 'pool_size':
            if type(value) is not int or not 0 <= value <= 32:
                raise ValueError('Размер пула: 0–32')
        else:
            raise ValueError('Неизвестная расширенная настройка')
        advanced[key] = value
    for category, route in request.get('routes', {}).items():
        if category not in CATEGORIES or not isinstance(route, list) or not route or len(route) > 16 or any(not isinstance(n, str) or n not in data.get('exits', {}) for n in route):
            raise ValueError('Маршрут должен содержать имена существующих выходов')
        data.setdefault('routes', {})[category] = route
    return data


class Application:
    def __init__(self, state):
        self.state = Path(state)
        self.options = json.loads((self.state / 'settings.json').read_text())
        self.config = Path(self.options['config'])
        self.lock = threading.Lock()
        self.sessions = {}
        self.failures = {}

    def auth(self):
        return json.loads((self.state / 'auth.json').read_text())

    def read(self):
        raw = self.config.read_bytes()
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError('Конфиг должен быть YAML mapping')
        return raw, data, hashlib.sha256(raw).hexdigest()

    def command(self, *args):
        return subprocess.run(args, capture_output=True, text=True, timeout=20)

    def running(self):
        return self.command('systemctl', 'is-active', 'tgws.service').returncode == 0

    def ready(self):
        time.sleep(0.4)
        _, data, _ = self.read()
        for _ in range(12):
            try:
                if self.running():
                    for item in data.get('listen', {}).values():
                        if item.get('enabled', True):
                            host = item.get('host', '0.0.0.0')
                            with socket.create_connection(('127.0.0.1' if host == '0.0.0.0' else host, item['port']), timeout=0.15):
                                pass
                    return True
            except OSError:
                pass
            time.sleep(0.2)
        return False

    def status(self):
        _, data, revision = self.read()
        public = copy.deepcopy(data)
        for value in public.get('listen', {}).values():
            if isinstance(value, dict):
                for key in ('password', 'secret'):
                    if key in value:
                        value[key + '_set'] = bool(value.pop(key))
        public['exits'] = {name: {'type': item.get('type', '')} for name, item in data.get('exits', {}).items()}
        return dict(config=public, revision=revision, active=self.running(),
                    backups=[p.name for p in sorted((self.state / 'backups').glob('*.yml'), reverse=True)][:20])

    def links(self, host):
        if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('Укажи IP или DNS-имя своего прокси без порта')
        _, data, _ = self.read()
        links = []
        for name, listener in data.get('listen', {}).items():
            if not listener.get('enabled', True):
                continue
            fields = dict(server=host, port=listener['port'])
            if name == 'socks5':
                fields.update(user=listener.get('username', ''), **{'pass': listener.get('password', '')})
                url = 'tg://socks?' + urlencode(fields)
            else:
                secret = listener.get('secret', '')
                if not secret:
                    continue
                domain = listener.get('fake_tls_domain', '')
                fields['secret'] = ('ee' + secret + domain.encode().hex()) if domain else 'dd' + secret
                url = 'tg://proxy?' + urlencode(fields)
            links.append(dict(name=name, url=url))
        return links

    def apply(self, request, restore=None):
        with self.lock:
            raw, data, revision = self.read()
            if request.get('revision') != revision:
                raise ValueError('Настройки изменились. Обнови страницу перед сохранением')
            if restore is not None:
                if not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{12}\.yml', restore):
                    raise ValueError('Недопустимая резервная копия')
                new_raw = (self.state / 'backups' / restore).read_bytes()
                if not isinstance(yaml.safe_load(new_raw), dict):
                    raise ValueError('Некорректная резервная копия')
            else:
                new = validated_update(data, request, self.options['port'])
                if new == data:
                    return 'Изменений нет; TGWS не перезапускался'
                new_raw = yaml.safe_dump(new, allow_unicode=True, sort_keys=False).encode()
            backup = self.state / 'backups' / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S-') + revision[:12] + '.yml')
            atomic_write(backup, raw)
            atomic_write(self.config, new_raw)
            try:
                if self.command('systemctl', 'restart', 'tgws.service').returncode or not self.ready():
                    raise RuntimeError('TGWS не запустился')
            except Exception:
                atomic_write(self.config, raw)
                try:
                    recovered = self.command('systemctl', 'restart', 'tgws.service').returncode == 0 and self.ready()
                except subprocess.SubprocessError:
                    recovered = False
                if not recovered:
                    raise ValueError('Прежний конфиг восстановлен; TGWS требует проверки в консоли')
                raise ValueError('Применение не удалось; прежний конфиг восстановлен')
            for old in sorted((self.state / 'backups').glob('*.yml'), reverse=True)[20:]:
                old.unlink()
            return 'Настройки применены; перезапущен только TGWS'

    def logs(self):
        text = self.command('journalctl', '-u', 'tgws.service', '-n', '60', '--no-pager', '-o', 'cat').stdout
        _, data, _ = self.read()
        def redact(value):
            nonlocal text
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('password', 'secret') and isinstance(item, str) and item:
                        text = text.replace(item, '[скрыто]')
                    else:
                        redact(item)
            elif isinstance(value, list):
                for item in value:
                    redact(item)
        redact(data)
        return re.sub(r'(?i)(secret=|password=|pass=)[^\s&]+', r'\1[скрыто]', text)[-24000:]


class AdminServer(ThreadingHTTPServer):
    def __init__(self, address, handler, context=None):
        self.context = context
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        if self.context:
            connection = self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
        return connection, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'TGWS'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, fmt, *args):
        # Never log request URLs, bodies, cookies or credentials.
        pass

    def reply(self, code, data, kind='application/json; charset=utf-8', cookie=None):
        content = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        for name, value in [('Content-Type', kind), ('Content-Length', str(len(content))), ('Cache-Control', 'no-store'),
                            ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Referrer-Policy', 'no-referrer'),
                            ('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]:
            self.send_header(name, value)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(content)

    def session(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookie['tgws_session'].value
            with self.server.app.lock:
                item = self.server.app.sessions.get(token)
            if item and item['expires'] > time.monotonic() and item['version'] == self.server.app.auth()['salt']:
                return item
        except (KeyError, ValueError):
            pass
        return None

    def handle_request(self, post):
        app = self.server.app
        expected = f"{app.options['bind']}:{app.options['port']}"
        if not private_address(self.client_address[0]) or self.headers.get('Host') != expected:
            return self.reply(403, dict(error='Панель доступна только из локальной сети по настроенному адресу'))
        if not post and self.path == '/':
            return self.reply(200, (ROOT / 'proxy/webui.html').read_bytes(), 'text/html; charset=utf-8')
        body = {}
        if post:
            if self.headers.get('Origin') != 'https://' + expected or self.headers.get('Content-Type') != 'application/json':
                return self.reply(403, dict(error='Недопустимый источник запроса'))
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 32768:
                return self.reply(413, dict(error='Размер запроса превышен'))
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError('Ожидается JSON object')
        if post and self.path == '/api/login':
            now = time.monotonic()
            ip = self.client_address[0]
            with app.lock:
                app.failures = {key: [t for t in values if now-t < 60] for key, values in app.failures.items() if any(now-t < 60 for t in values)}
                attempts = app.failures.setdefault(ip, [])
                if len(attempts) >= 5:
                    return self.reply(429, dict(error='Подожди минуту перед следующей попыткой'))
                attempts.append(now)
            auth = app.auth()
            username, password = body.get('username', ''), body.get('password', '')
            if not isinstance(username, str) or not isinstance(password, str) or len(password) > 256:
                return self.reply(401, dict(error='Неверный логин или пароль'))
            if not (hmac.compare_digest(username.encode(), auth['username'].encode()) and hmac.compare_digest(password_hash(password, auth['salt']), auth['hash'])):
                return self.reply(401, dict(error='Неверный логин или пароль'))
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with app.lock:
                app.sessions = {key: value for key, value in app.sessions.items() if value['expires'] > now}
                if len(app.sessions) >= 128:
                    app.sessions.pop(next(iter(app.sessions)))
                app.sessions[token] = dict(csrf=csrf, expires=now+1800, version=auth['salt'])
                app.failures.pop(ip, None)
            return self.reply(200, dict(csrf=csrf), cookie=f'tgws_session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800')
        session = self.session()
        if not session:
            return self.reply(401, dict(error='Нужен вход'))
        if post and not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
            return self.reply(403, dict(error='Неверный CSRF token'))
        if not post and self.path == '/api/status':
            return self.reply(200, dict(**app.status(), csrf=session['csrf']))
        if not post and self.path == '/api/logs':
            return self.reply(200, dict(log=app.logs()))
        if post and self.path == '/api/links':
            return self.reply(200, dict(links=app.links(body.get('host'))))
        if post and self.path == '/api/apply':
            return self.reply(200, dict(message=app.apply(body)))
        if post and self.path == '/api/restore':
            return self.reply(200, dict(message=app.apply(body, restore=body.get('backup', ''))))
        if post and self.path == '/api/restart':
            with app.lock:
                ok = app.command('systemctl', 'restart', 'tgws.service').returncode == 0 and app.ready()
            return self.reply(200 if ok else 500, dict(message='TGWS перезапущен' if ok else 'Ошибка перезапуска'))
        if post and self.path == '/api/logout':
            with app.lock:
                app.sessions = {k: v for k, v in app.sessions.items() if v is not session}
            return self.reply(200, dict(message='Выход'), cookie='tgws_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0')
        return self.reply(404, dict(error='Не найдено'))

    def dispatch(self, post):
        try:
            self.handle_request(post)
        except (ValueError, TypeError, KeyError, AttributeError):
            self.reply(400, dict(error='Некорректный запрос или параметры настроек'))
        except (OSError, subprocess.SubprocessError, yaml.YAMLError):
            self.reply(500, dict(error='Операция не выполнена; проверь журнал службы на хосте'))

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)


def reset_password(state, username=None, password=None):
    current = json.loads((state/'auth.json').read_text()) if (state/'auth.json').exists() else {}
    username = username or current.get('username', 'admin')
    password = password or secrets.token_urlsafe(18)
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username) or not 12 <= len(password) <= 256:
        raise ValueError('Логин: 1–64 латинских символа; пароль: 12–256 символов')
    auth = dict(username=username, salt=secrets.token_hex(16))
    auth['hash'] = password_hash(password, auth['salt'])
    atomic_write(state / 'auth.json', json.dumps(auth).encode())
    print('Login: ' + username + '\nPassword: ' + password)


def main():
    parser = argparse.ArgumentParser(description='TGWS LAN HTTPS panel')
    parser.add_argument('action', choices=['init', 'serve', 'info', 'reset-password'])
    parser.add_argument('--state', type=Path, default=ROOT/'webui-state')
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--config', type=Path, default=ROOT/'config.yml')
    args = parser.parse_args()
    state = args.state.resolve()
    if args.action == 'init':
        if not private_address(args.bind) or not 1024 <= args.port <= 65535:
            parser.error('Требуется адрес LAN/loopback и порт 1024–65535')
        if (state/'settings.json').exists():
            parser.error('Панель уже настроена; используй info или reset-password')
        if not args.config.is_file():
            parser.error('Конфиг TGWS не найден')
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        (state/'backups').mkdir(mode=0o700, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TGWS LAN panel')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
                .not_valid_after(now+dt.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(args.bind))]), critical=False)
                .sign(key, hashes.SHA256()))
        atomic_write(state/'key.pem', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        atomic_write(state/'cert.pem', cert.public_bytes(serialization.Encoding.PEM))
        atomic_write(state/'settings.json', json.dumps(dict(bind=args.bind, port=args.port, config=str(args.config.resolve()))).encode())
        reset_password(state)
    if args.action == 'reset-password':
        reset_password(state)
    options = json.loads((state/'settings.json').read_text())
    if args.action != 'serve':
        print(f"URL: https://{options['bind']}:{options['port']}/")
        return
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(state/'cert.pem', state/'key.pem')
    server = AdminServer((options['bind'], options['port']), Handler, context)
    server.app = Application(state)
    print(f"TGWS HTTPS panel listening on {options['bind']}:{options['port']}", flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
