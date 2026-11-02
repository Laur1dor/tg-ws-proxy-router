"""Offline web administration tests. All writes use temporary directories."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import yaml
from proxy.webui import Application, Handler, AdminServer, atomic_write, password_hash, private_address, validated_update


CONFIG = dict(listen=dict(socks5=dict(enabled=True, host='0.0.0.0', port=1080, username='', password='private-socks-test'),
                          mtproto=dict(enabled=True, host='0.0.0.0', port=2443, secret='ab'*16)),
              exits=dict(cf_ws=dict(type='cloudflare_ws'), direct=dict(type='direct'),
                         private=dict(type='socks5', host='example.invalid', password='private-exit-test')),
              routes=dict(data=['cf_ws', 'direct'], calls=['direct']),
              advanced=dict(skip_front=True, dc_ip=['2:149.154.167.51'], custom_option='keep'))


class ConfigTests(unittest.TestCase):
    def test_tui_save_keeps_options_and_skip_front(self):
        from proxy import menu
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'config.yml'
            path.write_text(yaml.safe_dump(CONFIG))
            updated = copy.deepcopy(CONFIG)
            updated['advanced'] = dict(skip_front=True, pool_size=0)
            with patch.object(menu, '_to_dict', return_value=updated):
                menu.save(path)
            self.assertEqual(yaml.safe_load(path.read_text())['advanced']['dc_ip'], CONFIG['advanced']['dc_ip'])
            self.assertTrue(yaml.safe_load(path.read_text())['advanced']['skip_front'])
        with patch.object(menu.proxy_config, 'skip_front', True):
            self.assertTrue(menu._to_dict()['advanced']['skip_front'])

    def test_patch_preserves_secrets_and_unknown_fields(self):
        updated = validated_update(CONFIG, dict(listen=dict(mtproto=dict(secret='')), advanced=dict(pool_size=0)), 8766)
        self.assertEqual(updated['listen'], CONFIG['listen'])
        self.assertEqual(updated['advanced']['dc_ip'], CONFIG['advanced']['dc_ip'])
        self.assertEqual(updated['advanced']['custom_option'], 'keep')
        self.assertEqual(updated['exits'], CONFIG['exits'])

    def test_rejects_reserved_duplicate_ports_routes_and_url(self):
        for request in [dict(listen=dict(socks5=dict(port=8766))), dict(listen=dict(socks5=dict(port=2443))),
                        dict(routes=dict(data=['missing'])), dict(advanced=dict(cfproxy_worker_domain=['https://bad/path'])),
                        dict(listen=dict(mtproto=dict(secret='bad'))), dict(exits={})]:
            with self.subTest(request=request), self.assertRaises(ValueError):
                validated_update(CONFIG, request, 8766)

    def test_only_private_bind_addresses(self):
        self.assertTrue(private_address('192.168.1.103'))
        self.assertTrue(private_address('127.0.0.1'))
        for address in ['0.0.0.0', '8.8.8.8', '100.64.1.1', '::', 'invalid']:
            self.assertFalse(private_address(address))


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        (self.state/'backups').mkdir()
        self.config = self.state/'config.yml'
        self.config.write_text(yaml.safe_dump(CONFIG))
        self.original = self.config.read_bytes()
        self.password = secrets.token_urlsafe(24)
        self.auth = dict(username='admin', salt=secrets.token_hex(16))
        self.auth['hash'] = password_hash(self.password, self.auth['salt'])
        atomic_write(self.state/'auth.json', json.dumps(self.auth).encode())
        (self.state/'settings.json').write_text(json.dumps(dict(config=str(self.config), bind='127.0.0.1', port=8766)))
        self.app = Application(self.state)
        self.command = patch.object(self.app, 'command', return_value=subprocess.CompletedProcess([], 0, 'active\n', ''))
        self.command.start()
        self.server = AdminServer(('127.0.0.1', 0), Handler)
        self.app.options['port'] = self.server.server_port
        self.server.app = self.app
        self.host = '127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ''
        self.csrf = ''

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.command.stop()
        self.temp.cleanup()

    def request(self, path, body=None, origin=True, csrf=True, host=None):
        headers = {'Host': host or self.host, 'Cookie': self.cookie}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            if origin:
                headers['Origin'] = 'https://' + self.host
            if csrf:
                headers['X-CSRF-Token'] = self.csrf
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('POST' if body is not None else 'GET', path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        content = response.read().decode()
        cookie = response.getheader('Set-Cookie')
        result = (response.status, json.loads(content), cookie)
        connection.close()
        return result

    def login(self):
        code, data, cookie = self.request('/api/login', dict(username='admin', password=self.password))
        self.assertEqual(code, 200)
        self.assertIn('Secure; HttpOnly; SameSite=Strict', cookie)
        self.cookie = cookie.split(';')[0]
        self.csrf = data['csrf']

    def test_auth_origin_csrf_and_host(self):
        self.assertEqual(self.request('/api/status')[0], 401)
        self.assertEqual(self.request('/api/login', {}, origin=False)[0], 403)
        self.assertEqual(self.request('/api/status', host='attacker.invalid')[0], 403)
        self.login()
        self.assertEqual(self.request('/api/restart', {}, csrf=False)[0], 403)

    def test_status_redacts_secrets_links_require_login(self):
        self.assertEqual(self.request('/api/links', dict(host='example.invalid'))[0], 401)
        self.login()
        code, data, _ = self.request('/api/status')
        self.assertEqual(code, 200)
        for secret in ['ab'*16, 'private-exit-test', 'private-socks-test']:
            self.assertNotIn(secret, json.dumps(data))
        self.assertEqual(self.request('/api/links', dict(host='example.invalid'))[0], 200)

    def test_password_reset_invalidates_existing_session(self):
        self.login()
        new_auth = dict(self.auth, salt=secrets.token_hex(16))
        atomic_write(self.state/'auth.json', json.dumps(new_auth).encode())
        self.assertEqual(self.request('/api/status')[0], 401)

    def test_stale_write_does_not_change_config(self):
        self.login()
        self.assertEqual(self.request('/api/apply', dict(revision='stale', advanced=dict(pool_size=0)))[0], 400)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_failed_restart_restores_exact_config(self):
        revision = hashlib.sha256(self.original).hexdigest()
        with patch.object(self.app, 'ready', side_effect=[False, True]):
            with self.assertRaisesRegex(ValueError, 'прежний конфиг восстановлен'):
                self.app.apply(dict(revision=revision, advanced=dict(pool_size=0)))
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_save_and_restore_preserve_unknown_fields(self):
        revision = hashlib.sha256(self.original).hexdigest()
        with patch.object(self.app, 'ready', return_value=True):
            self.app.apply(dict(revision=revision, advanced=dict(pool_size=0)))
            data = yaml.safe_load(self.config.read_bytes())
            self.assertEqual(data['advanced']['custom_option'], 'keep')
            self.assertEqual(data['listen'], CONFIG['listen'])
            backup = next((self.state/'backups').glob('*.yml')).name
            self.app.apply(dict(revision=hashlib.sha256(self.config.read_bytes()).hexdigest()), restore=backup)
        self.assertEqual(self.config.read_bytes(), self.original)


if __name__ == '__main__':
    unittest.main()
