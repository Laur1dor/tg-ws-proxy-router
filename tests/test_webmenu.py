import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from proxy import webmenu
from proxy.webui import reset_password, password_hash


class ConsolePanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.raw = json.dumps(dict(bind='127.0.0.1', port=8766, config='/private/config.yml')).encode()
        (self.state/'settings.json').write_bytes(self.raw)
        with contextlib.redirect_stdout(io.StringIO()):
            reset_password(self.state, username='owner', password='temporary-test-password')

    def test_password_reset_preserves_username_and_revokes_salt(self):
        before = json.loads((self.state/'auth.json').read_text())
        with contextlib.redirect_stdout(io.StringIO()) as output:
            reset_password(self.state)
        after = json.loads((self.state/'auth.json').read_text())
        self.assertEqual(after['username'], 'owner')
        self.assertNotEqual(before['salt'], after['salt'])
        password = output.getvalue().split('Password: ')[1].strip()
        self.assertEqual(after['hash'], password_hash(password, after['salt']))

    def test_same_port_does_not_restart(self):
        with patch.object(webmenu, 'service') as service:
            webmenu.change_port(self.state, 8766)
        service.assert_not_called()

    def test_port_failure_restores_settings(self):
        success = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(webmenu.socket, 'socket'), patch.object(webmenu, 'service', return_value=success) as service, \
                patch.object(webmenu, 'web_ready', side_effect=[False, True]):
            with self.assertRaisesRegex(ValueError, 'Порт восстановлен'):
                webmenu.change_port(self.state, 8767)
        self.assertEqual((self.state/'settings.json').read_bytes(), self.raw)
        self.assertEqual([call.args[0] for call in service.call_args_list], ['is-active', 'restart', 'restart'])

    def test_inactive_panel_port_changes_without_start(self):
        with patch.object(webmenu.socket, 'socket'), \
                patch.object(webmenu, 'service', return_value=subprocess.CompletedProcess([], 3, '', '')) as service:
            webmenu.change_port(self.state, 8767)
        self.assertEqual(json.loads((self.state/'settings.json').read_text())['port'], 8767)
        self.assertEqual(service.call_count, 1)

    def test_info_menu_only_reads_credentials(self):
        original = (self.state/'auth.json').read_bytes()
        with patch.object(webmenu.os, 'geteuid', return_value=0), \
                patch.object(webmenu, 'service', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                patch.object(webmenu.menu, 'ask', side_effect=['1', '0']), \
                patch.object(webmenu.menu, 'pause'), contextlib.redirect_stdout(io.StringIO()) as output:
            webmenu.main(self.state)
        self.assertIn('https://127.0.0.1:8766/', output.getvalue())
        self.assertIn('owner', output.getvalue())
        self.assertEqual((self.state/'auth.json').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
