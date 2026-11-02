"""Offline regression tests: verified TLS and Worker before public CF fallback."""
import asyncio
import ssl
import unittest
from unittest.mock import AsyncMock, patch

from proxy import exits
from proxy.config import proxy_config
from proxy.raw_websocket import _ssl_ctx


class WorkerRouteTests(unittest.IsolatedAsyncioTestCase):
    def test_tls_verifies_certificate_and_hostname(self):
        self.assertEqual(_ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(_ssl_ctx.check_hostname)

    async def test_worker_precedes_public_pool(self):
        ws = object()
        with patch.object(proxy_config, 'skip_front', True), \
                patch.object(proxy_config, 'cfproxy_worker_domains', ['relay.example.workers.dev']), \
                patch.object(proxy_config, 'fallback_cfproxy', True), \
                patch.object(exits.RawWebSocket, 'connect', AsyncMock(return_value=ws)) as connect, \
                patch.object(exits.balancer, 'get_domains_for_dc') as pool:
            self.assertIs(await exits.open_cloudflare_ws(2, False), ws)
            self.assertEqual(connect.await_args.args[:2],
                             ('relay.example.workers.dev', 'relay.example.workers.dev'))
            self.assertIn('dst=149.154.167.51', connect.await_args.kwargs['path'])
            pool.assert_not_called()

    async def test_worker_failure_uses_public_pool(self):
        ws = object()
        with patch.object(proxy_config, 'skip_front', True), \
                patch.object(proxy_config, 'cfproxy_worker_domains', ['relay.example.workers.dev']), \
                patch.object(proxy_config, 'fallback_cfproxy', True), \
                patch.object(exits.RawWebSocket, 'connect', AsyncMock(side_effect=[OSError('unreachable'), ws])) as connect, \
                patch.object(exits.balancer, 'get_domains_for_dc', return_value=['pool.example']), \
                patch.object(exits.balancer, 'update_domain_for_dc'):
            self.assertIs(await exits.open_cloudflare_ws(2, False), ws)
            self.assertEqual([call.args[0] for call in connect.await_args_list],
                             ['relay.example.workers.dev', 'kws2.pool.example'])

    async def test_worker_failure_without_public_pool(self):
        with patch.object(proxy_config, 'skip_front', True), \
                patch.object(proxy_config, 'cfproxy_worker_domains', ['relay.example.workers.dev']), \
                patch.object(proxy_config, 'fallback_cfproxy', False), \
                patch.object(exits.RawWebSocket, 'connect', AsyncMock(side_effect=OSError('unreachable'))), \
                patch.object(exits.balancer, 'get_domains_for_dc') as pool:
            self.assertIsNone(await exits.open_cloudflare_ws(2, False))
            pool.assert_not_called()


if __name__ == '__main__':
    unittest.main()
