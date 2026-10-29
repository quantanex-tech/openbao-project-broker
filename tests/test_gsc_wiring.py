import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import broker
import client
import google_search_console as gsc


class AccessBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / 'config.json'
        path.write_text(json.dumps({'schema_version': 1, 'openbao_address': 'https://vault.example',
            'projects': {'demo': {'enabled': True, 'allowed_uids': [1000], 'secret_prefix': 'projects/demo'}}}))
        self.broker = broker.Broker(path, {'demo': object()})

    def test_ungranted_identity_cannot_start_gsc_or_read_vault(self):
        with patch.object(self.broker, 'client') as vault:
            with self.assertRaises(broker.BrokerError) as caught:
                self.broker.dispatch(1001, {'action': 'google_search_console_read', 'project': 'demo',
                    'credential': 'production/google-search-console', 'operation': 'sites_list'})
        self.assertEqual(caught.exception.code, 'project_access_denied')
        vault.assert_not_called()

    def test_gsc_does_not_wait_for_workspace_transfer_slot(self):
        # An idle read transport must not steal/release migration's large-transfer slot.
        self.broker.google.transfer_slot.acquire()
        try:
            with patch.object(self.broker, 'client', return_value=object()), \
                 patch.object(self.broker, 'read', return_value={'data': {'fabricated': True}}), \
                 patch.object(self.broker.search_console, 'execute', return_value={'http_status': 200, 'data': {}}):
                result = self.broker.dispatch(1000, {'action': 'google_search_console_read', 'project': 'demo',
                    'credential': 'production/google-search-console', 'operation': 'sites_list'})
            self.assertEqual(result['http_status'], 200)
            self.assertFalse(self.broker.google.transfer_slot.acquire(blocking=False))
        finally:
            self.broker.google.transfer_slot.release()

    def test_credential_path_escape_is_refused_before_vault(self):
        with patch.object(self.broker, 'client', return_value=object()), patch.object(self.broker, 'read') as read:
            with self.assertRaises(broker.BrokerError):
                self.broker.dispatch(1000, {'action': 'google_search_console_read', 'project': 'demo',
                    'credential': '../infrastructure/grant', 'operation': 'sites_list'})
        read.assert_not_called()

    def test_mcp_exposes_named_read_tool_and_refuses_extra_transport_fields(self):
        definition = next(x for x in client.TOOLS if x['name'] == 'google_search_console_read')
        self.assertTrue(definition['annotations']['readOnlyHint'])
        self.assertFalse(definition['annotations']['destructiveHint'])
        with patch.object(client, 'call') as request:
            result = client.tool_call('google_search_console_read', {'project': 'demo',
                'credential': 'production/google-search-console', 'operation': 'sites_list',
                'headers': {'Authorization': 'FAKE-MARKER'}})
        self.assertFalse(result['ok'])
        request.assert_not_called()

    def test_near_limit_gsc_result_survives_actual_socket_envelope(self):
        from test_search_console import record
        payload = {'inspectionResult': {'coverageState': 'p' * (gsc.MAX_RESPONSE - 4096)}}
        socket_path = str(Path(self.tmp.name) / 'broker.sock')
        server = broker.Server(socket_path, broker.Handler)
        server.broker = self.broker
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(self.broker, 'client', return_value=object()), \
                 patch.object(self.broker, 'read', return_value={'data': record()}), \
                 patch.object(self.broker.search_console.auth, 'token', return_value='FAKE-ACCESS-TOKEN'), \
                 patch.object(gsc, 'exchange', return_value=(200, payload)), \
                 patch.object(client, 'SOCKET', socket_path):
                result = client.call({'action': 'google_search_console_read', 'project': 'demo',
                    'credential': 'production/google-search-console', 'operation': 'url_inspection',
                    'params': {'inspectionUrl': 'https://example.test/'}})
            self.assertTrue(result['ok'])
            self.assertEqual(result['result']['data'], payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_redaction_expansion_cannot_exceed_response_limit(self):
        from test_search_console import record
        data = record()
        data['authorized_user_json']['client_secret'] = 'S'
        with patch.object(self.broker.search_console.auth, 'token', return_value='FAKE-ACCESS-TOKEN'), \
             patch.object(gsc, 'exchange', return_value=(200, {'inspectionResult': {'message': 'S' * 300000}})):
            with self.assertRaises(gsc.ApiError) as caught:
                self.broker.search_console.execute(('demo', 'fixture'), data,
                    {'operation': 'url_inspection', 'params': {'inspectionUrl': 'https://example.test/'}})
        self.assertEqual(caught.exception.code, 'gsc_response_invalid')


if __name__ == '__main__':
    unittest.main()
