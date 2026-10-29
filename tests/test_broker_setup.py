"""Exercise generic enrollment and installed CLI/MCP against a fake local vault."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import broker
from test_install import installer


def configuration():
    return {'schema_version': 1, 'openbao_address': 'http://127.0.0.1:8200',
            'kv_mount': 'custom-kv', 'auth_mount': 'custom-role',
            'projects': {'demo': {'enabled': True, 'allowed_uids': [os.getuid()],
                                  'secret_prefix': 'projects/demo'}}}


class SetupValidation(unittest.TestCase):
    def test_invalid_config_rejected_before_any_login(self):
        cases = [None, [], {}, {**configuration(), 'openbao_address': 'http://vault.example.test'},
                 {**configuration(), 'kv_mount': '../other'},
                 {**configuration(), 'auth_mount': 'role?override=yes'},
                 {**configuration(), 'openbao_address': 'https://user:password@vault.example.test'}]
        for field, value in [('allowed_uids', [True]), ('allowed_uids', ['1000']),
                             ('enabled', 'true'), ('secret_prefix', 'projects/../other')]:
            config = configuration()
            config['projects']['demo'][field] = value
            cases.append(config)
        with patch.object(broker.OpenBao, '_authenticate') as login:
            for config in cases:
                with self.subTest(config=config), self.assertRaises(broker.BrokerError):
                    broker.validate_config(config)
            login.assert_not_called()

    def test_credential_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'registration.json'
            data = {'projects': {'demo': {'role_id': 'fixture-role', 'secret_id': 'fixture-secret'}}}
            path.write_text(json.dumps(data))
            path.chmod(0o600)
            self.assertEqual(broker.read_credentials(path), data['projects'])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                broker.read_credentials(path)
            link = Path(directory) / 'alias'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                broker.read_credentials(link)

    def test_mount_paths_and_local_address_defaults(self):
        config = configuration()
        broker.validate_config(config)
        client = broker.OpenBao(config['openbao_address'], {}, config['kv_mount'], config['auth_mount'])
        self.assertEqual(client.kv_mount, 'custom-kv')
        self.assertEqual(client.auth_mount, 'custom-role')


class InstalledRoundTrip(unittest.TestCase):
    def test_installed_service_catalog_and_mcp_use_configured_mounts_and_socket(self):
        seen = []
        class Vault(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def reply(self, value):
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def do_POST(self):
                seen.append(self.path)
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if self.path == '/v1/auth/custom-role/login':
                    self.reply({'auth': {'client_token': 'FIXTURE-VAULT-TOKEN', 'lease_duration': 3600}})
                else:
                    self.reply({})
            def do_GET(self):
                seen.append(self.path)
                if self.headers.get('X-Vault-Token') != 'FIXTURE-VAULT-TOKEN':
                    self.send_error(403)
                elif self.path == '/v1/custom-kv/metadata/projects/demo?list=true':
                    self.reply({'data': {'keys': ['reporting']}})
                elif self.path == '/v1/custom-kv/data/projects/demo/reporting':
                    self.reply({'data': {'metadata': {'version': 1}, 'data': {
                        'api_token': 'FIXTURE-PROVIDER-SECRET', '_http': {
                            'version': 1, 'base_url': 'https://api.example.com',
                            'paths': ['/status'], 'methods': ['GET'],
                            'auth': {'type': 'bearer', 'field': 'api_token'}}}}})
                else:
                    self.send_error(404)
        vault = ThreadingHTTPServer(('127.0.0.1', 0), Vault)
        worker = threading.Thread(target=vault.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                prefix = root / 'installed'
                installer.install(prefix)
                config = configuration()
                config['openbao_address'] = 'http://127.0.0.1:' + str(vault.server_port)
                (root / 'projects.json').write_text(json.dumps(config))
                credentials = root / 'approle.json'
                credentials.write_text(json.dumps({'projects': {'demo': {
                    'role_id': 'FIXTURE-ROLE', 'secret_id': 'FIXTURE-SECRET-ID'}}}))
                credentials.chmod(0o600)
                env = {**os.environ, 'PROJECT_ACCESS_SOCKET': str(root / 'service.sock'),
                       'PROJECT_BROKER_CONFIG': str(root / 'projects.json'),
                       'PROJECT_BROKER_CREDENTIALS': str(credentials),
                       'PROJECT_BROKER_AUDIT': str(root / 'audit.jsonl')}
                process = subprocess.Popen([str(prefix / 'bin/project-broker')], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 10
                    while not (root / 'service.sock').exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(.02)
                    def cli(*args, input=None):
                        return subprocess.run([str(prefix / 'bin/project-access'), *args], env=env,
                                              input=input, capture_output=True, text=True, timeout=10, check=True)
                    status = json.loads(cli('status').stdout)
                    self.assertEqual(status['result']['version'], '0.6.0')
                    self.assertEqual(status['result']['projects'], ['demo'])
                    catalog = cli('catalog', '--project', 'demo').stdout
                    result = json.loads(catalog)['result']
                    self.assertEqual(result['secret_root'], 'custom-kv/projects/demo')
                    self.assertEqual(result['credentials'][0]['api']['status'], 'ready')
                    for secret in ('FIXTURE-PROVIDER-SECRET', 'FIXTURE-VAULT-TOKEN', 'FIXTURE-SECRET-ID'):
                        self.assertNotIn(secret, catalog)
                    requests = [
                        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
                        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                         'params': {'name': 'project_access_status', 'arguments': {}}}]
                    messages = cli('mcp', input=''.join(json.dumps(r) + '\n' for r in requests)).stdout.splitlines()
                    self.assertEqual(json.loads(messages[0])['result']['serverInfo']['name'], 'openbao-project-access')
                    self.assertTrue(json.loads(messages[1])['result']['structuredContent']['ok'])
                    check = json.loads(cli('check', '--project', 'demo', '--name', 'reporting').stdout)
                    self.assertEqual(check['result']['storage_path'], 'custom-kv/projects/demo/reporting')
                finally:
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertFalse((root / 'service.sock').exists())
                for secret in ('FIXTURE-PROVIDER-SECRET', 'FIXTURE-VAULT-TOKEN', 'FIXTURE-SECRET-ID'):
                    self.assertNotIn(secret, stdout + stderr + (root / 'audit.jsonl').read_text())
                self.assertIn('/v1/auth/custom-role/login', seen)
                self.assertIn('/v1/auth/token/revoke-self', seen)
        finally:
            vault.shutdown()
            vault.server_close()
            worker.join(5)


if __name__ == '__main__':
    unittest.main()
