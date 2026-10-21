#!/usr/bin/env python3
"""Isolated integration tests for lab tools. Does not provision host networking."""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'tests/lab'
BINARY = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')) / 'debug/riverlb'
sys.path.insert(0, str(LAB))
from backend import make_server


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class LabTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='riverlb-lab-tools-', dir='/tmp')
        self.folder = Path(self.temp.name)
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.temp.cleanup()

    def backend(self, name='node-a', tls=False):
        marker = self.folder / f'{name}.unhealthy'
        server = make_server('127.0.0.1', 0, name, marker)
        if tls:
            cert, key = self.folder/'cert.pem', self.folder/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost',
                            '-keyout', str(key), '-out', str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return server, marker

    def load(self, url, filename, *options, expected=0):
        output = self.folder/filename
        result = subprocess.run([sys.executable, str(LAB/'http_load.py'), url,
                                 '--duration', '0.4', '--rate', '10', '--output', str(output),
                                 *options], text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        summary = json.loads(output.read_text())
        rows = [json.loads(row) for row in output.with_suffix('.requests.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), summary['started'])
        self.assertEqual(summary['scheduled'], summary['started'] + summary['scheduler_dropped'])
        return summary, rows

    def test_identity_health_failure_and_payload(self):
        server, marker = self.backend()
        base = f'http://127.0.0.1:{server.server_port}'
        summary, rows = self.load(base+'/?delay_ms=5', 'identity.json', '--host', 'lab.example.test')
        self.assertEqual(summary['backend_counts'], {'node-a': 4})
        self.assertTrue(all(row['latency_ms'] >= 5 for row in rows))
        _, rows = self.load(base+'/payload?bytes=16384', 'payload.json', '--expect-bytes', '16384')
        self.assertTrue(all(row['bytes'] == 16384 for row in rows))
        summary, _ = self.load(base+'/payload?bytes=10', 'wrong-size.json',
                               '--expect-bytes', '11', expected=1)
        self.assertEqual(summary['failures'], 4)
        summary, _ = self.load(base+'/', 'wrong-node.json', '--expect-nodes', 'node-z', expected=1)
        self.assertEqual(summary['failures'], 4)
        marker.touch()
        summary, _ = self.load(base+'/healthz', 'unhealthy.json', expected=1)
        self.assertEqual(summary['status_counts'], {'503': 4})
        self.assertEqual(summary['failures'], 4)
        marker.unlink()
        summary, _ = self.load(base+'/healthz', 'recovered.json')
        self.assertTrue(summary['passed'])

    def test_scheduler_overload_is_visible(self):
        server, _ = self.backend()
        summary, _ = self.load(f'http://127.0.0.1:{server.server_port}/?delay_ms=200',
                               'overload.json', '--rate', '50', '--workers', '1', expected=1)
        self.assertGreater(summary['scheduler_dropped'], 0)
        self.assertFalse(summary['passed'])

    def test_refused_connection_is_recorded(self):
        summary, _ = self.load(f'http://127.0.0.1:{free_port()}/', 'refused.json', expected=1)
        self.assertEqual(summary['successes'], 0)
        self.assertTrue(summary['error_counts'])

    def test_tls_trust_and_hostname_validation(self):
        server, _ = self.backend(tls=True)
        self.load(f'https://localhost:{server.server_port}/', 'trusted.json',
                  '--ca', str(self.folder/'cert.pem'))
        summary, _ = self.load(f'https://localhost:{server.server_port}/', 'untrusted.json', expected=1)
        self.assertTrue(any('CERTIFICATE_VERIFY_FAILED' in key for key in summary['error_counts']))
        summary, _ = self.load(f'https://127.0.0.1:{server.server_port}/', 'wrong-san.json',
                               '--ca', str(self.folder/'cert.pem'), expected=1)
        self.assertTrue(any('CERTIFICATE_VERIFY_FAILED' in key for key in summary['error_counts']))

    def profile(self, profile, config, expected=0):
        path = self.folder / 'loadgen.json'
        path.write_text(json.dumps(config))
        results = self.folder / ('profiles-' + profile)
        process = subprocess.run([sys.executable, str(LAB/'loadgen.py'), profile,
                                  '--config', str(path), '--results', str(results),
                                  '--duration', '0.4', '--rate', '10', '--workers', '1'],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, expected, process.stderr + process.stdout)
        reports = list(results.glob('*/run.json'))
        return json.loads(reports[0].read_text()) if reports else None

    def test_named_profiles_record_tls_results_and_stop_failed_ramp(self):
        tls_server, _ = self.backend(tls=True)
        config = dict(http_url='http://127.0.0.1:1/',
                      https_url=f'https://localhost:{tls_server.server_port}/',
                      ca_certificate=str(self.folder/'cert.pem'), expected_nodes=['node-a'])
        report = self.profile('https', config)
        self.assertTrue(report['passed'])
        self.assertEqual(report['phases'][0]['result']['backend_counts'], {'node-a': 4})
        # A failed ramp must stop after its first phase rather than increase load.
        http_server, _ = self.backend('failed-node')
        config.update(http_url=f'http://127.0.0.1:{http_server.server_port}/fail', expected_nodes=['failed-node'])
        report = self.profile('ramp', config, expected=1)
        self.assertFalse(report['passed'])
        self.assertEqual(len(report['phases']), 1)
        self.assertEqual(report['phases'][0]['result']['failures'], 4)

    def test_combined_profile_validates_https_trust_before_starting_http(self):
        server, _ = self.backend()
        config = dict(http_url=f'http://127.0.0.1:{server.server_port}/',
                      https_url='https://localhost/', ca_certificate=str(self.folder/'missing.pem'),
                      expected_nodes=['node-a'])
        self.assertIsNone(self.profile('check', config, expected=2))
        self.assertFalse((self.folder/'profiles-check').exists())

    @unittest.skipUnless(BINARY.exists(), 'build the debug RiverLB binary first')
    def test_distribution_through_riverlb(self):
        backends = [self.backend(name)[0] for name in ('node-a', 'node-b', 'node-c')]
        admin, vip = free_port(), free_port()
        config = self.folder/'config.toml'
        members = ', '.join(f'"127.0.0.1:{server.server_port}"' for server in backends)
        config.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 30
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "lab"
server_type = "http"
listen = "127.0.0.1:{vip}"
algorithm = "round_robin"
members = [{members}]
http = {{}}
''')
        subprocess.run([str(BINARY), 'admin', '--database', str(config.with_suffix('.db'))],
                       input='lab-only-test-password-123\n', text=True, capture_output=True, check=True)
        with (self.folder/'riverlb.log').open('w+') as log:
            process = subprocess.Popen([str(BINARY), 'serve', '-c', str(config), '--external-network'],
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic()+10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', vip), timeout=0.1):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            log.seek(0)
                            self.fail(log.read())
                        time.sleep(0.05)
                time.sleep(1.1)
                summary, _ = self.load(f'http://127.0.0.1:{vip}/', 'proxy.json',
                                       '--duration', '1.2', '--workers', '1',
                                       '--expect-nodes', 'node-a,node-b,node-c')
                self.assertEqual(summary['backend_counts'], {'node-a': 4, 'node-b': 4, 'node-c': 4})
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


class TRexAPI(unittest.TestCase):
    def test_profile_serialization(self):
        from trex_tcp_profile import register
        for size in (1024, 16384, 1048576):
            data = register().get_profile(response_bytes=size).to_json()
            self.assertTrue(data['templates'])
            self.assertEqual(data['templates'][0]['client_template']['port'], 9000)
            self.assertEqual(data['templates'][0]['server_template']['assoc'][0]['port'], 9000)
        with self.assertRaises(ValueError):
            register().get_profile(response_bytes=0)
        with self.assertRaises(ValueError):
            register().get_profile(client_start='198.18.10.127', client_end='198.18.10.64')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--trex', action='store_true')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LabTools)
    if args.trex:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TRexAPI))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
