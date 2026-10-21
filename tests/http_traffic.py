"""Compare HTTP counters with exact bytes at a real backend, including upgrades."""
import base64
import hashlib
import http.client
import json
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until


def run():
    records, lock = [], threading.Lock()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline()
            if not line:  # Default TCP health probes carry no application data.
                return
            up = bytearray(line)
            headers = {}
            while True:
                line = self.rfile.readline()
                up.extend(line)
                if line == b'\r\n':
                    break
                key, value = line.split(b':', 1)
                headers[key.lower()] = value.strip()
            path = up.split(b' ', 2)[1]
            if headers.get(b'transfer-encoding') == b'chunked':
                while True:
                    line = self.rfile.readline()
                    up.extend(line)
                    size = int(line.strip(), 16)
                    up.extend(self.rfile.read(size + 2))
                    if not size:
                        break
            else:
                up.extend(self.rfile.read(int(headers.get(b'content-length', b'0'))))
            if path == b'/ws':
                accept = base64.b64encode(hashlib.sha1(headers[b'sec-websocket-key'] + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
                down = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n' + b'\x81\x01X'
                self.request.sendall(down)  # Upgrade headers and first frame together.
                frame = self.rfile.read(7)
                assert frame == b'\x81\x81\x01\x02\x03\x04\x5b', frame
                up.extend(frame)
                reply = b'\x81\x01Z'
                self.request.sendall(reply)
                down += reply
            else:
                down = (b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' if path == b'/empty'
                        else b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n')
                self.request.sendall(down)
            with lock:
                records.append((len(up), len(down)))

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    backend = Server(('127.0.0.1', 0), Handler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-http-traffic-') as folder:
            root = Path(folder)
            cert, key = root/'cert.pem', root/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            ports = {name: free_port() for name in ['buffered', 'streaming', 'https']}
            admin = free_port()
            path = root/'config.toml'
            text = f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 1000
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[nodes]]
name = "backend"
address = "127.0.0.1:{backend.server_address[1]}"
[[pools]]
name = "shared"
algorithm = "round_robin"
members = []
node_members = ["backend"]
'''
            for name, port in ports.items():
                text += f'''[[virtual_servers]]
name = "{name}"
listen = "127.0.0.1:{port}"
server_type = "http"
default_pool = "shared"
http = {{ streaming = {str(name == 'streaming').lower()} }}
'''
                if name == 'https':
                    text += f'tls = {{certificate = {json.dumps(str(cert))}, private_key = {json.dumps(str(key))}}}\n'
            path.write_text(text)
            bootstrap(BINARY, path)

            def api(route='/api/v1/statistics'):
                with urllib.request.urlopen(f'http://127.0.0.1:{admin}'+route, timeout=5) as response:
                    return json.load(response)

            def counters(name):
                return next(v for v in api()['virtual_servers'] if v['name'] == name)['traffic']

            def verify(name, before, record_count):
                wait_until(lambda: len(records) == record_count + 1)
                expected_up, expected_down = records[-1]
                wait_until(lambda: counters(name)['completed'] == before['completed'] + 1)
                after = counters(name)
                assert after['bytes_in'] - before['bytes_in'] == expected_up, (name, before, after, records[-1])
                assert after['bytes_out'] - before['bytes_out'] == expected_down, (name, before, after, records[-1])
                member = next(v for v in api()['virtual_servers'] if v['name'] == name)['members'][0]
                assert member['bytes_to_backend'] == after['bytes_in']
                assert member['bytes_to_client'] == after['bytes_out']

            with (root/'log').open('w+') as log:
                process = subprocess.Popen([BINARY, 'serve', '-c', path, '--external-network'], stdout=log, stderr=log)
                wait_until(lambda: all(m['healthy'] for v in api('/api/v1/status')['virtual_servers'] for m in v['members']))
                context = ssl.create_default_context(cafile=cert)
                for name, port in ports.items():
                    for method, uri, body in [('GET', '/empty', None), ('GET', '/chunked', None),
                                              ('POST', '/upload', iter([b'ab', b'c']))]:
                        before, count = counters(name), len(records)
                        connection = (http.client.HTTPSConnection('localhost', port, context=context, timeout=5) if name == 'https'
                                      else http.client.HTTPConnection('127.0.0.1', port, timeout=5))
                        try:
                            connection.request(method, uri, body=body, encode_chunked=body is not None)
                            response = connection.getresponse()
                            assert response.status == 200
                            assert response.read() == (b'' if uri == '/empty' else b'abc')
                        finally:
                            connection.close()
                        verify(name, before, count)
                before, count = counters('buffered'), len(records)
                with socket.create_connection(('127.0.0.1', ports['buffered']), timeout=5) as client:
                    client.sendall(b'GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
                    data = b''
                    while b'\r\n\r\n' not in data:
                        chunk = client.recv(4096)
                        assert chunk, 'EOF during WebSocket handshake'
                        data += chunk
                    head, pending = data.split(b'\r\n\r\n', 1)
                    assert b'101 Switching Protocols' in head
                    while len(pending) < 3:
                        chunk = client.recv(3-len(pending))
                        assert chunk, 'EOF before prefetched frame'
                        pending += chunk
                    assert pending == b'\x81\x01X'
                    client.sendall(b'\x81\x81\x01\x02\x03\x04\x5b')
                    echo = b''
                    while len(echo) < 3:
                        chunk = client.recv(3-len(echo))
                        assert chunk, 'EOF before echoed frame'
                        echo += chunk
                    assert echo == b'\x81\x01Z'
                verify('buffered', before, count)
                pool = api()['pools'][0]['traffic']
                assert pool['bytes_in'] == sum(r[0] for r in records)
                assert pool['bytes_out'] == sum(r[1] for r in records)
                node = api('/api/v1/nodes')[0]
                assert sum(i['bytes_to_backend'] for i in node['instances']) == pool['bytes_in']
                assert sum(i['bytes_to_client'] for i in node['instances']) == pool['bytes_out']
                print('PASS HTTP byte accounting: exact backend headers/body/chunks, empty GET, verified HTTPS, streaming upload, WebSocket prefetch, pool/member/node totals')
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=15)
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    run()
