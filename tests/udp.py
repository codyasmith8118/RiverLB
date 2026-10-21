"""UDP proxy conversations, capacity, health, apply lifecycle, SNAT and protocol isolation."""
import copy
import json
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until


def run():
    seen = []
    unhealthy = set()
    servers = []
    clients = []
    process = None

    def backend(label):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                if data == b'probe':
                    sock.sendto(b'down' if label in unhealthy else b'alive', self.client_address)
                elif data == b'return-empty':
                    sock.sendto(b'', self.client_address)
                elif data == b'two-replies':
                    sock.sendto(b'first', self.client_address)
                    sock.sendto(b'second', self.client_address)
                else:
                    seen.append((label, self.client_address, data))
                    sock.sendto(label.encode() + data, self.client_address)
        server = socketserver.ThreadingUDPServer(('127.0.0.1', 0), Handler)
        server.max_packet_size = 65536
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address[1]

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(65536):
                self.request.sendall(data)
    tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), TCP)
    tcp.daemon_threads = True
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    servers.append(tcp)
    ports = [backend(label) for label in ('A', 'B')]
    admin, vip = free_port(), free_port()

    def api(path='/api/v1/config', method='GET', body=None):
        request = urllib.request.Request(f'http://127.0.0.1:{admin}'+path,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={'Content-Type': 'application/json', 'X-RiverLB-Request': 'configure'})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def statistics():
        return next(v for v in api('/api/v1/statistics')['virtual_servers'] if v['name']=='udp')

    def client():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        sock.settimeout(1)
        clients.append(sock)
        return sock

    def exchange(sock, payload):
        sock.sendto(payload, ('127.0.0.1', vip))
        response, source = sock.recvfrom(65536)
        assert source == ('127.0.0.1', vip), source
        assert response[1:] == payload, (len(response), len(payload))
        return response[:1]

    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-udp-', dir='/tmp') as folder:
            root = Path(folder)
            path = root/'config.toml'
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 4
[[health_monitors]]
name = "udp-ready"
kind = "udp"
send = "probe"
receive = "alive"
interval_secs = 1
timeout_ms = 150
rise = 1
fall = 1
[[pools]]
name = "datagrams"
algorithm = "round_robin"
members = ["127.0.0.1:{ports[0]}", "127.0.0.1:{ports[1]}"]
monitor = "udp-ready"
[[virtual_servers]]
name = "udp"
server_type = "udp"
listen = "127.0.0.1:{vip}"
default_pool = "datagrams"
udp_idle_timeout_secs = 1
connection_limit = 2
source_nat = {{mode = "snat", addresses = ["127.0.0.2"]}}
[[virtual_servers]]
name = "tcp"
server_type = "tcp"
listen = "127.0.0.1:{vip}"
members = ["127.0.0.1:{tcp.server_address[1]}"]
''')
            subprocess.run([BINARY, 'validate', '-c', path], check=True, capture_output=True)
            bootstrap(BINARY, path)
            with (root/'log').open('w+') as log:
                process = subprocess.Popen([BINARY, 'serve', '-c', path, '--external-network'], stdout=log, stderr=log)
                wait_until(lambda: all(m['healthy'] for v in api('/api/v1/status')['virtual_servers'] for m in v['members']))
                first, second, third = client(), client(), client()
                label = exchange(first, b'one')
                assert exchange(second, b'two') != label
                for data in (b'', b'\x00\xff\x00', b'x'*64000, b'last'):
                    assert exchange(first, data) == label
                first.sendto(b'return-empty', ('127.0.0.1', vip))
                assert first.recvfrom(100) == (b'', ('127.0.0.1', vip))
                first.sendto(b'two-replies', ('127.0.0.1', vip))
                assert {first.recvfrom(100)[0], first.recvfrom(100)[0]} == {b'first', b'second'}
                assert all(source[0] == '127.0.0.2' for _,source,_ in seen)
                third.sendto(b'over-capacity', ('127.0.0.1', vip))
                third.settimeout(0.2)
                try:
                    third.recvfrom(100)
                    raise AssertionError('flow limit was not enforced')
                except socket.timeout:
                    pass
                assert statistics()['traffic']['rejected'] > 0
                # A datagram from another backend endpoint must not reach the client.
                source = next(source for name,source,_ in reversed(seen) if name.encode()==label)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue:
                    rogue.sendto(b'forged-response', source)
                first.settimeout(0.2)
                try:
                    first.recvfrom(100)
                    raise AssertionError('unconnected backend datagram was forwarded')
                except socket.timeout:
                    pass
                first.settimeout(1)
                wait_until(lambda: statistics()['traffic']['current']==0)
                assert statistics()['traffic']['completed'] >= 2
                with socket.create_connection(('127.0.0.1', vip), timeout=2) as stream:
                    stream.sendall(b'tcp-same-port')
                    assert stream.recv(100) == b'tcp-same-port'
                counts = {b'A': 0, b'B': 0}
                # Let each short idle timeout release the flow before the next.
                for _ in range(6):
                    sock = client()
                    counts[exchange(sock, b'new-flow')] += 1
                    wait_until(lambda: statistics()['traffic']['current']==0)
                assert counts == {b'A':3, b'B':3}, counts
                unhealthy.add('A')
                wait_until(lambda: not next(v for v in api('/api/v1/status')['virtual_servers'] if v['name']=='udp')['members'][0]['healthy'])
                assert exchange(client(), b'healthy-only') == b'B'
                wait_until(lambda: statistics()['traffic']['current']==0)
                # Remove the pool member during a live flow; no stale receiver/session remains.
                sock = client()
                assert exchange(sock, b'before-apply') == b'B'
                saved = api()
                changed = copy.deepcopy(saved['config'])
                changed['pools'][0]['members'] = [f'127.0.0.1:{ports[1]}']
                changed['virtual_servers'][0]['description'] = 'UDP apply'
                before = time.monotonic()
                api(method='PUT', body={'revision': saved['revision'], 'config': changed})
                assert time.monotonic()-before < 2
                assert exchange(sock, b'after-apply') == b'B'
                stats = statistics()['traffic']
                assert stats['bytes_in'] >= 64000 and stats['bytes_out'] >= 64000
                assert stats['response_latency']['samples'] > 0
                # Reject protocol-incompatible settings without replacing the working revision.
                for mutation in ('http', 'wildcard', 'timeout', 'monitor'):
                    saved = api(); invalid = copy.deepcopy(saved['config'])
                    vs = invalid['virtual_servers'][0]
                    if mutation == 'http': vs['http'] = {}
                    if mutation == 'wildcard': vs['listen'] = f'0.0.0.0:{vip}'
                    if mutation == 'timeout': vs['udp_idle_timeout_secs'] = 0
                    if mutation == 'monitor': invalid['pools'][0].pop('monitor', None)
                    try:
                        api(method='PUT', body={'revision':saved['revision'], 'config':invalid})
                        raise AssertionError('invalid UDP configuration accepted: '+mutation)
                    except urllib.error.HTTPError as error:
                        assert error.code == 409, (mutation,error.code,error.read())
                    assert api()['revision'] == saved['revision']
                assert exchange(sock, b'validation-preserves-traffic') == b'B'
    finally:
        if process:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        for sock in clients: sock.close()
        for server in servers:
            server.shutdown(); server.server_close()
    print('PASS UDP: flow affinity/distribution/expiry, binary/empty/large datagrams, SNAT, peer filtering, limits, health, TCP same port, apply, validation and counters')


def run_ipv6():
    class IPv6Server(socketserver.ThreadingUDPServer):
        address_family = socket.AF_INET6
        daemon_threads = True
        max_packet_size = 65536
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(b'alive' if data == b'probe' else data, self.client_address)
    server = IPv6Server(('::1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-udp6-', dir='/tmp') as folder:
            root=Path(folder); path=root/'config.toml'
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as temporary:
                temporary.bind(('::1',0)); vip=temporary.getsockname()[1]
            admin=free_port()
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 4
[[health_monitors]]
name = "ready"
kind = "udp"
send = "probe"
receive = "alive"
interval_secs = 1
timeout_ms = 150
rise = 1
fall = 1
[[virtual_servers]]
name = "udp6"
server_type = "udp"
listen = "[::1]:{vip}"
members = ["[::1]:{server.server_address[1]}"]
monitor = "ready"
udp_idle_timeout_secs = 1
source_nat = {{mode = "snat", addresses = ["::1"]}}
''')
            bootstrap(BINARY,path)
            with (root/'log').open('w+') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path,'--external-network'],stdout=log,stderr=log)
                def healthy():
                    with urllib.request.urlopen(f'http://127.0.0.1:{admin}/api/v1/status',timeout=2) as response:
                        return json.load(response)['virtual_servers'][0]['members'][0]['healthy']
                wait_until(healthy)
                with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    for payload in (b'', b'IPv6 payload', b'x'*64000):
                        client.sendto(payload,('::1',vip))
                        data,source=client.recvfrom(65536)
                        assert data==payload and source[:2]==('::1',vip)
    finally:
        if process:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        server.shutdown(); server.server_close()
    print('PASS UDP IPv6: readiness, source binding, empty/binary/large replies from VIP')


if __name__ == '__main__':
    run()
    run_ipv6()
