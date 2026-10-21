"""Live counters, SNAT socket sources and persisted history over real traffic."""
import json
import signal
import socket
import socketserver
import subprocess
import struct
import tempfile
import threading
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until
from auth_helpers import bootstrap


def run():
    sources = []
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                while data := self.request.recv(65536):
                    sources.append(self.client_address[0])
                    self.request.sendall(data)
            except OSError:
                pass
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    backend = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    admin, proxy = free_port(), free_port()
    process = None
    def api(route="/api/v1/statistics"):
        with urllib.request.urlopen(f"http://127.0.0.1:{admin}"+route, timeout=5) as response:
            return json.load(response)
    def reset():
        request=urllib.request.Request(f'http://127.0.0.1:{admin}/api/v1/statistics/reset',data=b'{}',method='POST',headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)
    def stats():
        return api()["virtual_servers"][0]["traffic"]
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-traffic-") as folder:
            path = Path(folder)/"config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 1000
session_timeout_secs = 20
health_interval_secs = 1
max_connections = 64
[[nodes]]
name = "backend"
address = "127.0.0.1:{backend.server_address[1]}"
[[pools]]
name = "shared"
algorithm = "round_robin"
members = ["127.0.0.1:{backend.server_address[1]}"]
[[virtual_servers]]
name = "translated"
listen = "127.0.0.1:{proxy}"
default_pool = "shared"
source_nat = {{ mode = "snat", addresses = ["127.0.0.2", "127.0.0.3"] }}
''')
            bootstrap(BINARY, path)
            with (Path(folder)/"log").open("w+") as log:
                process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][0]["members"][0]["healthy"])
                for _ in range(4):
                    with socket.create_connection(("127.0.0.1", proxy), timeout=2) as client:
                        client.sendall(b"live-counter")
                        assert client.recv(100) == b"live-counter"
                        wait_until(lambda: stats()["current"] == 1 and stats()["bytes_in"] > 0 and stats()["bytes_out"] > 0)
                    wait_until(lambda: stats()["current"] == 0)
                wait_until(lambda: stats()["completed"] == 4 and stats()["current"] == 0)
                assert sources == ["127.0.0.2", "127.0.0.3", "127.0.0.2", "127.0.0.3"], sources
                snapshot = api()
                traffic = snapshot["virtual_servers"][0]["traffic"]
                assert traffic["accepted"] == 4 and traffic["peak"] == 1
                assert traffic["bytes_in"] == traffic["bytes_out"] == 4*len(b"live-counter")
                assert snapshot["pools"][0]["traffic"]["bytes_in"] == traffic["bytes_in"]
                assert snapshot["pools"][0]["traffic"]["peak"] is None
                member = snapshot["virtual_servers"][0]["members"][0]
                assert member["total_connections"] == 4 and member["peak_connections"] == 1
                assert traffic['connect_latency']['samples'] == 4
                assert member['traffic']['connect_latency']['samples'] == 4
                assert snapshot['pools'][0]['traffic']['connect_latency']['samples'] == 4
                assert api('/api/v1/nodes')[0]['connect_latency']['samples'] == 4
                wait_until(lambda: any(s["virtual_servers"][0]["traffic"]["bytes_in"] == traffic["bytes_in"] for s in api("/api/v1/statistics/history")))
                with urllib.request.urlopen(f"http://127.0.0.1:{admin}/metrics") as response:
                    text = response.read().decode()
                    assert 'riverlb_virtual_bytes_in_total{virtual_server="translated"} 48' in text
                    assert text.count('# TYPE riverlb_virtual_bytes_in_total counter') == 1
                saved = api('/api/v1/config')
                saved['config']['session_timeout_secs'] = 1
                request = urllib.request.Request(f'http://127.0.0.1:{admin}/api/v1/config',
                    data=json.dumps({'revision': saved['revision'], 'config': saved['config']}).encode(), method='PUT',
                    headers={'Content-Type':'application/json', 'X-RiverLB-Request':'configure'})
                with urllib.request.urlopen(request, timeout=10): pass
                assert stats()["accepted"] == 4 and stats()["bytes_in"] == 48
                with socket.create_connection(('127.0.0.1', proxy), timeout=3):
                    wait_until(lambda: stats()['session_timeouts'] == 1)
                assert stats()['backend_errors'] == stats()['transport_errors'] == 0
                client = socket.create_connection(('127.0.0.1', proxy), timeout=3)
                client.sendall(b'reset-test'); assert client.recv(100) == b'reset-test'
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)); client.close()
                wait_until(lambda: stats()['transport_errors'] == 1)
                assert stats()['failures'] == 2 and stats()['backend_errors'] == 0
                assert api()['pools'][0]['traffic']['session_timeouts'] == 1
                process.send_signal(signal.SIGTERM); assert process.wait(timeout=12) == 0
                process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                wait_until(lambda: bool(api("/api/v1/statistics/history")))
                assert any(s["virtual_servers"][0]["traffic"]["bytes_in"] == 48 for s in api("/api/v1/statistics/history"))
                wait_until(lambda: stats()['accepted']==6 and stats()['completed']==4)
                assert stats()['failures']==2 and stats()['current']==0
                member=api()['virtual_servers'][0]['members'][0]
                assert member['total_connections']==6 and member['completed']==4 and member['failures']==2
                assert stats()['connect_latency']['samples']==6
                before_epoch=api()['epoch']
                # Reset keeps an active connection alive and gauges meaningful.
                client=socket.create_connection(('127.0.0.1',proxy),timeout=3)
                client.sendall(b'before-reset');assert client.recv(100)==b'before-reset'
                wait_until(lambda:stats()['current']==1)
                reset()
                assert stats()['accepted']==stats()['completed']==stats()['failures']==stats()['bytes_in']==0
                assert stats()['current']==stats()['peak']==1 and api()['epoch']!=before_epoch
                client.sendall(b'after-reset');assert client.recv(100)==b'after-reset';client.close()
                wait_until(lambda:stats()['current']==0 and stats()['completed']==1)
                assert stats()['bytes_in']==stats()['bytes_out']==len(b'after-reset')
                history=api('/api/v1/statistics/history')
                assert all(sample['virtual_servers'][0]['traffic']['bytes_in']!=48 for sample in history)
                # Abrupt restart restores the latest five-second checkpoint.
                wait_until(lambda:any(sample['virtual_servers'][0]['traffic']['completed']==1 for sample in api('/api/v1/statistics/history')))
                process.kill();process.wait(timeout=10)
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:stats()['completed']==1)
                assert stats()['accepted']==0 and stats()['bytes_in']==len(b'after-reset') and stats()['current']==0
                member=api()['virtual_servers'][0]['members'][0]
                assert member['completed']==1 and member['bytes_to_backend']==len(b'after-reset')
                reset()
                process.send_signal(signal.SIGTERM);assert process.wait(timeout=12)==0
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:stats()['completed']==0)
                assert stats()['bytes_in']==stats()['failures']==0
                print("PASS traffic: live bytes, connection totals/peak, pool aggregate, SNAT rotation, metrics, database history")
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM); process.wait(timeout=12)
        backend.shutdown(); backend.server_close()


if __name__ == "__main__":
    run()
