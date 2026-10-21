from auth_helpers import bootstrap, session_token
"""Real socket integration tests; no external Python dependencies."""
import concurrent.futures
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/riverlb"


class Backend:
    def __init__(self, label, port=0):
        self.label = label
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.reply, args=(client,), daemon=True).start()

    def reply(self, client):
        with client:
            client.settimeout(3)
            try:
                data = b""
                while chunk := client.recv(4096):
                    data += chunk
                if data:
                    client.sendall(self.label + b":" + data)
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=2)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(check):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError("condition did not become true")


def run(algorithm):
    a, b = Backend(b"a"), Backend(b"b")
    ports = {a.port, b.port}
    while (proxy := free_port()) in ports:
        pass
    ports.add(proxy)
    while (admin := free_port()) in ports:
        pass
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-test-") as folder:
            config = Path(folder) / "config.toml"
            config.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "test"
listen = "127.0.0.1:{proxy}"
algorithm = "{algorithm}"
members = ["127.0.0.1:{a.port}", "127.0.0.1:{b.port}"]
''')
            subprocess.run([BINARY, "validate", "-c", config], check=True, capture_output=True)
            bootstrap(BINARY, config)
            with (Path(folder) / "daemon.log").open("w+") as log:
                process = subprocess.Popen([BINARY, "serve", "-c", config], stdout=log, stderr=log)

                def status():
                    with urllib.request.urlopen(f"http://127.0.0.1:{admin}/api/v1/status", timeout=1) as r:
                        return json.load(r)["virtual_servers"][0]["members"]

                def request(_=None):
                    with socket.create_connection(("127.0.0.1", proxy), timeout=2) as s:
                        s.sendall(b"payload")
                        s.shutdown(socket.SHUT_WR)
                        data = b""
                        while chunk := s.recv(4096):
                            data += chunk
                        assert data in (b"a:payload", b"b:payload"), data
                        return data

                wait_until(lambda: all(m["healthy"] for m in status()))
                with urllib.request.urlopen(f"http://127.0.0.1:{admin}/", timeout=1) as r:
                    assert b"RiverLB" in r.read()
                output = subprocess.check_output([BINARY, "status", "--address", f"127.0.0.1:{admin}", "--session-stdin"], input=(session_token()+"\n").encode())
                assert json.loads(output)["virtual_servers"][0]["name"] == "test"
                replies = [request() for _ in range(10)]
                if algorithm == "round_robin":
                    assert replies.count(b"a:payload") == 5
                if algorithm == "source_hash":
                    assert len(set(replies)) == 1
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    assert len(list(executor.map(request, range(24)))) == 24
                wait_until(lambda: sum(m["completed"] for m in status()) == 34 and all(m["active"] == 0 for m in status()))
                assert sum(m["bytes_to_backend"] for m in status()) == 34 * len(b"payload")
                old_port = b.port
                b.close()
                wait_until(lambda: not status()[1]["healthy"])
                assert all(request() == b"a:payload" for _ in range(6))
                b = Backend(b"b", old_port)
                wait_until(lambda: status()[1]["healthy"])
                request()
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=12) == 0
                print(f"PASS {algorithm}: forwarding, half-close, health/recovery, concurrency, counters, CLI, dashboard, shutdown")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        a.close()
        b.close()


if __name__ == "__main__":
    for method in ("round_robin", "least_connections", "source_hash"):
        run(method)
