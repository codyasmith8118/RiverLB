from auth_helpers import bootstrap, session_token
"""Real TCP source-affinity, expiry, failover and configuration reload checks."""
import json
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from smoke import Backend, BINARY, free_port, wait_until


def run():
    a, b = Backend(b"a"), Backend(b"b")
    admin, proxy = free_port(), free_port()
    process = None

    def config():
        with urllib.request.urlopen(f"http://127.0.0.1:{admin}/api/v1/config", timeout=2) as response:
            return json.load(response)

    def transfer():
        with socket.create_connection(("127.0.0.1", proxy), timeout=2) as client:
            client.sendall(b"data")
            client.shutdown(socket.SHUT_WR)
            result = b""
            while chunk := client.recv(4096):
                result += chunk
            return result

    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-persistence-") as folder:
            try:
                path = Path(folder) / "config.toml"
                path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "sticky"
listen = "127.0.0.1:{proxy}"
members = ["127.0.0.1:{a.port}", "127.0.0.1:{b.port}"]
persistence = {{ timeout_secs = 2, max_entries = 16 }}
''')
                bootstrap(BINARY, path)
                with (Path(folder) / "log").open("w+") as log:
                    process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                    wait_until(lambda: config()["revision"] == 1)
                    def healthy():
                        with urllib.request.urlopen(f"http://127.0.0.1:{admin}/api/v1/status", timeout=2) as response:
                            return all(m["healthy"] for m in json.load(response)["virtual_servers"][0]["members"])
                    wait_until(healthy)
                    original = config()["config"]
                    disabled = json.loads(json.dumps(original))
                    disabled["virtual_servers"][0]["persistence"] = {"timeout_secs":0,"max_entries":0}
                    def apply(settings):
                        document = config()
                        request = urllib.request.Request(f"http://127.0.0.1:{admin}/api/v1/config",
                            method="PUT",data=json.dumps({"revision":document["revision"],"config":settings}).encode(),
                            headers={"Content-Type":"application/json","X-RiverLB-Request":"configure"})
                        with urllib.request.urlopen(request,timeout=3): pass
                    apply(disabled)
                    wait_until(healthy)
                    assert {transfer() for _ in range(6)} == {b"a:data",b"b:data"}, "No persistence must rebalance requests from the same source"
                    with urllib.request.urlopen(f"http://127.0.0.1:{admin}/api/v1/persistence",timeout=2) as response:
                        assert json.load(response)["virtual_servers"][0]["total_records"] == 0
                    apply(original)
                    wait_until(healthy)
                    first = transfer()
                    assert first == b"a:data", first
                    for _ in range(5):
                        assert transfer() == first
                    time.sleep(2.2)
                    assert transfer() == b"b:data", "expired record must rebalance"
                    b.close()
                    wait_until(lambda: transfer() == b"a:data")
                    assert transfer() == b"a:data"
                    settings = config()["config"]["virtual_servers"][0]["persistence"]
                    assert settings == {"timeout_secs": 2, "max_entries": 16}
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=12) == 0
                    process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                    wait_until(lambda: config()["config"]["virtual_servers"][0]["persistence"] == settings)
                    print("PASS persistence: none rebalances without records, source reuse, expiry, failover, restart")
            finally:
                # Stop writers before TemporaryDirectory starts removing state.
                if process is not None and process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        raise
    finally:
        a.close()
        # Backend.close is not called twice; b already closed after the expiry check.
        if not b.stopped.is_set():
            b.close()


if __name__ == "__main__":
    run()
