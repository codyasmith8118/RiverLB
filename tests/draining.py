from auth_helpers import bootstrap, session_token
"""Live named-pool drain preserves established sessions and excludes new traffic."""
import json
import signal
import socket
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from smoke import Backend, BINARY, free_port, wait_until


def run():
    a, b = Backend(b"a"), Backend(b"b")
    admin, proxy = free_port(), free_port()
    process = None
    held = None

    def api(path="/api/v1/config", body=None):
        request = urllib.request.Request(f"http://127.0.0.1:{admin}" + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "X-RiverLB-Request": "configure"})
        if body is not None:
            request.method = "PUT"
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def transfer(stream=None):
        with stream or socket.create_connection(("127.0.0.1", proxy), timeout=2) as client:
            client.sendall(b"data")
            client.shutdown(socket.SHUT_WR)
            result = b""
            while chunk := client.recv(4096):
                result += chunk
            return result

    def healthy():
        return all(m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"])

    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-drain-") as folder:
            path = Path(folder) / "config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 30
health_interval_secs = 1
max_connections = 64
[[pools]]
name = "shared"
algorithm = "weighted_round_robin"
members = ["127.0.0.1:{a.port}", "127.0.0.1:{b.port}"]
member_weights = {{ "127.0.0.1:{a.port}" = 3 }}
[[virtual_servers]]
name = "service"
listen = "127.0.0.1:{proxy}"
default_pool = "shared"
persistence = {{ timeout_secs = 120, max_entries = 16 }}
''')
            bootstrap(BINARY, path)
            with (Path(folder) / "log").open("w+") as log:
                process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                wait_until(healthy)
                # Temporarily remove affinity so the actual scheduler ratio is observable.
                document = api()
                document["config"]["virtual_servers"][0]["persistence"]["timeout_secs"] = 0
                api(body={"revision": document["revision"], "config": document["config"]})
                wait_until(healthy)
                results = [transfer() for _ in range(40)]
                assert results.count(b"a:data") == 30, results
                assert results.count(b"b:data") == 10, results
                document = api()
                document["config"]["virtual_servers"][0]["persistence"]["timeout_secs"] = 120
                api(body={"revision": document["revision"], "config": document["config"]})
                wait_until(healthy)
                held = socket.create_connection(("127.0.0.1", proxy), timeout=2)
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][0]["members"][0]["active"] == 1)
                document = api()
                document["config"]["pools"][0]["draining_members"] = [f"127.0.0.1:{a.port}"]
                api(body={"revision": document["revision"], "config": document["config"]})
                wait_until(healthy)
                assert api("/api/v1/status")["virtual_servers"][0]["members"][0]["draining"]
                for _ in range(4):
                    assert transfer() == b"b:data"
                assert transfer(held) == b"a:data", "old session must survive apply"
                held = None
                assert api()["config"]["pools"][0]["draining_members"] == [f"127.0.0.1:{a.port}"]
                document = api()
                document["config"]["pools"][0]["draining_members"] = []
                api(body={"revision": document["revision"], "config": document["config"]})
                wait_until(healthy)
                assert transfer() == b"a:data", "removing drain must restore eligibility"
                print("PASS member drain: named pool apply, existing session, exclusion, restore, persistence")
    finally:
        if held:
            held.close()
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=12)
        a.close()
        b.close()


if __name__ == "__main__":
    run()
