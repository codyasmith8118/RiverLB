"""Measure apply/status latency with delayed backends using loopback sockets only."""
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until
import concurrent.futures
import http.server
import json
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


class Backend(http.server.BaseHTTPRequestHandler):
    delay = 0
    def do_GET(self):
        time.sleep(type(self).delay)
        try:
            self.send_response(200); self.end_headers(); self.wfile.write(b"ready")
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *_): pass


def run(measure_only=False):
    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend) for _ in range(8)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    admin, vip = free_port(), free_port()
    process = None
    def api(path="/api/v1/config", method="GET", body=None):
        request = urllib.request.Request(f"http://127.0.0.1:{admin}"+path,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={"Content-Type":"application/json", "X-RiverLB-Request":"configure"})
        with urllib.request.urlopen(request, timeout=30) as response: return json.load(response)
    def timed_apply(config, revision):
        began = time.monotonic()
        result = api(method="PUT", body={"revision":revision,"config":config})
        return time.monotonic()-began, result
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-apply-performance-") as folder:
            path = Path(folder)/"config.toml"
            members = [f"127.0.0.1:{server.server_port}" for server in servers]
            path.write_text(f'''management = "127.0.0.1:{admin}"
health_interval_secs = 1
connect_timeout_ms = 600
session_timeout_secs = 10
max_connections = 64
[[health_monitors]]
name = "ready"
kind = "http"
path = "/health"
host = "localhost"
expected_status = 200
interval_secs = 1
timeout_ms = 600
rise = 1
fall = 1
[[virtual_servers]]
name = "latency-test"
listen = "127.0.0.1:{vip}"
members = {json.dumps(members)}
monitor = "ready"
''')
            bootstrap(BINARY, path)
            with (Path(folder)/"server.log").open("w") as log:
                process = subprocess.Popen([BINARY,"serve","--external-network","-c",path],stdout=log,stderr=log)
                try:
                    wait_until(lambda: len(api("/api/v1/status")["virtual_servers"][0]["members"]) == 8)
                except Exception:
                    print((Path(folder)/"server.log").read_text()); raise
                wait_until(lambda: all(m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"]))
                data = api(); config = data["config"]
                config["virtual_servers"][0]["description"] = "metadata edit during slow probes"
                Backend.delay = 2
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(timed_apply, config, data["revision"])
                    time.sleep(.1)
                    began = time.monotonic(); api("/api/v1/status"); status_seconds = time.monotonic()-began
                    apply_seconds, result = future.result()
                measurements = {"members":8,"probe_timeout_ms":600,"apply_seconds":round(apply_seconds,3),"status_seconds":round(status_seconds,3)}
                print(json.dumps(measurements))
                if not measure_only:
                    assert apply_seconds < 1.5, measurements
                    assert status_seconds < 1, measurements
                    assert isinstance(result["duration_ms"],int) and result["duration_ms"]>=0
                    assert result["revision"] == data["revision"]+1
                    assert all(m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"]), "Unchanged healthy backends must remain available"
                    wait_until(lambda: all(not m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"]))
                    Backend.delay = 0
                    wait_until(lambda: all(m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"]))
                    # Changed monitoring inputs must not inherit a previous success.
                    changed=api(); changed["config"]["health_monitors"][0]["body_contains"]="different response"
                    Backend.delay=2
                    changed_seconds,_=timed_apply(changed["config"],changed["revision"])
                    assert changed_seconds<1.5, changed_seconds
                    assert all(not m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"])
                    print("PASS apply performance: save/status do not wait for probes; health detects failure/recovery")
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM); process.wait(timeout=15)
        for server in servers:
            server.shutdown(); server.server_close()


if __name__ == "__main__": run("--measure-only" in sys.argv)
