"""Real HTTP/HTTPS readiness, source-independent failures, and database revision browsing."""
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until
import copy
import http.server
import json
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path


class App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    status, body, delay = 200, b"ready", 0
    def do_GET(self):
        time.sleep(type(self).delay)
        assert self.path == "/health?readiness=1"
        assert self.headers["Host"] == "localhost"
        self.send_response(type(self).status)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for part in [type(self).body[:2], type(self).body[2:]]:
                if part:
                    self.wfile.write(f"{len(part):x}\r\n".encode()+part+b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
    def log_message(self, *_): pass


def run():
    plain_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=plain_server.serve_forever, daemon=True).start()
    process = tls_server = None
    admin, proxy = free_port(), free_port()
    def api(path="/api/v1/config", method="GET", body=None):
        request = urllib.request.Request(f"http://127.0.0.1:{admin}"+path,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={"Content-Type":"application/json", "X-RiverLB-Request":"configure"})
        with urllib.request.urlopen(request, timeout=10) as response: return json.load(response)
    def member(): return api("/api/v1/status")["virtual_servers"][0]["members"][0]
    def apply(config):
        current = api()
        api(method="PUT", body={"revision":current["revision"], "config":config})
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-monitors-") as folder:
            root = Path(folder); path = root/"config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 5
health_interval_secs = 1
max_connections = 64
[[health_monitors]]
name = "ready"
kind = "http"
path = "/health?readiness=1"
host = "localhost"
expected_status = 200
body_contains = "ready"
interval_secs = 1
timeout_ms = 250
rise = 2
fall = 2
[[pools]]
name = "apps"
algorithm = "round_robin"
members = ["127.0.0.1:{plain_server.server_port}"]
monitor = "ready"
[[virtual_servers]]
name = "home-app"
listen = "127.0.0.1:{proxy}"
default_pool = "apps"
app_url = "https://app.home.example/"
''')
            bootstrap(BINARY, path)
            with (root/"log").open("w+") as log:
                process = subprocess.Popen([BINARY,"serve","-c",path], stdout=log, stderr=log)
                wait_until(lambda: api()["revision"] == 1)
                wait_until(lambda: member()["healthy"])
                assert member()["probe_latency_ms"] is not None
                App.status = 503
                wait_until(lambda: not member()["healthy"])
                assert "503" in member()["probe_error"]
                App.status, App.body = 200, b"wrong"
                wait_until(lambda: "text was not found" in (member()["probe_error"] or ""))
                App.body, App.delay = b"ready", 1
                wait_until(lambda: "deadline" in (member()["probe_error"] or ""))
                App.delay = 0
                wait_until(lambda: member()["healthy"])
                App.body = b"x" * 65536 + b"ready"
                wait_until(lambda: "64 KiB" in (member()["probe_error"] or ""))
                App.body = b"ready"
                wait_until(lambda: member()["healthy"])
                config = api()["config"]
                for mutate in [
                    lambda c: c["pools"][0].update(monitor="missing"),
                    lambda c: c["virtual_servers"][0].update(app_url="javascript:alert(1)"),
                    lambda c: c["virtual_servers"][0].update(app_url="https://user:pass@app.home/"),
                    lambda c: c["health_monitors"][0].update(host="localhost\r\nInjected: yes"),
                ]:
                    bad = copy.deepcopy(config); mutate(bad)
                    try: api("/api/v1/config/validate","POST",bad)
                    except urllib.error.HTTPError as error: assert error.code == 422
                    else: raise AssertionError("invalid configuration accepted")
                assert api()["revision"] == 1
                # TLS monitor works only with trusted CA and matching hostname.
                cert, key = root/"cert.pem", root/"key.pem"
                subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-addext","basicConstraints=critical,CA:FALSE","-keyout",key,"-out",cert], check=True, capture_output=True)
                tls_server = http.server.ThreadingHTTPServer(("127.0.0.1",0), App)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
                tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
                threading.Thread(target=tls_server.serve_forever, daemon=True).start()
                secure = copy.deepcopy(config)
                secure["pools"][0]["members"] = [f"127.0.0.1:{tls_server.server_port}"]
                secure["health_monitors"][0].update(kind="https",ca_certificate=str(cert))
                apply(secure)
                try: wait_until(lambda: member()["healthy"])
                except AssertionError: raise AssertionError(member())
                secure["health_monitors"][0]["host"] = "wrong.example"
                apply(secure)
                assert member()["healthy"] is False
                wait_until(lambda: "TLS" in (member()["probe_error"] or ""))
                history = api("/api/v1/config/history")
                assert [h["revision"] for h in history] == [3,2,1]
                assert history[0]["actor"] == "admin"
                saved = api("/api/v1/config/history/1")
                assert saved["health_monitors"][0]["kind"] == "http"
                assert api()["revision"] == 3 # Reading history never changes live state.
                apply(saved)
                wait_until(lambda: member()["healthy"])
                assert api()["revision"] == 4
                process.send_signal(signal.SIGTERM); process.wait(timeout=15); process = None
                process = subprocess.Popen([BINARY,"serve","-c",path], stdout=log, stderr=log)
                wait_until(lambda: api()["revision"] == 4)
                assert len(api("/api/v1/config/history")) == 4
                # A node monitor overrides the pool check and also runs without a virtual server.
                monitored = api()["config"]
                address = f"127.0.0.1:{plain_server.server_port}"
                monitored["nodes"] = [{"name":"app-node","address":address,"monitor":"ready"}]
                monitored["pools"][0].pop("monitor")
                monitored["pools"][0]["members"] = []
                monitored["pools"][0]["node_members"] = ["app-node"]
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Up")
                App.status = 503
                wait_until(lambda: not member()["healthy"])
                assert api("/api/v1/nodes")[0]["state"] == "Down"
                monitored["virtual_servers"] = []
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Down")
                App.status = 200
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Up")
                bad = copy.deepcopy(monitored); bad["nodes"][0]["monitor"] = "missing"
                try: api("/api/v1/config/validate","POST",bad)
                except urllib.error.HTTPError as error: assert error.code == 422
                else: raise AssertionError("unknown node monitor accepted")
                # The node-specific HTTPS connector must use its monitor's CA and server name.
                monitored["nodes"][0]["address"] = f"127.0.0.1:{tls_server.server_port}"
                monitored["health_monitors"][0].update(kind="https",ca_certificate=str(cert))
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Up")
                monitored["health_monitors"][0]["host"] = "wrong.example"
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Down")
                monitored["health_monitors"][0]["host"] = "localhost"
                # TLS-only checks verify the handshake without requiring HTTP readiness.
                check = monitored["health_monitors"][0]
                check["kind"] = "tls"
                for field in ["path", "expected_status", "body_contains"]:
                    check.pop(field)
                App.status = 503
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Up")
                check["host"] = "wrong.example"
                apply(monitored)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Down")
                check["host"] = "localhost"
                apply(monitored)
                process.send_signal(signal.SIGTERM); process.wait(timeout=15); process = None
                process = subprocess.Popen([BINARY,"serve","-c",path], stdout=log, stderr=log)
                wait_until(lambda: api("/api/v1/nodes")[0]["state"] == "Up")
                assert api()["config"]["nodes"][0]["monitor"] == "ready"
                print("PASS monitors: HTTP status/text/chunked/deadline/recovery, verified HTTPS, named pools, node override/standalone HTTPS/TLS checks, persisted history")
    finally:
        if process and process.poll() is None: process.send_signal(signal.SIGTERM); process.wait(timeout=15)
        plain_server.shutdown(); plain_server.server_close()
        if tls_server: tls_server.shutdown(); tls_server.server_close()

if __name__ == "__main__": run()
