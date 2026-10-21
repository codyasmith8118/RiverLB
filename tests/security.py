"""Authenticated HTTPS control plane, real TLS traffic and SQLite file compatibility."""
import copy
import http.server
import json
import signal
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until


def run():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"TLS backend reached"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    process = None
    password = "initial-secret-password-123"
    admin, proxy = free_port(), free_port()
    scheme = "http"
    token = ""
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-security-") as folder:
            root = Path(folder)
            cert, key, path = root / "cert.pem", root / "key.pem", root / "config.toml"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 1000
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "https"
listen = "127.0.0.1:{proxy}"
tls = {{ certificate = "{cert}", private_key = "{key}" }}
members = ["127.0.0.1:{backend.server_port}"]
''')
            db = path.with_suffix(".db")
            subprocess.run([BINARY, "admin", "--database", db], input=(password+"\n").encode(), check=True, capture_output=True)
            context = ssl.create_default_context(cafile=cert)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

            def request(route, body=None, expected=200, authenticated=True, headers=None, method=None):
                request_headers = {"Content-Type": "application/json", "X-RiverLB-Request": "configure"}
                if authenticated and token:
                    request_headers["Cookie"] = "riverlb_session=" + token
                request_headers.update(headers or {})
                req = urllib.request.Request(f"{scheme}://127.0.0.1:{admin}" + route, method=method,
                    data=json.dumps(body).encode() if body is not None else None, headers=request_headers)
                try:
                    response = opener.open(req, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    text = response.read().decode()
                    assert response.code == expected, (response.code, text)
                    return text, response.headers

            def login(secret, expected=200):
                body, headers = request("/api/v1/auth/login", {"username": "admin", "password": secret}, expected, False)
                if expected == 200:
                    cookie = headers["Set-Cookie"]
                    assert all(value in cookie for value in ["HttpOnly", "SameSite=Strict"])
                    assert ("Secure" in cookie) == (scheme == "https")
                    return cookie.split(";", 1)[0].split("=", 1)[1]

            def start(log):
                return subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)

            with (root / "log").open("w+") as log:
                process = start(log)
                wait_until(lambda: request("/healthz", authenticated=False)[0] == "ok")
                request("/api/v1/config", expected=401, authenticated=False)
                request("/metrics", expected=401, authenticated=False)
                assert "Sign in" in request("/", authenticated=False)[0]
                assert "<svg" in request("/favicon.svg", authenticated=False)[0]
                appearance, appearance_headers = request("/appearance.js", authenticated=False)
                assert "riverlb.appearance" in appearance
                assert "text/javascript" in appearance_headers["Content-Type"]
                request("/api/v1/auth/login", {"username": "admin", "password": password}, 403, False, {"Origin": f"https://127.0.0.1:{admin}"})
                login("wrong-password", 401)
                token = login(password)
                config = json.loads(request("/api/v1/config")[0])
                config.pop("network_mode")
                config.pop("confirmation")
                assert config["revision"] == 1
                config["config"]["virtual_servers"][0]["description"] = "saved in database"
                next_admin = free_port()
                config["config"]["management"] = f"127.0.0.1:{next_admin}"
                config["config"]["management_tls"] = {"certificate": str(cert), "private_key": str(key)}
                request("/api/v1/config", config, 403, headers={"X-RiverLB-Request": ""}, method="PUT")
                broken = copy.deepcopy(config)
                broken["config"]["virtual_servers"][0]["tls"]["private_key"] = str(root / "missing.pem")
                request("/api/v1/config", broken, 409, method="PUT")
                assert json.loads(request("/api/v1/config")[0])["revision"] == 1
                applied = json.loads(request("/api/v1/config", config, method="PUT")[0])
                assert applied["management_url"] == f"https://127.0.0.1:{next_admin}"
                admin, scheme = next_admin, "https"
                wait_until(lambda: request("/healthz", authenticated=False)[0] == "ok")
                token = login(password)
                assert "riverlb.appearance" in request("/appearance.js", authenticated=False)[0]
                request("/api/v1/config/confirm", {"revision": applied["revision"]})
                # Verify browser-trusted TLS termination and an actual HTTP backend response.
                with opener.open(f"https://127.0.0.1:{proxy}/", timeout=5) as response:
                    assert response.read() == b"TLS backend reached"
                with socket.create_connection(("127.0.0.1", proxy), timeout=2) as client:
                    client.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    try:
                        reply = client.recv(128)
                        assert not reply.startswith(b"HTTP/") and b"TLS backend reached" not in reply
                    except ConnectionResetError:
                        pass
                # The local CLI cannot access a database owned by the daemon.
                busy = subprocess.run([BINARY, "admin", "--database", db], input=(password+"\n").encode(), capture_output=True)
                assert busy.returncode != 0 and b"database is in use" in busy.stderr
                new_password = "changed-secret-password-456"
                request("/api/v1/auth/password", {"current_password": password, "new_password": new_password})
                request("/api/v1/config", expected=401)
                login(password, 401)
                token = login(new_password)
                request("/api/v1/auth/logout", {})
                request("/api/v1/config", expected=401)
                token = login(new_password)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=12) == 0
                # TOML edits must not overwrite already saved database configuration.
                path.write_text(path.read_text().replace('name = "https"', 'name = "ignored-bootstrap-edit"'))
                process = start(log)
                wait_until(lambda: request("/healthz", authenticated=False)[0] == "ok")
                loaded = json.loads(request("/api/v1/config")[0])
                assert loaded["revision"] == 2
                assert loaded["config"]["virtual_servers"][0]["description"] == "saved in database"
                assert loaded["config"]["virtual_servers"][0]["name"] == "https"
                assert json.loads(request("/api/v1/audit")[0])
                for _ in range(10):
                    login("wrong-password", 401)
                login("wrong-password", 429)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=12) == 0
                with sqlite3.connect(db) as connection:
                    stored_hash = connection.execute("SELECT password_hash FROM administrators").fetchone()[0]
                    assert stored_hash.startswith("$argon2id$") and new_password not in stored_hash
                    assert connection.execute("SELECT COUNT(*) FROM configurations").fetchone()[0] == 2
                    assert connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0] >= 5
                    assert token not in str(connection.execute("SELECT token_hash FROM sessions").fetchall())
                connection.close()
                exported = subprocess.check_output([BINARY, "export", "--database", db])
                assert json.loads(exported)["virtual_servers"][0]["name"] == "https"
                print("PASS security: login/CSRF/logout/password/rate limit, HTTPS management and virtual server, durable configuration, SQLite read, exclusive database ownership")
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=12)
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    run()
