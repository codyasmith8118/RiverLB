"""Real management HTTP authorization, TOTP, tokens, allowlists and idle expiry.

All identities, secrets and databases are disposable fixtures. No host network,
installed appliance state, or existing accounts are modified.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/riverlb"
PASSWORD = "auth-release-fixture-password-123"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def totp(secret, counter=None):
    counter = int(time.time()) // 30 if counter is None else counter
    tag = hmac.new(base64.b32decode(secret), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = tag[-1] & 15
    return f"{(int.from_bytes(tag[offset:offset + 4], 'big') & 0x7fffffff) % 1000000:06}"


def run():
    process = None
    with tempfile.TemporaryDirectory(prefix="riverlb-auth-release-") as directory:
        root = Path(directory)
        config = root / "config.toml"
        database = config.with_suffix(".db")
        port = free_port()
        config.write_text(f'''management = "127.0.0.1:{port}"
connect_timeout_ms = 1000
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "disabled-fixture"
listen = "127.0.0.1:{free_port()}"
enabled = false
members = ["127.0.0.1:9"]
''')
        subprocess.run([BINARY, "admin", "--database", database], input=(PASSWORD + "\n").encode(), check=True, capture_output=True)

        def request(path, body=None, token=None, expected=200, method=None, source="127.0.0.1", extra=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10, source_address=(source, 0))
            headers = {"Content-Type": "application/json", "X-RiverLB-Request": "configure"}
            if token:
                if token.startswith("rlb_"):
                    headers["Authorization"] = "Bearer " + token
                else:
                    headers["Cookie"] = "riverlb_session=" + token
            headers.update(extra or {})
            try:
                connection.request(method or ("POST" if body is not None else "GET"), path, body=None if body is None else json.dumps(body), headers=headers)
                response = connection.getresponse()
                text = response.read().decode()
                assert response.status == expected, (path, response.status, expected, text)
                return json.loads(text) if text.startswith(("{", "[")) else text, dict(response.getheaders())
            finally:
                connection.close()

        def login(username, code=None, expected=200):
            _, headers = request("/api/v1/auth/login", {"username": username, "password": PASSWORD, **({"code": code} if code is not None else {})}, expected=expected)
            return headers.get("set-cookie", "").split(";", 1)[0].removeprefix("riverlb_session=")

        def stop():
            nonlocal process
            if process and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=12)
            process = None

        def start():
            nonlocal process
            process = subprocess.Popen([BINARY, "serve", "--config", config, "--external-network"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                try:
                    if request("/healthz")[0] == "ok":
                        return
                except (OSError, http.client.HTTPException):
                    pass
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                time.sleep(0.1)
            raise AssertionError("Management fixture did not become ready")

        try:
            start()
            # The management cap includes incomplete unauthenticated requests.
            held = []
            try:
                for _ in range(64):
                    client = socket.create_connection(("127.0.0.1", port), timeout=2)
                    client.sendall(f"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode())
                    held.append(client)
                # Acceptance is sequential; this connection follows all 64 above.
                with socket.create_connection(("127.0.0.1", port), timeout=2) as excess:
                    excess.settimeout(2)
                    try:
                        excess.sendall(f"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                        assert excess.recv(128) == b"", "Management connection cap was not enforced"
                    except (ConnectionResetError, BrokenPipeError):
                        pass
            finally:
                for client in held:
                    client.close()
            deadline = time.monotonic() + 5
            while True:
                try:
                    assert request("/healthz")[0] == "ok"
                    break
                except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            # One source cannot consume another source's sign-in allowance.
            bad = {"username": "admin", "password": "wrong-password"}
            for _ in range(10):
                request("/api/v1/auth/login", bad, source="127.0.0.2", expected=401)
            request("/api/v1/auth/login", bad, source="127.0.0.2", expected=429,
                    extra={"X-Forwarded-For": "127.0.0.3"})
            admin = login("admin")
            # A stalled large upload reserves capacity, without blocking health.
            with socket.create_connection(("127.0.0.1", port), timeout=2) as upload:
                upload.sendall((f"POST /api/v1/updates/stage HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                                f"Cookie: riverlb_session={admin}\r\nX-RiverLB-Request: configure\r\n"
                                "Content-Type: application/json\r\nContent-Length: 1000000\r\n\r\n{").encode())
                time.sleep(0.1)
                request("/api/v1/updates/stage", {}, admin, expected=503)
                assert request("/healthz")[0] == "ok"
            for username, role in [("reader", "read_only"), ("operator", "operator")]:
                request("/api/v1/administrators", {"username": username, "action": "create", "current_password": PASSWORD, "new_password": PASSWORD, "role": role}, admin)
            reader, operator = login("reader"), login("operator")
            assert request("/api/v1/auth/me", token=reader)[0]["role"] == "read_only"
            request("/api/v1/status", token=reader)
            request("/api/v1/config", {}, reader, expected=403, method="PUT")
            request("/api/v1/administrators", token=reader, expected=403)
            request("/api/v1/security/settings", token=reader, expected=403)
            request("/api/v1/operations/settings", token=reader, expected=403)
            request("/api/v1/backup", {}, reader, expected=403)
            request("/api/v1/statistics/reset", {}, reader, expected=403)
            request("/api/v1/statistics/reset", {}, operator)
            request("/api/v1/ha", {}, operator, expected=403, method="PUT")
            request("/api/v1/administrators", {"username": "admin", "action": "role", "role": "read_only", "current_password": PASSWORD}, admin, expected=409)
            monitoring = request("/api/v1/security/tokens", {"name": "prometheus", "scope": "monitoring", "lifetime_secs": 3600, "current_password": PASSWORD}, admin)[0]
            raw = monitoring["token"]
            assert raw not in json.dumps(request("/api/v1/security/tokens", token=admin)[0])
            request("/metrics", token=raw)
            request("/api/v1/status", token=raw)
            request("/api/v1/config", token=raw, expected=403)
            request("/api/v1/statistics/reset", {}, raw, expected=403)
            request("/api/v1/security/tokens/" + monitoring["id"], {}, admin, method="DELETE")
            request("/metrics", token=raw, expected=401)
            configure = request("/api/v1/security/tokens", {"name": "automation", "scope": "configure", "lifetime_secs": 3600, "current_password": PASSWORD}, admin)[0]
            request("/api/v1/config", token=configure["token"])
            request("/api/v1/administrators", token=configure["token"], expected=403)
            request("/api/v1/security/settings", token=configure["token"], expected=403)
            request("/api/v1/security/settings", {"settings": {"idle_timeout_secs": 60, "source_allowlist": ["198.51.100.0/24"]}, "current_password": PASSWORD}, admin, expected=409, method="PUT")
            request("/api/v1/security/settings", {"settings": {"idle_timeout_secs": 60, "source_allowlist": ["127.0.0.1/32"]}, "current_password": PASSWORD}, admin, method="PUT")
            try:
                request("/healthz", source="127.0.0.2", extra={"X-Forwarded-For": "127.0.0.1"})
            except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
                pass  # Denied at accept time, before parsing HTTP or TLS.
            else:
                raise AssertionError("Disallowed source reached HTTP management")
            enrollment = request("/api/v1/security/mfa/enroll", {"current_password": PASSWORD}, admin)[0]
            request("/api/v1/security/mfa/confirm", {"code": "invalid"}, admin, expected=409)
            codes = request("/api/v1/security/mfa/confirm", {"code": totp(enrollment["secret"])}, admin)[0]["recovery_codes"]
            assert len(codes) == 10 and len(set(codes)) == 10
            request("/api/v1/status", token=admin, expected=401)
            request("/api/v1/config", token=configure["token"], expected=401)
            login("admin", expected=401)
            login("admin", "12345", expected=401)
            recovered = login("admin", codes[0])
            login("admin", codes[0], expected=401)
            assert request("/api/v1/security/mfa", token=recovered)[0]["recovery_codes_remaining"] == 9
            request("/api/v1/security/mfa/disable", {"current_password": PASSWORD, "code": codes[1]}, recovered)
            request("/api/v1/status", token=recovered, expected=401)
            admin = login("admin")
            # Reads/polling do not refresh idle activity. Expire only this fixture's
            # rows while its daemon is stopped, then prove restart preserves expiry.
            stop()
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE auth_session_activity SET last_seen=?", (int(time.time()) - 61,))
                stored = " ".join(r[0] for r in conn.execute("SELECT json FROM auth_accounts"))
                assert all(code not in stored for code in codes)
            conn.close()
            start()
            request("/api/v1/status", token=admin, expected=401)
            request("/api/v1/status", token=reader, expected=401)
            print("PASS auth release: server-side roles, token scope/revocation, source allowlists, TOTP/recovery single use, MFA session revocation and durable idle expiration")
        finally:
            stop()


if __name__ == "__main__":
    run()
