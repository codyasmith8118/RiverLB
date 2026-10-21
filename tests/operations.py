"""Disposable appliance health/alerts/audit/encrypted restore integration fixtures."""
import base64
import contextlib
import http.server
import json
import os
import signal
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until


def run():
    process = None
    server = None
    with tempfile.TemporaryDirectory(prefix="riverlb-operations-") as folder:
        root = Path(folder)
        configuration = root / "config.toml"
        database = configuration.with_suffix(".db")
        port = free_port()
        configuration.write_text(f'''management = "127.0.0.1:{port}"
connect_timeout_ms = 100
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "secret-fixture-name"
description = "secret-fixture-description"
listen = "127.0.0.1:{free_port()}"
members = ["127.0.0.1:{free_port()}"]
''')
        password = "fixture-admin-password-123"
        backup_passphrase = "fixture-backup-passphrase-123"
        subprocess.run([BINARY, "admin", "--database", str(database)],
                       input=(password + "\n").encode(), capture_output=True, check=True)
        origin = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        token = None

        def request(path, body=None, method=None, expected=200, authenticated=True, csrf=True):
            headers = {"Content-Type": "application/json"}
            if csrf:
                headers["X-RiverLB-Request"] = "configure"
            if authenticated and token:
                headers["Cookie"] = "riverlb_session=" + token
            operation = urllib.request.Request(origin + "/api/v1/" + path,
                data=json.dumps(body).encode() if body is not None else None,
                headers=headers, method=method)
            try:
                response = opener.open(operation, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                encoded = response.read()
                assert response.status == expected, (path, response.status, encoded)
                return json.loads(encoded), response.headers

        def login():
            nonlocal token
            _, headers = request("auth/login", {"username": "admin", "password": password})
            token = headers["Set-Cookie"].split(";")[0].removeprefix("riverlb_session=")

        def start():
            nonlocal process
            process = subprocess.Popen([BINARY, "serve", "--config", str(configuration), "--external-network"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            wait_until(lambda: opener.open(origin + "/healthz", timeout=1).status == 200)

        def stop():
            nonlocal process
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=12)
                process.stderr.close()
            process = None

        deliveries = []
        fail_first = [True]

        class Webhook(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                assert length <= 65536
                deliveries.append(json.loads(self.rfile.read(length)))
                self.send_response(429 if fail_first[0] else 204)
                fail_first[0] = False
                self.end_headers()

            def log_message(self, *_):
                pass

        try:
            start()
            request("operations/settings", expected=401, authenticated=False)
            request("operations/health", expected=401, authenticated=False)
            login()
            health = request("operations/health")[0]
            assert health["version"] and health["revision"] == 1
            assert health["system"]["memory"]["total_bytes"] > 0
            assert health["system"]["disk"]["total_bytes"] > 0
            assert health["system"]["interfaces"]
            assert health["pending_configuration"] is False
            public = request("operations/settings")[0]
            assert "backup_key" not in public
            settings = public["settings"]
            request("operations/settings", {"settings": settings}, method="PUT", expected=403, csrf=False)
            request("operations/backup/download", {"passphrase": "short"}, expected=422)

            # An existing local directory cannot silently stand in for an unavailable remote mount.
            bad = json.loads(json.dumps(settings))
            bad["backups"]["enabled"] = True
            bad["backups"]["destination"] = str(root)
            request("operations/settings", {"settings": bad, "backup_passphrase": backup_passphrase}, method="PUT", expected=422)

            request("device-certificates/self-signed", {"name": "secret-fixture-certificate", "hostname": "fixture.test", "days": 1})
            envelope, headers = request("operations/backup/download", {"passphrase": backup_passphrase})
            assert envelope["format"] == "riverlb-encrypted-backup-v1"
            assert "riverlb-backup.rlbenc" in headers["Content-Disposition"]
            assert "private_key" not in envelope and "tables" not in envelope
            request("operations/backup/restore", {"backup": envelope, "passphrase": "incorrect-fixture-passphrase"}, expected=422)
            tampered = dict(envelope)
            tampered["created"] += 1
            request("operations/backup/restore", {"backup": tampered, "passphrase": backup_passphrase}, expected=422)
            tampered = dict(envelope)
            ciphertext = bytearray(base64.b64decode(tampered["ciphertext"]))
            ciphertext[0] ^= 1
            tampered["ciphertext"] = base64.b64encode(ciphertext).decode()
            request("operations/backup/restore", {"backup": tampered, "passphrase": backup_passphrase}, expected=422)
            validated = request("operations/backup/restore", {"backup": envelope, "passphrase": backup_passphrase})[0]
            assert validated["valid"] and not validated["staged"]
            assert validated["summary"]["format"] == 3 and validated["summary"]["administrators"] == 1
            assert validated["summary"]["device_certificates"] == 1
            request("operations/backup/restore", {"backup": envelope, "passphrase": backup_passphrase, "stage": True})
            assert request("operations/health")[0]["revision"] == 1

            bundle = request("operations/support", {})[0]
            encoded = json.dumps(bundle)
            for forbidden in ("secret-fixture", password, backup_passphrase, "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "$argon2"):
                assert forbidden not in encoded, forbidden
            assert bundle["configuration_inventory"]["virtual_servers"] == 1
            assert "object" in bundle["virtual_servers"][0]
            audit = request("operations/audit?query=backup&limit=1")[0]
            assert audit["total"] >= 2 and len(audit["entries"]) == 1
            older = request("operations/audit?query=backup&limit=1&offset=1")[0]
            assert older["entries"][0]["id"] < audit["entries"][0]["id"]
            assert request("operations/audit?query=" + urllib.parse.quote("' OR 1=1 --"))[0]["total"] == 0
            request("operations/audit?limit=201", expected=422)

            # Backups never capture a tentative management/network configuration.
            original_origin=origin
            saved=request("config")[0]
            changed=json.loads(json.dumps(saved["config"]))
            changed["management"]=f"127.0.0.1:{free_port()}"
            applied=request("config",{"revision":saved["revision"],"config":changed},method="PUT")[0]
            assert applied["confirmation"]["pending"]
            origin="http://"+changed["management"]
            wait_until(lambda: opener.open(origin+"/healthz",timeout=1).status==200)
            request("operations/backup/download",{"passphrase":backup_passphrase},expected=422)
            request("operations/backup/restore",{"backup":envelope,"passphrase":backup_passphrase,"stage":True},expected=422)
            request("config/revert",{"revision":applied["revision"]})
            origin=original_origin
            wait_until(lambda: opener.open(origin+"/healthz",timeout=1).status==200)

            # Real verified HTTPS webhook and UDP syslog, wholly within the disposable fixture.
            certificate, key = root / "webhook.crt", root / "webhook.key"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "extendedKeyUsage=serverAuth"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Webhook)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            syslog.bind(("127.0.0.1", 0))
            syslog.settimeout(5)
            settings["alerts"].update(memory_percent=1, webhook_url=f"https://localhost:{server.server_port}/alerts",
                webhook_ca=str(certificate), syslog_address=f"127.0.0.1:{syslog.getsockname()[1]}", forward_audit=True)
            saved = request("operations/settings", {"settings": settings, "backup_passphrase": backup_passphrase}, method="PUT")[0]
            assert saved["backup_key_configured"] and "backup_key" not in saved
            refreshed = request("operations/alerts/refresh", {})[0]
            assert any(alert["id"] == "memory" for alert in refreshed["alerts"])
            assert refreshed["queued_notifications"] > 0 and "HTTP 429" in refreshed["delivery_error"]
            assert deliveries and deliveries[0]["product"] == "RiverLB"
            assert syslog.recv(2048).startswith(b"<132>1 ")
            audit_packets = []
            while True:
                packet = syslog.recv(2048)
                audit_packets.append(packet)
                if b"audit id=" in packet:
                    break
            syslog.close()

            stop()
            state_path = database.with_suffix(".operations.json")
            assert state_path.stat().st_mode & 0o777 == 0o600
            private = json.loads(state_path.read_text())
            assert backup_passphrase not in state_path.read_text()
            assert len(base64.b64decode(private["backup_key"]["key"])) == 32
            # Exercise retry recovery without waiting through the production backoff interval.
            private["notification_next_attempt"] = 0
            state_path.write_text(json.dumps(private))
            start()
            wait_until(lambda: request("operations/settings")[0]["queued_notifications"] == 0)
            assert len(deliveries) >= 2
            assert request("operations/settings")[0]["delivery_error"] is None
            stop()

            with contextlib.closing(sqlite3.connect(database)) as db:
                assert db.execute("SELECT COUNT(*) FROM restore_stage").fetchone()[0] == 1
            restored=subprocess.run([BINARY, "restore", "--database", str(database), "--staged", "--replace"],
                capture_output=True, timeout=30)
            assert restored.returncode==0,restored.stderr.decode()
            start()
            request("operations/settings", expected=401)
            login()
            assert request("operations/settings")[0]["backup_key_configured"]
            print("PASS appliance operations: authenticated health, alerts, verified webhook retry/restart, RFC5424 syslog, audit search/paging, encrypted backup authentication/tamper checks, staged offline restore and secret-redacted diagnostics")
        finally:
            stop()
            if server is not None:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    run()
