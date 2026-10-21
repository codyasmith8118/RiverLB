"""Exercise datagram monitor dispatch, health transitions and persisted configuration."""
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until
import copy
import json
import signal
import socket
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path


def run():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(0.1)
    mode = {"kind": "udp", "valid": True}
    stop = threading.Event()

    def respond():
        while not stop.is_set():
            try:
                request, client = server.recvfrom(4096)
            except socket.timeout:
                continue
            if mode["kind"] == "udp":
                reply = b"pong" if mode["valid"] else b"wrong"
            else:
                reply = bytearray(request)
                reply[2:4] = b"\x81\x80" if mode["valid"] else b"\x81\x83"
                reply[6:8] = b"\x00\x01"
                reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\x7f\x00\x00\x01")
            server.sendto(reply, client)

    thread = threading.Thread(target=respond)
    thread.start()
    process = None
    admin = free_port()

    def api(path="/api/v1/config", method="GET", body=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{admin}" + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Content-Type": "application/json", "X-RiverLB-Request": "configure"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def apply(config):
        api(method="PUT", body={"revision": api()["revision"], "config": config})

    def state():
        return api("/api/v1/nodes")[0]["state"]

    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-datagram-monitors-") as folder:
            root = Path(folder)
            path = root / "config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 5
health_interval_secs = 1
max_connections = 64
virtual_servers = []
''')
            bootstrap(BINARY, path)
            with (root / "log").open("w+") as log:
                process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                try:
                    wait_until(lambda: api()["revision"] == 1)
                except AssertionError:
                    log.flush()
                    raise AssertionError((root / "log").read_text())
                config = api()["config"]
                monitor = {"name": "datagram", "kind": "udp", "interval_secs": 1,
                           "timeout_ms": 500, "rise": 1, "fall": 1, "send": "ping", "receive": "pong"}
                config["health_monitors"] = [monitor]
                config["nodes"] = [{"name": "service", "address": f"127.0.0.1:{server.getsockname()[1]}",
                                    "monitor": "datagram"}]
                apply(config)
                wait_until(lambda: state() == "Up")
                mode["valid"] = False
                wait_until(lambda: state() == "Down")
                mode.update(kind="dns", valid=True)
                monitor.clear()
                monitor.update(name="datagram", kind="dns", interval_secs=1, timeout_ms=500,
                               rise=1, fall=1, query="health.example", record_type="A")
                apply(config)
                wait_until(lambda: state() == "Up")
                mode["valid"] = False
                wait_until(lambda: state() == "Down")
                mode["valid"] = True
                wait_until(lambda: state() == "Up")
                # ICMP must work without a TCP listener or UDP responder on the member port.
                echo = copy.deepcopy(config)
                echo["health_monitors"][0] = {"name": "datagram", "kind": "icmp", "interval_secs": 1,
                                               "timeout_ms": 500, "rise": 1, "fall": 1}
                echo["nodes"][0]["address"] = "127.0.0.1:1"
                apply(echo)
                wait_until(lambda: state() == "Up")
                apply(config)
                wait_until(lambda: state() == "Up")
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=15)
                process = subprocess.Popen([BINARY, "serve", "-c", path], stdout=log, stderr=log)
                wait_until(lambda: state() == "Up")
                assert api()["config"]["health_monitors"][0]["kind"] == "dns"
                print("PASS datagram monitors: UDP matching, DNS failures/recovery, ICMP without TCP, restart persistence")
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=15)
        stop.set()
        thread.join(timeout=2)
        server.close()


if __name__ == "__main__":
    run()
