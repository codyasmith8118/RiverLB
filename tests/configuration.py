from auth_helpers import bootstrap, session_token
"""Configuration API transaction and reload integration checks."""
import copy
import json
import signal
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from smoke import Backend, BINARY, free_port, wait_until


def run():
    a, b = Backend(b"a"), Backend(b"b")
    process = None
    admin, proxy = free_port(), free_port()
    config = dict(management=f"127.0.0.1:{admin}", connect_timeout_ms=200,
                  session_timeout_secs=10, health_interval_secs=1, max_connections=64,
                  virtual_servers=[dict(name="original", listen=f"127.0.0.1:{proxy}",
                                        algorithm="round_robin", members=[f"127.0.0.1:{a.port}"])])

    def api(path="/api/v1/config", method="GET", body=None, headers=None, expected=200):
        request_headers = {"Content-Type": "application/json", "X-RiverLB-Request": "configure"}
        request_headers.update(headers or {})
        request = urllib.request.Request(f"http://127.0.0.1:{admin}" + path,
            data=json.dumps(body).encode() if body is not None else None, method=method, headers=request_headers)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.code == expected, (response.code, response.read())
            return json.load(response)

    def transfer(port, expected, stream=None):
        if stream is None:
            wait_until(lambda: any(v["listen"].endswith(":"+str(port)) and any(
                m["healthy"] and not m["draining"] for m in v["members"])
                for v in api("/api/v1/status")["virtual_servers"]))
        with stream or socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
            stream.sendall(b"data")
            stream.shutdown(socket.SHUT_WR)
            data = b""
            while chunk := stream.recv(4096):
                data += chunk
            assert data == expected + b":data", data

    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-config-") as folder:
            path = Path(folder) / "config.toml"
            path.write_text(f'''management = "{config['management']}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "original"
listen = "127.0.0.1:{proxy}"
algorithm = "round_robin"
members = ["127.0.0.1:{a.port}"]
''')
            bootstrap(BINARY, path)
            with (Path(folder) / "log").open("w+") as log:
                process = subprocess.Popen([BINARY, "serve", "-c", path, "--external-network"], stdout=log, stderr=log)
                wait_until(lambda: api()["revision"] == 1)
                with urllib.request.urlopen(f"http://127.0.0.1:{admin}/app.js", timeout=2) as script:
                    assert "javascript" in script.headers["Content-Type"]
                    assert b"source_self_ip" in script.read()
                initial_file = path.read_text()
                invalid = copy.deepcopy(config)
                invalid["max_connections"] = 0
                api(method="PUT", body={"revision":1,"config":invalid}, expected=409)
                assert path.read_text() == initial_file
                api("/api/v1/config/validate", "POST", config)
                api(method="PUT", body={"revision":1,"config":config}, headers={"Origin":"https://evil.example"}, expected=403)
                api(headers={"Host":"evil.example"}, expected=403)
                api(method="PUT", body={"revision":1,"config":config}, headers={"X-RiverLB-Request":""}, expected=403)
                # Binding failure must not modify disk or the live generation.
                with socket.socket() as occupied:
                    occupied.bind(("127.0.0.1", 0)); occupied.listen()
                    conflict = copy.deepcopy(config)
                    conflict["virtual_servers"][0]["listen"] = f"127.0.0.1:{occupied.getsockname()[1]}"
                    api(method="PUT", body={"revision":1,"config":conflict}, expected=409)
                assert api()["revision"] == 1 and path.read_text() == initial_file
                transfer(proxy,b"a")
                # An established session survives replacing the pool.
                existing = socket.create_connection(("127.0.0.1", proxy), timeout=2)
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][0]["members"][0]["active"] == 1)
                updated = copy.deepcopy(config)
                updated["virtual_servers"][0].update(name="updated",algorithm="source_hash",members=[f"127.0.0.1:{b.port}"])
                updated["max_connections"] = 32
                assert api(method="PUT", body={"revision":1,"config":updated})["revision"] == 2
                transfer(proxy,b"a",existing)
                transfer(proxy,b"b")
                assert api()["config"] == updated
                assert path.read_text() == initial_file  # TOML is now a bootstrap input
                api(method="PUT", body={"revision":1,"config":config}, expected=409)
                # Add a listener and move management to a new port.
                second = free_port()
                new_admin = free_port()
                updated["virtual_servers"].append(dict(name="second",listen=f"127.0.0.1:{second}",algorithm="least_connections",members=[f"127.0.0.1:{a.port}"]))
                updated["management"] = f"127.0.0.1:{new_admin}"
                result = api(method="PUT", body={"revision":2,"config":updated})
                assert result["management_url"] == f"http://127.0.0.1:{new_admin}"
                admin = new_admin
                wait_until(lambda: api()["revision"] == 3)
                assert api("/api/v1/config/confirmation")["pending"]
                api("/api/v1/config/confirm","POST",{"revision":3})
                transfer(second,b"a")
                # Delete a virtual server and verify saved config survives restart.
                updated["virtual_servers"].pop(0)
                api(method="PUT", body={"revision":3,"config":updated})
                transfer(second,b"a")
                process.send_signal(signal.SIGTERM); assert process.wait(timeout=12) == 0
                process = subprocess.Popen([BINARY,"serve","-c",path,"--external-network"],stdout=log,stderr=log)
                wait_until(lambda: api()["config"] == updated)
                transfer(second,b"a")
                # Editing, disabling and re-enabling an existing server is live.
                updated["virtual_servers"][0]["enabled"] = False
                updated["virtual_servers"][0]["description"] = "maintenance"
                api(method="PUT", body={"revision":4,"config":updated})
                try:
                    socket.create_connection(("127.0.0.1",second),timeout=1).close()
                    raise AssertionError("disabled listener accepted a connection")
                except ConnectionRefusedError:
                    pass
                updated["virtual_servers"][0]["enabled"] = True
                updated["virtual_servers"][0]["description"] = "back online"
                api(method="PUT", body={"revision":5,"config":updated})
                transfer(second,b"a")
                assert api()["config"]["virtual_servers"][0]["description"] == "back online"
                # External network mode saves models and exposes a plan without altering the host.
                updated["network"] = {"vlans":[{"name":"rlb100","interface":"eth0","tag":100}],
                    "self_ips":[{"name":"inside","address":"192.0.2.10/24","vlan":"rlb100"}],
                    "routes":[{"name":"test-route","destination":"198.51.100.0/24","gateway":"192.0.2.1","vlan":"rlb100","metric":100}]}
                plan = api("/api/v1/network/plan","POST",updated)
                assert plan["mode"] == "external" and len(plan["steps"]) == 8
                assert any(s["command"][1:3] == ["rule","add"] for s in plan["steps"])
                result = api(method="PUT",body={"revision":6,"config":updated})
                assert "--external-network is enabled" in result["message"]
                assert api()["config"]["network"] == updated["network"]
                assert all(i["ifname"] != "rlb100" for i in api("/api/v1/network/interfaces"))
                invalid = copy.deepcopy(updated); invalid["network"]["self_ips"][0]["vlan"] = "missing"
                api(method="PUT",body={"revision":7,"config":invalid},expected=409)
                assert api()["revision"] == 7
                # Named pool changes affect all referring listeners, without duplicating members.
                updated["nodes"] = [dict(name="app-node",address=f"127.0.0.1:{b.port}",enabled=True)]
                updated["pools"] = [dict(name="shared",algorithm="round_robin",members=[],node_members=["app-node"])]
                updated["virtual_servers"][0]["default_pool"] = "shared"
                updated["virtual_servers"][0]["members"] = []
                shared_port = free_port()
                shared_server = copy.deepcopy(updated["virtual_servers"][0])
                shared_server["name"] = "shared-secondary"
                shared_server["listen"] = f"127.0.0.1:{shared_port}"
                updated["virtual_servers"].append(shared_server)
                updated["health_rise"] = 2
                updated["health_fall"] = 2
                api(method="PUT",body={"revision":7,"config":updated})
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][0]["members"][0]["healthy"])
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][1]["members"][0]["healthy"])
                transfer(second,b"b")
                transfer(shared_port,b"b")
                live = api("/api/v1/status")
                assert [(p["name"],p["state"]) for p in live["pools"]] == [("shared","up")]
                assert all(v["state"] == "up" for v in live["virtual_servers"])
                updated["nodes"][0]["address"] = f"127.0.0.1:{a.port}"
                api(method="PUT",body={"revision":8,"config":updated})
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][0]["members"][0]["healthy"])
                wait_until(lambda: api("/api/v1/status")["virtual_servers"][1]["members"][0]["healthy"])
                transfer(second,b"a")
                transfer(shared_port,b"a")
                with urllib.request.urlopen(f"http://127.0.0.1:{admin}/metrics", timeout=2) as metrics:
                    assert "version=0.0.4" in metrics.headers["Content-Type"]
                    text = metrics.read().decode()
                    assert 'riverlb_member_healthy{virtual_server="shared-secondary"' in text
                    assert 'riverlb_member_completed_sessions_total{virtual_server="shared-secondary"' in text
                missing = copy.deepcopy(updated); missing["pools"] = []
                api(method="PUT",body={"revision":9,"config":missing},expected=409)
                assert api()["revision"] == 9
                process.send_signal(signal.SIGTERM); assert process.wait(timeout=12) == 0
                print("PASS configuration: transactions, live editing, networking, named pool routing/updates/reference safety, rise/fall settings")
    finally:
        if process and process.poll() is None:
            process.terminate(); process.wait(timeout=12)
        a.close(); b.close()


if __name__ == "__main__":
    run()
