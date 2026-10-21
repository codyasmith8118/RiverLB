"""Confirm/revert crash recovery against real Linux objects in a private netns.

Run with sudo unshare --net -- python3 tests/confirmation_network.py, or an
equivalent unprivileged user/net namespace. The guarded fixture creates only a
dummy uplink and temporary application state, never host networking/firewalld.
"""
import copy
import http.client
import json
import os
import signal
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from auth_helpers import PASSWORD, bootstrap
from smoke import BINARY, free_port, wait_until


def ip(*args):
    return json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", *map(str, args)]))


def mutate_ip(*args):
    subprocess.run(["/usr/sbin/ip", *map(str, args)], check=True, capture_output=True)


def run():
    parent = os.environ.get("RIVERLB_TEST_PARENT_NETNS")
    if parent is None:
        parent = os.readlink("/proc/1/ns/net")
    assert os.readlink("/proc/self/ns/net") != parent, "requires a disposable network namespace"
    assert {link["ifname"] for link in ip("link", "show")} == {"lo"}, "requires an empty test namespace"
    mutate_ip("link", "set", "lo", "up")
    mutate_ip("link", "add", "uplink", "type", "dummy")
    mutate_ip("link", "set", "uplink", "up")
    process = None
    cookie = ""
    with tempfile.TemporaryDirectory(prefix="riverlb-network-confirmation-") as directory:
        root = Path(directory)
        config = root / "config.toml"
        database = config.with_suffix(".db")
        journal = config.with_suffix(".confirmation.json")
        management = free_port()
        config.write_text(f'''management = "127.0.0.1:{management}"
connect_timeout_ms = 200
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
virtual_servers = []
[[network.vlans]]
name = "rlb100"
interface = "uplink"
tag = 100
[[network.self_ips]]
name = "inside"
address = "192.0.2.10/24"
vlan = "rlb100"
[[network.self_ips]]
name = "inside-secondary"
address = "192.0.2.20/24"
vlan = "rlb100"
[[network.routes]]
name = "test-route"
destination = "198.51.100.0/24"
gateway = "192.0.2.1"
vlan = "rlb100"
metric = 500
''')
        bootstrap(BINARY, config)

        def call(path, body=None, method=None, expected=200):
            connection = http.client.HTTPConnection("127.0.0.1", management, timeout=5)
            try:
                connection.request(
                    method or ("POST" if body is not None else "GET"),
                    path,
                    json.dumps(body) if body is not None else None,
                    {"Content-Type": "application/json", "X-RiverLB-Request": "configure", "Cookie": cookie},
                )
                response = connection.getresponse()
                raw = response.read().decode()
                assert response.status == expected, (response.status, expected, raw)
                return json.loads(raw) if raw.startswith(("{", "[")) else raw, dict(response.getheaders())
            finally:
                connection.close()

        def start():
            nonlocal process, cookie
            process = subprocess.Popen([BINARY, "serve", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                wait_until(lambda: call("/healthz")[0] == "ok")
            except BaseException:
                process.terminate()
                _, error = process.communicate(timeout=12)
                raise AssertionError(error.decode())
            _, headers = call("/api/v1/auth/login", {"username": "admin", "password": PASSWORD})
            cookie = headers["set-cookie"].split(";", 1)[0]

        def stop(crash=False):
            nonlocal process
            if process is not None:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
                _, error = process.communicate(timeout=12)
                if not crash:
                    assert process.returncode == 0, error.decode()
                process = None

        def trial():
            current = call("/api/v1/config")[0]
            proposed = copy.deepcopy(current["config"])
            proposed["network"]["vlans"][0]["tag"] = 200
            proposed["network"]["self_ips"][0]["address"] = "192.0.2.11/24"
            proposed["network"]["self_ips"] = proposed["network"]["self_ips"][:1]
            applied = call("/api/v1/config", {"revision": current["revision"], "config": proposed}, "PUT")[0]
            assert applied["confirmation"]["pending"]
            assert ip("-d", "link", "show", "rlb100")[0]["linkinfo"]["info_data"]["id"] == 200
            assert addresses() == {"192.0.2.11"}
            assert journal.exists()
            return applied["revision"]

        def addresses():
            return {
                address["local"]
                for link in ip("-4", "address", "show", "dev", "rlb100")
                for address in link["addr_info"]
            }

        def restored(expected_revision):
            current = call("/api/v1/config")[0]
            assert current["revision"] == expected_revision, current
            assert current["config"]["network"]["vlans"][0]["tag"] == 100
            assert ip("-d", "link", "show", "rlb100")[0]["linkinfo"]["info_data"]["id"] == 100
            assert addresses() == {"192.0.2.10", "192.0.2.20"}
            rules = ip("-N", "-4", "rule", "show")
            owned = {rule["src"].split("/", 1)[0] for rule in rules if rule.get("priority") == 18600}
            assert owned == {"192.0.2.10", "192.0.2.20"}, rules
            assert any(route["dst"] == "198.51.100.0/24" for route in ip("-4", "route", "show"))
            assert not journal.exists()

        try:
            start()
            trial_revision = trial()
            pending_bytes = journal.read_bytes()
            stop(crash=True)
            # A committed trial remains in Linux after SIGKILL; startup must
            # restore the prior tag, self IPs and source routes before serving.
            start()
            restored(trial_revision + 1)
            stop(crash=True)

            # Retry after the recovery database commit but before journal clear,
            # preserving and reusing the already-restored old VLAN.
            journal.write_bytes(pending_bytes)
            journal.chmod(0o600)
            start()
            restored(trial_revision + 1)
            stop(crash=True)

            # An unrelated same-name link must be preserved and fail startup.
            journal.write_bytes(pending_bytes)
            journal.chmod(0o600)
            mutate_ip("link", "del", "rlb100")
            mutate_ip("link", "add", "other-uplink", "type", "dummy")
            for creation in [
                ("link", "add", "rlb100", "type", "dummy"),
                ("link", "add", "link", "uplink", "name", "rlb100", "type", "vlan", "id", 300),
                ("link", "add", "link", "other-uplink", "name", "rlb100", "type", "vlan", "id", 100),
            ]:
                mutate_ip(*creation)
                before = ip("-d", "link", "show", "rlb100")[0]
                failed = subprocess.Popen([BINARY, "serve", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    _, error = failed.communicate(timeout=12)
                except BaseException:
                    failed.kill()
                    failed.communicate(timeout=12)
                    raise
                assert failed.returncode != 0, "Foreign interface was adopted during confirmation recovery"
                assert journal.exists(), error.decode()
                after = ip("-d", "link", "show", "rlb100")[0]
                assert {key: before.get(key) for key in ("ifindex", "link_index", "linkinfo")} == {
                    key: after.get(key) for key in ("ifindex", "link_index", "linkinfo")
                }, (before, after)
                mutate_ip("link", "del", "rlb100")
            mutate_ip("link", "del", "other-uplink")
            start()
            restored(trial_revision + 1)

            # Simulate an interrupted prepare that has not committed the trial
            # revision, leaving a durable journal and partially removed links.
            trial_revision = trial()
            stop(crash=True)
            connection = sqlite3.connect(database)
            try:
                with connection:
                    connection.execute("DELETE FROM configurations WHERE revision=?", (trial_revision,))
            finally:
                connection.close()
            mutate_ip("link", "del", "rlb100")
            start()
            restored(trial_revision - 1)
            stop()
            assert {link["ifname"] for link in ip("link", "show")} == {"lo", "uplink"}
            assert not any(rule.get("priority") == 18600 for rule in ip("-N", "-4", "rule", "show"))
            print("PASS network confirmation: committed and uncommitted crash recovery, VLAN/self-IP/source routes, retry after DB recovery and foreign-interface refusal")
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=12)


def run_ha_history():
    """Real HA ownership withdrawal with a deterministic authority fixture.

    Cluster quorum/fencing decisions are fixture data, not live qualification.
    Addresses, source policies, gateways, restart and pending recovery are real.
    """
    assert {link["ifname"] for link in ip("link", "show")} == {"lo", "uplink"}
    assert ip("-d", "link", "show", "uplink")[0]["linkinfo"]["info_kind"] == "dummy"
    process = None
    cookie = ""
    with tempfile.TemporaryDirectory(prefix="riverlb-ha-network-confirmation-") as directory:
        root = Path(directory)
        config = root / "config.toml"
        settings = root / "ha.json"
        authority = root / "authority"
        management = free_port()
        traffic = free_port()
        config.write_text(f'''management = "127.0.0.1:{management}"
connect_timeout_ms = 100
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "floating-web"
listen = "203.0.113.70:{traffic}"
ingress_vlan = "external"
members = ["127.0.0.1:9"]
[[network.vlans]]
name = "external"
interface = "uplink"
ipv4_gateway = "192.0.2.1"
[[network.self_ips]]
name = "local"
address = "192.0.2.10/24"
vlan = "external"
[[network.self_ips]]
name = "floating"
address = "203.0.113.69/24"
vlan = "external"
''')
        authority.write_text('#!/usr/bin/python3\nprint(\'{"quorate":true,"fencing":true,"owner":"node-a"}\')\n')
        authority.chmod(0o700)
        settings.write_text(json.dumps({
            "cluster_id": "network-confirmation",
            "node_id": "node-a",
            "peer_id": "node-b",
            "socket": str(root / "ha.sock"),
            "state_file": str(root / "state.json"),
            "authority": str(authority),
            "floating_self_ips": ["floating"],
            "automatic_sync": False,
            "ssh_target": "root@192.0.2.20",
            "ssh_program": "/usr/bin/true",
            "ssh_identity": str(root / "identity"),
            "ssh_known_hosts": str(root / "known-hosts"),
            "peer_socket": str(root / "peer.sock"),
            "peer_binary": str(BINARY.resolve()),
            "sync_interval_secs": 1,
            "max_sync_age_secs": 120,
        }))
        settings.chmod(0o600)
        bootstrap(BINARY, config)

        def call(path, body=None, method=None):
            connection = http.client.HTTPConnection("127.0.0.1", management, timeout=5)
            try:
                connection.request(
                    method or ("POST" if body is not None else "GET"), path,
                    json.dumps(body) if body is not None else None,
                    {"Content-Type": "application/json", "X-RiverLB-Request": "configure", "Cookie": cookie},
                )
                response = connection.getresponse()
                raw = response.read().decode()
                assert response.status == 200, (response.status, raw)
                return json.loads(raw) if raw.startswith(("{", "[")) else raw, dict(response.getheaders())
            finally:
                connection.close()

        def start():
            nonlocal process, cookie
            process = subprocess.Popen([BINARY, "serve", "--config", config, "--ha-config", settings], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                wait_until(lambda: call("/healthz")[0] == "ok")
            except BaseException:
                process.terminate()
                _, error = process.communicate(timeout=12)
                raise AssertionError(error.decode())
            _, headers = call("/api/v1/auth/login", {"username": "admin", "password": PASSWORD})
            cookie = headers["set-cookie"].split(";", 1)[0]

        def stop(crash=False):
            nonlocal process
            if process is not None:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
                _, error = process.communicate(timeout=12)
                if not crash:
                    assert process.returncode == 0, error.decode()
                process = None

        def ha(action):
            result = subprocess.run([BINARY, "ha", "--socket", root / "ha.sock", action], capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr.decode()
            return json.loads(result.stdout)

        def addresses():
            return {
                address["local"]
                for link in ip("-4", "address", "show", "dev", "uplink")
                for address in link["addr_info"]
            }

        def change(address, gateway, confirm):
            current = call("/api/v1/config")[0]
            proposed = copy.deepcopy(current["config"])
            proposed["network"]["self_ips"][0]["address"] = address
            proposed["network"]["vlans"][0]["ipv4_gateway"] = gateway
            applied = call("/api/v1/config", {"revision": current["revision"], "config": proposed}, "PUT")[0]
            assert applied["confirmation"]["pending"]
            assert addresses() == {address.split("/", 1)[0], "203.0.113.69", "203.0.113.70"}
            if confirm:
                call("/api/v1/config/confirm", {"revision": applied["revision"]})
                assert not config.with_suffix(".confirmation.json").exists()
            history = json.loads(root.joinpath("state.ownership.json").read_text())
            assert len(history["configurations"]) == 2
            assert history["configurations"][0][0]["network"]["self_ips"][0]["address"] != address
            return applied["revision"]

        def standby(expected_revision):
            current = call("/api/v1/config")[0]
            assert current["revision"] == expected_revision
            assert current["config"]["network"]["self_ips"][0]["address"] == "198.51.100.10/24"
            assert ha("status")["role"] == "standby"
            assert addresses() == {"198.51.100.10"}
            rules = ip("-N", "-4", "rule", "show")
            assert {rule["src"].split("/", 1)[0] for rule in rules if rule.get("priority") == 18600} == {"198.51.100.10"}, rules
            route_state = ip("-N", "-4", "route", "show", "table", "all")
            routes = [route for route in route_state if str(route.get("protocol")) == "186"]
            assert any(route.get("gateway") == "198.51.100.1" for route in routes), (routes, route_state)
            assert not any(
                route.get("gateway") in {"192.0.2.1", "198.18.0.1"}
                or route.get("dst") in {"192.0.2.0/24", "198.18.0.0/24", "203.0.113.0/24", "203.0.113.69", "203.0.113.70"}
                for route in routes
            ), routes
            assert not config.with_suffix(".confirmation.json").exists()

        try:
            start()
            ha("seed")
            ha("activate")
            confirmed_revision = change("198.51.100.10/24", "198.51.100.1", confirm=True)
            stop(crash=True)
            # Normal confirmed-config restart must withdraw the active floating
            # addresses without installing policies from historical config A.
            start()
            standby(confirmed_revision)
            ha("seed")
            ha("activate")
            trial_revision = change("198.18.0.10/24", "198.18.0.1", confirm=False)
            stop(crash=True)
            # Pending recovery must likewise withdraw B/C ownership before
            # provisioning the confirmed standby B target and its gateway.
            start()
            standby(trial_revision + 1)
            stop()
            assert addresses() == set()
            assert not any(rule.get("priority") == 18600 for rule in ip("-N", "-4", "rule", "show"))
            print("PASS HA network recovery: historical ownership withdrawal, changed local subnet/gateway, confirmed and pending crash restart, standby policies and no floating ownership (authority fixture)")
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=12)


if __name__ == "__main__":
    run()
    run_ha_history()
