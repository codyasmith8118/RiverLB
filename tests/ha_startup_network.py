"""HA standby startup against real tagged VLANs in a disposable Linux netns.

Run with sudo unshare --net -- python3 tests/ha_startup_network.py, or an
equivalent user/net namespace. Only dummy eth1/eth2, local sockets and temporary
application state are used. Cluster authority and SSH transport are fixtures.
"""
import json
import os
import signal
import socket
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from auth_helpers import bootstrap, management_tls_fixture
from smoke import BINARY, free_port, wait_until


IP = "/usr/sbin/ip"
LOCAL = {"10.10.20.10", "10.10.10.10"}
FLOATING = {"10.10.20.100", "10.10.10.100"}
VLANS = {
    "internal3020": ("eth1", 3020, "10.10.20.10", "10.10.20.0/24", "10.10.20.1"),
    "external3010": ("eth2", 3010, "10.10.10.10", "10.10.10.0/24", "10.10.10.1"),
}


def ip(*args):
    return json.loads(subprocess.check_output([IP, "-j", *map(str, args)]))


def mutate_ip(*args):
    subprocess.run([IP, *map(str, args)], check=True, capture_output=True)


def addresses():
    return {
        address["local"]
        for link in ip("-4", "address", "show")
        for address in link["addr_info"]
        if link["ifname"] in VLANS
    }


def source_rules():
    return [rule for rule in ip("-N", "-4", "rule", "show") if rule.get("priority") == 18600]


def assert_standby_network():
    links = ip("-d", "link", "show")
    indices = {link["ifname"]: link["ifindex"] for link in links}
    assert set(indices) == {"lo", "eth1", "eth2", *VLANS}, links
    for name, (parent, tag, local, subnet, gateway) in VLANS.items():
        link = next(link for link in links if link["ifname"] == name)
        assert link.get("link_index") == indices[parent] or link.get("link") == parent, link
        assert link["linkinfo"]["info_kind"] == "vlan", link
        assert link["linkinfo"]["info_data"]["id"] == tag, link
        assert "UP" in link["flags"], link
        configured = [address for device in ip("-4", "address", "show", "dev", name)
                      for address in device["addr_info"]]
        assert {(address["local"], address["prefixlen"]) for address in configured} == {(local, 24)}, configured

        rules = [rule for rule in source_rules() if rule["src"].split("/", 1)[0] == local]
        assert len(rules) == 1, rules
        routes = ip("-N", "-4", "route", "show", "table", rules[0]["table"])
        assert any(route.get("dst") == subnet and route.get("dev") == name for route in routes), routes
        assert any(route.get("dst") == "default" and route.get("gateway") == gateway
                   and route.get("dev") == name for route in routes), routes
        assert any(route.get("dst") == "default" and str(route.get("type")) in {"unreachable", "7"}
                   and route.get("metric") == 4294967295 for route in routes), routes
        # Exercise Linux's actual source-policy lookup without sending packets.
        lookup = ip("-4", "route", "get", "203.0.113.9", "from", local)[0]
        assert lookup.get("dev") == name and lookup.get("gateway") == gateway, lookup

    rules = source_rules()
    assert len(rules) == len(LOCAL), rules
    assert {rule["src"].split("/", 1)[0] for rule in rules} == LOCAL, rules
    assert addresses() == LOCAL, addresses()
    routes = ip("-4", "route", "show")
    assert any(route.get("dst") == "10.200.0.0/16" and route.get("gateway") == "10.10.20.1"
               and route.get("dev") == "internal3020" for route in routes), routes


def assert_clean_kernel():
    assert {link["ifname"] for link in ip("link", "show")} == {"lo", "eth1", "eth2"}
    assert not source_rules(), source_rules()
    assert not ip("-4", "route", "show"), ip("-4", "route", "show")
    assert not ip("-N", "-4", "route", "show", "table", "all", "protocol", 186)


def run():
    parent = os.environ.get("RIVERLB_TEST_PARENT_NETNS")
    if parent is None:
        parent = os.readlink("/proc/1/ns/net")
    assert os.readlink("/proc/self/ns/net") != parent, "requires a disposable network namespace"
    assert os.geteuid() == 0, "requires root in the test user namespace for private HA settings"
    assert {link["ifname"] for link in ip("link", "show")} == {"lo"}, "requires an empty test namespace"
    # Standalone startup otherwise discovers installed HA settings outside the fixture.
    assert not Path("/etc/riverlb/ha.json").exists(), "requires a test environment without installed HA settings"
    mutate_ip("link", "set", "lo", "up")
    for name in ("eth1", "eth2"):
        mutate_ip("link", "add", name, "type", "dummy")
        mutate_ip("link", "set", name, "up")

    process = None
    with tempfile.TemporaryDirectory(prefix="riverlb-ha-startup-") as directory:
        root = Path(directory)
        cert, key, tls_context = management_tls_fixture(root, ["10.10.20.10"])
        config = root / "config.toml"
        settings = root / "ha.json"
        control_socket = root / "ha.sock"
        journal = root / "state.ownership.json"
        logfile = root / "daemon.log"
        management, proxy = free_port(), free_port()
        while proxy == management:
            proxy = free_port()
        config.write_text(f'''management = "10.10.20.10:{management}"
management_tls = {{certificate = "{cert}", private_key = "{key}"}}
connect_timeout_ms = 100
session_timeout_secs = 5
health_interval_secs = 1
max_connections = 10
[[virtual_servers]]
name = "web"
listen = "10.10.10.100:{proxy}"
algorithm = "round_robin"
ingress_vlan = "external3010"
members = ["127.0.0.1:9"]
[[network.vlans]]
name = "internal3020"
interface = "eth1"
tag = 3020
role = "internal"
ipv4_gateway = "10.10.20.1"
[[network.vlans]]
name = "external3010"
interface = "eth2"
tag = 3010
role = "external"
ipv4_gateway = "10.10.10.1"
[[network.self_ips]]
name = "internal-local"
address = "10.10.20.10/24"
vlan = "internal3020"
[[network.self_ips]]
name = "external-local"
address = "10.10.10.10/24"
vlan = "external3010"
[[network.self_ips]]
name = "internal-floating"
address = "10.10.20.100/24"
vlan = "internal3020"
[[network.routes]]
name = "backend-route"
destination = "10.200.0.0/16"
gateway = "10.10.20.1"
vlan = "internal3020"
metric = 500
''')
        bootstrap(BINARY, config)
        authority = root / "authority"
        authority.write_text('#!/usr/bin/python3\nprint(\'{"quorate":true,"fencing":true,"owner":null}\')\n')
        authority.chmod(0o700)
        transport = root / "ssh"
        transport.write_text("#!/bin/sh\nexit 1\n")
        transport.chmod(0o700)
        ha_settings = dict(
            automatic_sync=False, cluster_id="startup-test", node_id="riverlb-a", peer_id="riverlb-b",
            socket=str(control_socket), state_file=str(root / "state.json"), authority=str(authority),
            floating_self_ips=["internal-floating"], ssh_target="root@127.0.0.1",
            ssh_program=str(transport), ssh_identity=str(root / "identity"),
            ssh_known_hosts=str(root / "known-hosts"), peer_socket=str(root / "peer.sock"),
            peer_binary=str(BINARY.resolve()), sync_interval_secs=60, max_sync_age_secs=300,
        )

        def enable_ha():
            settings.write_text(json.dumps(ha_settings))
            settings.chmod(0o600)

        def command(ha=True):
            return [BINARY, "serve", "-c", config, *(["--ha-config", settings] if ha else [])]

        def ha(action):
            result = subprocess.run([BINARY, "ha", "--socket", control_socket, action],
                                    capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr.decode()
            return json.loads(result.stdout)

        def start(with_ha=True):
            nonlocal process
            with logfile.open("a") as log:
                process = subprocess.Popen(command(with_ha), stdout=log, stderr=log)

            def ready():
                if process.poll() is not None:
                    raise AssertionError(logfile.read_text())
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls_context))
                with client.open(f"https://10.10.20.10:{management}/healthz", timeout=1) as response:
                    assert response.read() == b"ok"
                return not with_ha or (control_socket.exists() and ha("status")["role"] == "standby")

            try:
                wait_until(ready)
            except BaseException:
                stop(crash=True)
                raise AssertionError(logfile.read_text())

        def stop(crash=False):
            nonlocal process
            if process is not None:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
                process.wait(timeout=15)
                if not crash:
                    assert process.returncode == 0, logfile.read_text()
                process = None

        def activate_and_crash():
            ha("seed")
            ha("activate")
            status = ha("status")
            assert status["role"] == "active" and status["data_ready"], status
            assert addresses() == LOCAL | FLOATING, addresses()
            assert journal.exists() and journal.stat().st_uid == 0
            assert journal.stat().st_mode & 0o077 == 0
            stop(crash=True)
            assert addresses() == LOCAL | FLOATING, addresses()

        try:
            # No prior process has created either tagged device or an ownership journal.
            enable_ha()
            assert not journal.exists()
            assert_clean_kernel()
            start()
            assert_standby_network()
            stop()
            assert_clean_kernel()

            # A clean standalone stop removes the VLANs before HA is enabled.
            settings.unlink()
            start(with_ha=False)
            assert addresses() == LOCAL | FLOATING, addresses()
            stop()
            assert_clean_kernel()
            enable_ha()
            start()
            assert_standby_network()

            # Crash while active: restart must withdraw both VIP and floating self IP.
            activate_and_crash()
            start()
            assert_standby_network()
            standby_tables = {rule["table"] for rule in source_rules()}
            standby_links = {link["ifname"]: link["ifindex"] for link in ip("link", "show")}

            # Withdrawal remains in force if management binding subsequently fails.
            activate_and_crash()
            with socket.socket() as blocker:
                blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                blocker.bind(("10.10.20.10", management))
                blocker.listen()
                failed = subprocess.run(command(), capture_output=True, timeout=15)
            assert failed.returncode != 0, failed.stdout
            assert b"Address already in use" in failed.stderr, failed.stderr.decode()
            assert {link["ifname"]: link["ifindex"] for link in ip("link", "show")} == standby_links
            assert addresses() == LOCAL, addresses()
            # Failed startup may roll back newly restored local policies; it must
            # never compensate withdrawal by restoring floating source rules.
            assert {rule["src"].split("/", 1)[0] for rule in source_rules()} <= LOCAL, source_rules()

            # Model a reboot after failed recovery: the ownership journal survives,
            # but all managed kernel objects have disappeared. Source rules and
            # unreachable guards need explicit removal when only deleting links.
            saved_journal = journal.read_bytes()
            routes = ip("-N", "-4", "route", "show", "table", "all", "protocol", 186)
            for table in standby_tables:
                if any(str(route.get("table")) == str(table) for route in routes):
                    mutate_ip("-4", "route", "flush", "table", table)
            for _ in source_rules():
                mutate_ip("-4", "rule", "del", "priority", 18600)
            for name in VLANS:
                mutate_ip("link", "del", name)
            assert_clean_kernel()
            assert journal.read_bytes() == saved_journal
            start()
            assert_standby_network()
            stop()
            assert_clean_kernel()
            print("PASS HA startup: fresh tagged VLANs, local source routes/gateways, standalone-to-HA clean restart, "
                  "crashed active withdrawal, failed-start ownership safety and empty-kernel journal retry")
        finally:
            stop(crash=True)


if __name__ == "__main__":
    run()
