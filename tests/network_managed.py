from auth_helpers import bootstrap, session_token
"""Run only inside a disposable network namespace with CAP_NET_ADMIN.

The parent test harness creates `uplink` as a dummy interface. This never targets
the host eth0. Managed objects are removed on a clean daemon shutdown.
"""
import json
import signal
import socket
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until


def ip(*args):
    return json.loads(subprocess.check_output(["/usr/sbin/ip","-j",*args]))


def run():
    # Refuse accidental execution in the host namespace.
    links = ip("link","show")
    assert {i["ifname"] for i in links} == {"lo","uplink"}, "requires the isolated test namespace"
    subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True)
    admin,proxy,backend = free_port(),free_port(),free_port()
    listener = socket.socket(); listener.bind(("127.0.0.1",backend)); listener.listen(); listener.settimeout(.1)
    stopped=threading.Event(); sources=[]
    def reply(client):
        with client:
            client.settimeout(3)
            try:
                data=client.recv(100)
                if data: client.sendall(data)
            except OSError: pass
    def loop():
        while not stopped.is_set():
            try: client,source=listener.accept()
            except socket.timeout: continue
            except OSError: return
            sources.append(source[0]); threading.Thread(target=reply,args=(client,),daemon=True).start()
    threading.Thread(target=loop,daemon=True).start()
    process=None
    def api(method="GET",body=None,expected=200):
        req=urllib.request.Request(f"http://127.0.0.1:{admin}/api/v1/config",method=method,
            data=json.dumps(body).encode() if body else None,
            headers={"Content-Type":"application/json","X-RiverLB-Request":"configure"})
        try: response=urllib.request.urlopen(req,timeout=5)
        except urllib.error.HTTPError as error: response=error
        with response:
            assert response.code==expected,(response.code,response.read())
            return json.load(response)
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-managed-") as folder:
            path=Path(folder)/"config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 200
session_timeout_secs = 5
health_interval_secs = 1
max_connections = 10
[[virtual_servers]]
name = "test"
listen = "192.0.2.12:{proxy}"
algorithm = "round_robin"
source_self_ip = "inside"
members = ["127.0.0.1:{backend}"]
[[network.vlans]]
name = "rlb100"
interface = "uplink"
tag = 100
[[network.self_ips]]
name = "inside"
address = "192.0.2.10/24"
vlan = "rlb100"
[[network.self_ips]]
name = "inside-v6"
address = "2001:db8:100::10/64"
vlan = "rlb100"
[[network.routes]]
name = "test-route"
destination = "198.51.100.0/24"
gateway = "192.0.2.1"
vlan = "rlb100"
metric = 500
''')
            bootstrap(BINARY, path)
            # Automatic provisioning must fail clearly rather than silently
            # saving network objects when the deployed process lacks privileges.
            denied = subprocess.run(["setpriv", "--bounding-set=-net_admin", BINARY,
                                     "serve", "-c", path], capture_output=True, timeout=10)
            assert denied.returncode != 0
            assert b"CAP_NET_ADMIN" in denied.stderr, denied.stderr
            assert all(i["ifname"] != "rlb100" for i in ip("link", "show"))
            # A same-name interface with a different VLAN tag is a conflict.
            subprocess.run(["/usr/sbin/ip","link","add","link","uplink","name","rlb100","type","vlan","id","101"],check=True)
            conflict=subprocess.run([BINARY,"serve","-c",path],capture_output=True,timeout=10)
            assert conflict.returncode != 0
            assert b"does not match requested VLAN" in conflict.stderr, conflict.stderr
            assert ip("-d","link","show","rlb100")[0]["linkinfo"]["info_data"]["id"]==101
            subprocess.run(["/usr/sbin/ip","link","del","rlb100"],check=True)
            with (Path(folder)/"log").open("w+") as log:
                process=subprocess.Popen([BINARY,"serve","-c",path],stdout=log,stderr=log)
                try: wait_until(lambda:api()["network_mode"]=="managed")
                except AssertionError:
                    log.seek(0); raise AssertionError(log.read())
                assert ip("link","show","rlb100")
                assert any(a["local"]=="192.0.2.10" for i in ip("address","show","dev","rlb100") for a in i["addr_info"])
                assert any(a["local"]=="192.0.2.12" and a["prefixlen"]==32 for i in ip("address","show","dev","rlb100") for a in i["addr_info"])
                assert any(r["dst"]=="198.51.100.0/24" for r in ip("route","show"))
                with socket.create_connection(("192.0.2.12",proxy),timeout=2) as client:
                    client.sendall(b"test"); assert client.recv(100)==b"test"
                assert "192.0.2.10" in sources
                # An unclean exit leaves kernel objects. A failed restart must
                # preserve them; a successful restart must reuse them once.
                before_rules=ip("rule","show")
                before_rules_v6=ip("-6","rule","show")
                process.kill(); process.wait(timeout=10)
                blocker=socket.socket(); blocker.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); blocker.bind(("127.0.0.1",admin)); blocker.listen()
                try:
                    failed=subprocess.run([BINARY,"serve","-c",path],capture_output=True,timeout=15)
                    assert failed.returncode != 0, failed.stdout
                    assert b"Address already in use" in failed.stderr, (failed.stderr,ip("-N","-d","route","show","table","all"))
                    assert ip("link","show","rlb100")
                    assert any(a["local"]=="192.0.2.12" for d in ip("address","show","dev","rlb100") for a in d["addr_info"])
                    assert ip("rule","show")==before_rules
                    assert ip("-6","rule","show")==before_rules_v6
                finally: blocker.close()
                process=subprocess.Popen([BINARY,"serve","-c",path],stdout=log,stderr=log)
                try: wait_until(lambda:api()["network_mode"]=="managed")
                except AssertionError:
                    log.seek(0); raise AssertionError(log.read())
                assert ip("rule","show")==before_rules
                assert ip("-6","rule","show")==before_rules_v6
                with socket.create_connection(("192.0.2.12",proxy),timeout=2) as client:
                    client.sendall(b"restart"); assert client.recv(100)==b"restart"
                config=api()["config"]
                # Failure after creating an additional VLAN/address rolls back the kernel.
                broken=json.loads(json.dumps(config))
                broken["network"]["vlans"].append(dict(name="rlb200",interface="uplink",tag=200))
                broken["network"]["self_ips"].append(dict(name="second",address="203.0.113.10/24",vlan="rlb200"))
                broken["virtual_servers"][0]["listen"]="203.0.114.99:8081" # not assigned
                extra=json.loads(json.dumps(broken["virtual_servers"][0]))
                extra.update(name="new-vip",listen="203.0.113.12:8082",ingress_vlan="rlb200")
                broken["virtual_servers"].append(extra)
                api("PUT",dict(revision=1,config=broken),expected=409)
                assert all(i["ifname"]!="rlb200" for i in ip("link","show"))
                assert api()["revision"]==1
                # Remove the route and update a self IP through the API.
                config["network"]["routes"]=[]
                config["network"]["self_ips"][0]["address"]="192.0.2.11/24"
                config["virtual_servers"][0]["listen"]=f"192.0.2.13:{proxy}"
                api("PUT",dict(revision=1,config=config))
                assert not any(r["dst"]=="198.51.100.0/24" for r in ip("route","show"))
                with socket.create_connection(("192.0.2.13",proxy),timeout=2) as client:
                    client.sendall(b"new"); assert client.recv(100)==b"new"
                assert "192.0.2.11" in sources
                assert not any(a["local"]=="192.0.2.12" for i in ip("address","show","dev","rlb100") for a in i["addr_info"])
                process.send_signal(signal.SIGTERM)
                result=process.wait(timeout=12)
                if result != 0:
                    log.seek(0); raise AssertionError(log.read())
                assert all(i["ifname"]!="rlb100" for i in ip("link","show"))
                print("PASS managed network: VLAN/address/route, IPv4/IPv6 crash restart, conflict rejection, failed-start preservation, source binding, rollback, web updates, shutdown cleanup")
    finally:
        if process and process.poll() is None: process.terminate(); process.wait(timeout=12)
        stopped.set(); listener.close()


if __name__=="__main__": run()
