"""Real routed automap and explicit SNAT in isolated namespaces; no host changes."""
import json
import os
import signal
import socket
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until
from auth_helpers import bootstrap


def run():
    parent=os.environ.get('RIVERLB_TEST_PARENT_NETNS') or str(Path('/proc/1/ns/net').readlink())
    assert str(Path('/proc/self/ns/net').readlink()) != parent, 'requires isolated namespace'
    assert {i['ifname'] for i in json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'link']))} == {'lo'}
    backend = subprocess.Popen(['unshare', '--net', '--', 'python3', 'tests/nat_backend.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    process = None
    try:
        pid = int(backend.stdout.readline())
        for args in [('link', 'add', 'uplink', 'type', 'veth', 'peer', 'name', 'srv0'), ('link', 'set', 'srv0', 'netns', str(pid)), ('link', 'set', 'uplink', 'up')]:
            subprocess.run(['/usr/sbin/ip', *args], check=True)
        backend.stdin.write('ready\n'); backend.stdin.flush()
        backend_port = int(backend.stdout.readline())
        admin, proxy = free_port(), free_port()
        def api(body=None):
            request = urllib.request.Request(f'http://127.0.0.1:{admin}/api/v1/config',
                data=json.dumps(body).encode() if body else None, method='PUT' if body else 'GET',
                headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.load(response)
        def transfer():
            with socket.create_connection(('127.0.0.1', proxy), timeout=3) as client:
                client.sendall(b'test'); client.shutdown(socket.SHUT_WR)
                data = b''
                while chunk := client.recv(4096): data += chunk
                return json.loads(data)['source']
        with tempfile.TemporaryDirectory(prefix='riverlb-automap-') as folder:
            path = Path(folder)/'config.toml'
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 1000
session_timeout_secs = 10
health_interval_secs = 1
max_connections = 64
[[virtual_servers]]
name = "automap"
listen = "127.0.0.1:{proxy}"
members = ["192.0.2.100:{backend_port}"]
source_nat = {{ mode = "automap" }}
[[network.vlans]]
name = "inside"
interface = "uplink"
[[network.self_ips]]
name = "first"
address = "192.0.2.10/24"
vlan = "inside"
''')
            bootstrap(BINARY, path)
            with (Path(folder)/'log').open('w+') as log:
                process = subprocess.Popen([BINARY,'serve','-c',path,'--manage-network'], stdout=log, stderr=log)
                wait_until(lambda: api()['revision'] == 1)
                assert transfer() == '192.0.2.10', 'automap must select egress self IP'
                document = api()
                document['config']['network']['self_ips'].append({'name':'second','address':'192.0.2.11/24','vlan':'inside'})
                document['config']['virtual_servers'][0]['source_nat'] = {'mode':'snat','addresses':['192.0.2.10','192.0.2.11']}
                api({'revision':document['revision'],'config':document['config']})
                def members_ready():
                    with urllib.request.urlopen(f'http://127.0.0.1:{admin}/api/v1/status',timeout=5) as response:
                        status=json.load(response)
                    return all(member['healthy'] for server in status['virtual_servers'] for member in server['members'])
                wait_until(members_ready)  # Changed probe source waits for its asynchronous first check.
                assert [transfer(), transfer(), transfer(), transfer()] == ['192.0.2.10','192.0.2.11','192.0.2.10','192.0.2.11']
                process.send_signal(signal.SIGTERM); assert process.wait(timeout=12) == 0
                addresses = json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show','dev','uplink']))
                assert not any(a['local'] in ['192.0.2.10','192.0.2.11'] for interface in addresses for a in interface['addr_info'])
                print('PASS routed NAT: real egress automap, explicit source rotation, managed cleanup, isolated backend namespace')
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM); process.wait(timeout=12)
        backend.terminate(); backend.wait(timeout=5)


if __name__ == '__main__':
    run()
