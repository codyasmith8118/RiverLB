"""External/internal traffic isolation; run inside a disposable network namespace.

Creates separate client and backend namespaces connected by veth pairs. Never
changes the VM's adapters. Requires iproute2, util-linux and CAP_NET_ADMIN in the
test namespace (an unprivileged user namespace can supply it).
"""
import copy
import argparse
import json
import os
import signal
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until


def ip(*args):
    subprocess.run(["/usr/sbin/ip", *map(str, args)], check=True, capture_output=True)


def inside(namespace, *command, **kwargs):
    return subprocess.run(["nsenter", "-t", str(namespace.pid), "-n", "--", *command],
                          check=True, capture_output=True, **kwargs)


def run(tagged=False):
    parent = os.environ.get('RIVERLB_TEST_PARENT_NETNS')
    if parent is None:
        parent = os.readlink('/proc/1/ns/net')
    assert os.readlink('/proc/self/ns/net') != parent, \
        'requires a disposable network namespace'
    links = json.loads(subprocess.check_output(['/usr/sbin/ip','-j','link','show']))
    assert {i['ifname'] for i in links} == {'lo'}, 'requires an empty test namespace'
    ip('link', 'set', 'lo', 'up')
    client = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
    backend = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
    process = service = None
    client_device = 'client100' if tagged else 'client0'
    backend_device = 'backend200' if tagged else 'backend0'
    try:
        for namespace in [client, backend]:
            wait_until(lambda: os.readlink(f'/proc/{namespace.pid}/ns/net') != os.readlink('/proc/self/ns/net'))
            inside(namespace, '/usr/sbin/ip', 'link', 'set', 'lo', 'up')
        for device, peer, namespace, address, tag, traffic_device in [
            ('rlb-ext', 'client0', client, '192.0.2.20/24', 100, client_device),
            ('rlb-int', 'backend0', backend, '198.51.100.20/24', 200, backend_device),
        ]:
            ip('link', 'add', device, 'type', 'veth', 'peer', 'name', peer)
            ip('link', 'set', peer, 'netns', namespace.pid)
            ip('link', 'set', device, 'up')
            inside(namespace, '/usr/sbin/ip', 'link', 'set', peer, 'up')
            if tagged:
                inside(namespace, '/usr/sbin/ip', 'link', 'add', 'link', peer, 'name', traffic_device,
                       'type', 'vlan', 'id', str(tag))
                inside(namespace, '/usr/sbin/ip', 'link', 'set', traffic_device, 'up')
            inside(namespace, '/usr/sbin/ip', 'address', 'add', address, 'dev', traffic_device)
        inside(client, '/usr/sbin/ip', '-6', 'address', 'add', '2001:db8:1::20/64', 'dev', client_device, 'nodad')
        inside(backend, '/usr/sbin/ip', '-6', 'address', 'add', '2001:db8:2::20/64', 'dev', backend_device, 'nodad')
        admin, proxy = free_port(), free_port()
        with tempfile.TemporaryDirectory(prefix='riverlb-two-arm-') as folder:
            root = Path(folder)
            sources = root / 'sources'
            service_code = '''
import socket, threading, sys
def reply(sock,source):
    with open(sys.argv[1],'a') as log: log.write(source[0]+'\\n')
    with sock:
        sock.settimeout(3)
        try:
            data=sock.recv(4096)
            if data: sock.sendall(data)
        except OSError: pass
def listen(family,address):
    listener=socket.socket(family); listener.bind((address,8001)); listener.listen()
    while True:
        sock,source=listener.accept()
        threading.Thread(target=reply,args=(sock,source),daemon=True).start()
threading.Thread(target=listen,args=(socket.AF_INET6,'2001:db8:2::20'),daemon=True).start()
listen(socket.AF_INET,'198.51.100.20')
'''
            service = subprocess.Popen(['nsenter', '-t', str(backend.pid), '-n', '--',
                                        'python3', '-c', service_code, str(sources)])
            path = root / 'config.toml'
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 300
session_timeout_secs = 5
health_interval_secs = 1
max_connections = 32
[[virtual_servers]]
name = "two-arm"
listen = "192.0.2.11:{proxy}"
ingress_vlan = "external"
backend_vlan = "internal"
members = ["198.51.100.20:8001"]
[[virtual_servers]]
name = "two-arm-v6"
listen = "[2001:db8:1::11]:{proxy}"
ingress_vlan = "external"
backend_vlan = "internal"
members = ["[2001:db8:2::20]:8001"]
[[network.vlans]]
name = "external"
interface = "rlb-ext"
{'tag = 100' if tagged else ''}
role = "external"
ipv4_gateway = "192.0.2.20"
ipv6_gateway = "2001:db8:1::20"
[[network.vlans]]
name = "internal"
interface = "rlb-int"
{'tag = 200' if tagged else ''}
role = "internal"
[[network.self_ips]]
name = "external-self"
address = "192.0.2.10/24"
vlan = "external"
[[network.self_ips]]
name = "internal-self"
address = "198.51.100.10/24"
vlan = "internal"
[[network.self_ips]]
name = "external-self-v6"
address = "2001:db8:1::10/64"
vlan = "external"
[[network.self_ips]]
name = "internal-self-v6"
address = "2001:db8:2::10/64"
vlan = "internal"
''')
            bootstrap(BINARY, path)
            with (root / 'log').open('w+') as log:
                process = subprocess.Popen([BINARY, 'serve', '-c', path], stdout=log, stderr=log)

                def api(method='GET', body=None, expected=200, route='/api/v1/config'):
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError('RiverLB exited: ' + log.read())
                    request = urllib.request.Request(f'http://127.0.0.1:{admin}'+route,
                        method=method, data=json.dumps(body).encode() if body else None,
                        headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
                    try:
                        response = urllib.request.urlopen(request, timeout=5)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        result = json.load(response)
                        assert response.code == expected, result
                        return result

                def confirm(saved):
                    if saved.get('confirmation',{}).get('pending'):
                        api('POST',{'revision':saved['revision']},route='/api/v1/config/confirm')

                wait_until(lambda: api()['network_mode'] == 'managed')
                request_code = '''
import socket, sys
with socket.create_connection((sys.argv[2],int(sys.argv[1])),timeout=1) as sock:
    sock.sendall(b'external-to-internal'); assert sock.recv(100)==b'external-to-internal'
'''

                def forward():
                    try:
                        for destination in ['192.0.2.11', '2001:db8:1::11']:
                            inside(client, 'python3', '-c', request_code, str(proxy), destination)
                    except subprocess.CalledProcessError:
                        return False
                    return True

                wait_until(forward)
                # Assigned self IPs must answer ICMP from the client network,
                # including across real 802.1Q tagged links in the tagged fixture.
                inside(client, 'ping', '-c', '1', '-W', '2', '192.0.2.10')
                inside(client, 'ping', '-6', '-c', '1', '-W', '2', '2001:db8:1::10')
                inside(client, 'ping', '-c', '1', '-W', '2', '192.0.2.11')
                inside(client, 'ping', '-6', '-c', '1', '-W', '2', '2001:db8:1::11')
                # The client also represents a routed network. Main-table routes
                # deliberately point at the wrong interface; replies must follow
                # the VIP/self-IP's ingress VLAN instead, including with strict RPF.
                inside(client, '/usr/sbin/ip', 'address', 'add', '198.18.0.20/32', 'dev', 'lo')
                inside(client, '/usr/sbin/ip', '-6', 'address', 'add', '2001:db8:9::20/128', 'dev', 'lo', 'nodad')
                ip('route', 'add', '198.18.0.0/24', 'dev', 'rlb-int')
                ip('-6', 'route', 'add', '2001:db8:9::/64', 'dev', 'rlb-int')
                subprocess.run(['sysctl','-w',f'net.ipv4.conf.{"external" if tagged else "rlb-ext"}.rp_filter=1'],check=True,capture_output=True)
                for source,destinations in [('198.18.0.20',['192.0.2.10','192.0.2.11']),('2001:db8:9::20',['2001:db8:1::10','2001:db8:1::11'])]:
                    for destination in destinations:
                        inside(client,'ping','-c','1','-W','2','-I',source,destination)
                    inside(client,'python3','-c','''import socket,sys
with socket.create_connection((sys.argv[2],int(sys.argv[1])),timeout=2,source_address=(sys.argv[3],0)) as sock:
    sock.sendall(b'external-to-internal');assert sock.recv(100)==b'external-to-internal'
''',str(proxy),destinations[1],source)
                # Both health probes and application sockets use the internal self IP.
                assert sources.read_text().splitlines()
                assert set(sources.read_text().splitlines()) == {'198.51.100.10', '2001:db8:2::10'}
                inside(backend, '/usr/sbin/ip', 'route', 'add', '192.0.2.0/24',
                       'via', '198.51.100.10', 'dev', backend_device)
                inside(backend, '/usr/sbin/ip', '-6', 'route', 'add', '2001:db8:1::/64',
                       'via', '2001:db8:2::10', 'dev', backend_device)
                for destination in ['192.0.2.11', '2001:db8:1::11']:
                    inside(backend, 'python3', '-c', '''
import socket, sys
try:
    socket.create_connection((sys.argv[2],int(sys.argv[1])),timeout=.5)
except OSError: pass
else: raise AssertionError('Internal ingress reached external-only listener')
''', str(proxy), destination)
                saved = api()
                config = saved['config']
                # Without a VLAN return route, policy lookup fails rather than
                # escaping through the wrong main-table route. Restore gateways
                # through normal apply to verify the live routing update.
                missing_gateway=copy.deepcopy(config)
                missing_gateway['network']['vlans'][0].pop('ipv4_gateway')
                missing_gateway['network']['vlans'][0].pop('ipv6_gateway')
                saved=api('PUT',dict(revision=saved['revision'],config=missing_gateway))
                for family,destination,sources_on_vlan in [('-4','198.18.0.20',['192.0.2.10','192.0.2.11']),('-6','2001:db8:9::20',['2001:db8:1::10','2001:db8:1::11'])]:
                    for source in sources_on_vlan:
                        lookup=subprocess.run(['/usr/sbin/ip',family,'route','get',destination,'from',source],capture_output=True)
                        assert lookup.returncode != 0,lookup.stdout
                confirm(saved)
                saved=api('PUT',dict(revision=saved['revision'],config=config))
                wait_until(forward)
                confirm(saved)
                invalid = copy.deepcopy(config)
                invalid['virtual_servers'][0]['ingress_vlan'] = 'internal'
                api('PUT', dict(revision=saved['revision'],config=invalid), expected=409)
                assert api()['revision'] == saved['revision']
                wait_until(forward)
                if tagged:
                    # Same device name but a different tag must not silently reuse
                    # a socket attached to the old kernel interface index.
                    invalid = copy.deepcopy(config)
                    invalid['network']['vlans'][0]['tag'] = 101
                    api('PUT', dict(revision=saved['revision'],config=invalid), expected=409)
                    assert api()['revision'] == saved['revision']
                    assert forward()
                # Role metadata changes leave managed links and listening sockets intact.
                config['network']['vlans'][0]['role'] = 'internal'
                saved = api('PUT', dict(revision=saved['revision'], config=config))
                assert forward()
                confirm(saved)
                # Automap also honors the selected backend device.
                config['virtual_servers'][0]['source_nat'] = {'mode':'automap'}
                saved = api('PUT', dict(revision=saved['revision'],config=config))
                assert forward()
                config['virtual_servers'][0]['source_nat'] = {'mode':'snat','addresses':['198.51.100.10']}
                saved = api('PUT', dict(revision=saved['revision'],config=config))
                assert forward()
                assert set(sources.read_text().splitlines()) == {'198.51.100.10', '2001:db8:2::10'}
                # A backend pinned to the wrong device must fail rather than
                # falling back to the working internal route.
                wrong_egress = copy.deepcopy(config)
                wrong_egress['virtual_servers'][0]['backend_vlan'] = 'external'
                wrong_egress['virtual_servers'][0].pop('source_nat', None)
                saved = api('PUT', dict(revision=saved['revision'],config=wrong_egress))
                assert not forward(), 'Backend escaped its configured egress device'
                assert set(sources.read_text().splitlines()) == {'198.51.100.10', '2001:db8:2::10'}
                saved = api('PUT', dict(revision=saved['revision'],config=config))
                wait_until(forward)
                confirm(saved)
                # A nonexistent adapter fails apply and leaves the old generation serving.
                invalid = copy.deepcopy(config)
                invalid['network']['vlans'][1]['interface'] = 'missing0'
                api('PUT', dict(revision=saved['revision'],config=invalid), expected=409)
                assert api()['revision'] == saved['revision']
                wait_until(forward)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=12) == 0
                addresses = json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show']))
                assert not any(a['local'] in ['192.0.2.10','192.0.2.11','198.51.100.10','2001:db8:1::10','2001:db8:1::11','2001:db8:2::10']
                               for i in addresses for a in i['addr_info'])
                for family in ['-4','-6']:
                    rules=json.loads(subprocess.check_output(['/usr/sbin/ip',family,'-j','rule','show']))
                    assert not any(r.get('priority')==18600 for r in rules), rules
                    routes=json.loads(subprocess.check_output(['/usr/sbin/ip',family,'-j','route','show','table','all','proto','186']))
                    assert routes == [], routes
                # A duplicate IPv6 address must fail startup and roll back even
                # the address whose DAD check failed (plus preceding objects).
                inside(client, '/usr/sbin/ip', '-6', 'address', 'add', '2001:db8:1::10/64',
                       'dev', client_device, 'nodad')
                failed = subprocess.run([BINARY,'serve','-c',path],
                                        capture_output=True, timeout=15)
                assert failed.returncode != 0, failed.stdout
                assert b'duplicate address detected' in failed.stderr, failed.stderr
                addresses = json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show']))
                assert not any(a['local'] in ['192.0.2.10','192.0.2.11','198.51.100.10','2001:db8:1::10','2001:db8:1::11','2001:db8:2::10']
                               for i in addresses for a in i['addr_info'])
                print('PASS two-arm return routing (' + ('tagged' if tagged else 'untagged') + '): IPv4/IPv6 external ingress, internal backend/probes, ingress rejection, automap/SNAT, reload safety, rollback, DAD failure cleanup')
    finally:
        for child in [process, service, client, backend]:
            if child and child.poll() is None:
                child.terminate()
                child.wait(timeout=12)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tagged',action='store_true')
    run(parser.parse_args().tagged)
