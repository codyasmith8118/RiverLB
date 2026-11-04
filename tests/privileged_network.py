#!/usr/bin/env python3
"""Real helper and non-root peer in an explicitly disposable container/netns."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SOCKET = '/run/riverlb-privileged/control.sock'


def receive(connection):
    def exact(length):
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                raise EOFError('Helper closed connection')
            result.extend(chunk)
        return result
    size = struct.unpack('!I', exact(4))[0]
    assert 0 < size <= 2 * 1024 * 1024
    return json.loads(exact(size))


def client(request=None):
    request = json.load(sys.stdin) if request is None else request
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(SOCKET)
        challenge = receive(connection)
        request.update(version=1, nonce=challenge['nonce'])
        encoded = json.dumps(request).encode()
        connection.sendall(struct.pack('!I', len(encoded)) + encoded)
        print(json.dumps(receive(connection)), flush=True)


def rpc(action, parameters, accepted=True, channel=None):
    request = json.dumps(dict(action=action, parameters=parameters))
    if channel is None:
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--request'],
                                 input=request, capture_output=True, text=True, timeout=30,
                                 user=1001, group=1001, extra_groups=[])
        assert process.returncode == 0, process.stderr
        response = json.loads(process.stdout)
    else:
        channel.stdin.write(request + '\n')
        channel.stdin.flush()
        response = json.loads(channel.stdout.readline())
    assert response['ok'] is accepted, (action, response)
    return response.get('result')


def call(argv, accepted=True, changed=None):
    result = rpc('network', dict(argv=argv), accepted)
    if accepted:
        assert result['code'] == 0, (argv, result)
        if changed is not None:
            assert result['changed'] is changed, (argv, result)


def ip(*arguments):
    return subprocess.check_output(['/usr/sbin/ip', *arguments], text=True)


def network_manager():
    Path('/run/dbus').mkdir(parents=True, exist_ok=True)
    Path('/etc/NetworkManager/conf.d').mkdir(parents=True, exist_ok=True)
    Path('/etc/NetworkManager/conf.d/no-auto.conf').write_text('[main]\nno-auto-default=*\n')
    subprocess.run(['dbus-uuidgen', '--ensure'], check=True)
    log = open('/tmp/riverlb-network-manager-test.log', 'w')
    bus = subprocess.Popen(['dbus-daemon', '--system', '--nofork', '--nopidfile'], stdout=log, stderr=log)
    manager, channel = None, None

    def nm(*args):
        return subprocess.check_output(['nmcli', '--wait', '15', '--escape', 'no', *args],
                                       text=True, stderr=subprocess.STDOUT, timeout=25).strip()

    def wait(predicate):
        for _ in range(100):
            try:
                if predicate():
                    return
            except subprocess.CalledProcessError:
                pass
            time.sleep(0.1)
        raise AssertionError('NetworkManager did not reach expected state')

    try:
        wait(lambda: Path('/run/dbus/system_bus_socket').exists())
        manager = subprocess.Popen(['NetworkManager', '--no-daemon'], stdout=log, stderr=log)
        wait(lambda: nm('-g', 'STATE', 'general') != '')
        nm('connection', 'add', 'type', 'ethernet', 'ifname', 'traffic0', 'con-name', 'baseline',
           'ipv4.method', 'manual', 'ipv4.addresses', '192.0.2.9/24',
           'ipv4.never-default', 'yes', 'ipv6.method', 'disabled')
        nm('connection', 'up', 'id', 'baseline')
        identifier = nm('-g', 'connection.uuid', 'connection', 'show', 'id', 'baseline')
        profile = next(path for path in Path('/etc/NetworkManager/system-connections').glob('*')
                       if identifier in path.read_text())
        channel = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--stream'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, user=1001, group=1001, extra_groups=[])

        def request(tool, argv, peer=channel, accepted=True):
            result = rpc('network_manager', dict(tool=tool, argv=argv), accepted=accepted, channel=peer)
            if accepted:
                assert result['code'] == 0, result
                return result['stdout']

        prefix = ['--system', '--timeout=3s', '--json=short', 'call',
                  'org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager', 'org.freedesktop.NetworkManager']
        device = json.loads(request('busctl', prefix + ['GetDeviceByIpIface', 's', 'traffic0']))['data'][0]

        def checkpoint():
            return json.loads(request('busctl', prefix + ['CheckpointCreate', 'aouu', '1', device, '90', '2']))['data'][0]

        def properties(address):
            result = {'connection.interface-name': 'traffic0', 'connection.autoconnect': 'yes', '802-3-ethernet.mtu': '1500'}
            for family in ['ipv4', 'ipv6']:
                result.update({family + '.' + key: value for key, value in {
                    'method': 'manual' if family == 'ipv4' else 'disabled',
                    'addresses': address if family == 'ipv4' else '', 'gateway': '', 'dns': '',
                    'never-default': 'yes', 'ignore-auto-dns': 'yes', 'route-metric': '100'}.items()})
            return [item for pair in result.items() for item in pair]

        def trial(address):
            request('nmcli', ['--wait', '15', '--escape', 'no', 'connection', 'modify', '--temporary',
                              'uuid', identifier, *properties(address)])
            request('nmcli', ['--wait', '15', '--escape', 'no', 'connection', 'up', 'uuid', identifier, 'ifname', 'traffic0'])

        current = checkpoint()
        trial('192.0.2.20/24')
        assert '192.0.2.20/24' in ip('address', 'show', 'dev', 'traffic0')
        assert '192.0.2.9/24' in profile.read_text()
        # A separate process with the same UID cannot confirm this peer's trial.
        request('busctl', prefix + ['CheckpointDestroy', 'o', current], peer=None, accepted=False)
        request('busctl', prefix + ['CheckpointRollback', 'o', current])
        wait(lambda: '192.0.2.9/24' in ip('address', 'show', 'dev', 'traffic0'))
        current = checkpoint()
        trial('192.0.2.30/24')
        request('nmcli', ['--wait', '15', '--escape', 'no', 'connection', 'modify', 'uuid', identifier,
                          'connection.autoconnect', 'yes'])
        request('busctl', prefix + ['CheckpointDestroy', 'o', current])
        assert '192.0.2.30/24' in profile.read_text()
        print('PASS real non-root NetworkManager helper: empty controller, peer-bound trial, rollback and persistent confirmation')
    finally:
        for process in [channel, manager, bus]:
            if process is not None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
        log.close()


def main():
    assert os.environ.get('RIVERLB_PRIVILEGED_TEST') == 'disposable-container'
    assert os.geteuid() == 0
    assert not Path('/etc/riverlb-privileged').exists(), 'Requires a clean disposable filesystem'
    for parent, mode in [('/etc/riverlb-privileged', 0o700), ('/var/lib/riverlb-privileged', 0o700),
                         ('/run/riverlb-privileged', 0o755)]:
        Path(parent).mkdir(mode=mode)
    Path('/etc/riverlb-privileged/policy.json').write_text(json.dumps(dict(
        version=1, uid=1001, gid=1001, traffic_interfaces=['traffic0'], management_interfaces=['mgmt0'])))
    for name in ['traffic', 'mgmt']:
        ip('link', 'add', name + '0', 'type', 'veth', 'peer', 'name', name + '1')
        for suffix in ['0', '1']:
            ip('link', 'set', name + suffix, 'up')
    ip('address', 'add', '198.51.100.1/24', 'dev', 'mgmt0')
    ip('address', 'add', '192.0.2.9/24', 'dev', 'traffic0')  # Borrowed OS state.
    # A pre-existing route bearing the application's marker still belongs to
    # the OS. The broker must detect it, leave it unowned, and preserve deletion.
    ip('-4', 'route', 'add', '203.0.113.0/24', 'via', '192.0.2.2', 'dev', 'traffic0', 'metric', '50', 'proto', '186')
    helper = subprocess.Popen([sys.executable, '-I', str(ROOT / 'deploy/privileged/riverlb-privileged'), 'serve'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            if Path(SOCKET).exists():
                break
            assert helper.poll() is None, helper.stdout.read()
            time.sleep(0.05)
        else:
            raise AssertionError('Helper did not become ready')
        call(['address', 'add', '198.51.100.2/24', 'dev', 'mgmt0'], accepted=False)
        call(['-batch', '/tmp/commands'], accepted=False)
        call(['address', 'add', '192.0.2.9/24', 'dev', 'traffic0'], changed=False)
        call(['address', 'del', '192.0.2.9/24', 'dev', 'traffic0'], changed=False)
        route = ['-4', 'route', 'add', '203.0.113.0/24', 'via', '192.0.2.2', 'dev', 'traffic0', 'metric', '50', 'proto', '186']
        call(route, changed=False)
        route[2] = 'del'
        call(route, changed=False)
        for prefix in ['192.0.2.70/24', '2001:db8::70/64']:
            call(['address', 'add', prefix, 'dev', 'traffic0'], changed=True)
            call(['address', 'add', prefix, 'dev', 'traffic0'], changed=False)
            family = '-4' if ':' not in prefix else '-6'
            source = prefix.split('/')[0] + ('/32' if family == '-4' else '/128')
            rule = [family, 'rule', 'add', 'from', source, 'lookup', '1000001', 'priority', '18600', 'protocol', '186']
            call(rule, changed=True)
            call(rule, changed=False)
            rule[2] = 'del'
            call(rule, changed=True)
            if family == '-4':
                bound = subprocess.run([sys.executable, '-c',
                    "import socket; from pathlib import Path; "
                    "assert next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')) == '0000000000000000'; "
                    "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'traffic0\\0'); s.bind(('192.0.2.70',0))"],
                    user=1001, group=1001, extra_groups=[], capture_output=True, text=True, timeout=5)
                assert bound.returncode == 0, bound.stderr
            call(['address', 'del', prefix, 'dev', 'traffic0'], changed=True)
        for family, prefix in [('-4', '192.0.2.0/24'), ('-6', '2001:db8::/64')]:
            route = [family, 'route', 'add', 'table', '1000001', prefix, 'dev', 'traffic0', 'scope', 'link', 'proto', '186']
            call(route, changed=True)
            call(route, changed=False)
            route[2] = 'del'
            call(route, changed=True)
            unreachable = [family, 'route', 'add', 'table', '1000001', 'unreachable', 'default',
                           'metric', '4294967295', 'proto', '186']
            call(unreachable, changed=True)
            call(unreachable, changed=False)
            unreachable[2] = 'del'
            call(unreachable, changed=True)
        call(['link', 'add', 'link', 'traffic0', 'name', 'vlan10', 'type', 'vlan', 'id', '10'], changed=True)
        call(['link', 'set', 'dev', 'vlan10', 'up'], changed=True)
        call(['address', 'add', '192.0.2.80/24', 'dev', 'vlan10'], changed=True)
        call(['address', 'del', '192.0.2.80/24', 'dev', 'vlan10'], changed=True)
        call(['link', 'del', 'dev', 'vlan10'], changed=True)
        assert '192.0.2.9/24' in ip('address', 'show', 'dev', 'traffic0')
        assert '203.0.113.0/24' in ip('-4', 'route', 'show', 'table', 'main')
        state = json.loads(Path('/var/lib/riverlb-privileged/ownership.json').read_text())
        assert not state['owned'] and state['intent'] is None, state
        print('PASS real non-root helper: IPv4/IPv6 address and route lifecycle, VLANs, borrowed state and management protection')
        network_manager()
    finally:
        helper.terminate()
        try:
            helper.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            helper.kill()
            helper.communicate()


if __name__ == '__main__':
    if sys.argv[1:] == ['--request']:
        client()
    elif sys.argv[1:] == ['--stream']:
        for line in sys.stdin:
            client(json.loads(line))
    else:
        assert sys.argv[1:] == []
        main()
