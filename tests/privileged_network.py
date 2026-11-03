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


def client():
    request = json.load(sys.stdin)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(SOCKET)
        challenge = receive(connection)
        request.update(version=1, nonce=challenge['nonce'])
        encoded = json.dumps(request).encode()
        connection.sendall(struct.pack('!I', len(encoded)) + encoded)
        print(json.dumps(receive(connection)))


def call(argv, accepted=True, changed=None):
    process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--request'],
                             input=json.dumps(dict(action='network', parameters=dict(argv=argv))),
                             capture_output=True, text=True, timeout=15,
                             user=1001, group=1001, extra_groups=[])
    assert process.returncode == 0, process.stderr
    response = json.loads(process.stdout)
    assert response['ok'] is accepted, (argv, response)
    if accepted:
        assert response['result']['code'] == 0, (argv, response)
        if changed is not None:
            assert response['result']['changed'] is changed, (argv, response)


def ip(*arguments):
    return subprocess.check_output(['/usr/sbin/ip', *arguments], text=True)


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
    else:
        assert sys.argv[1:] == []
        main()
