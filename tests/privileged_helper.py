#!/usr/bin/env python3
"""Closed grammars and real local transport rejection tests; no host mutations."""
import array
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest.mock import patch
import tempfile
import ipaddress
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('privileged_broker', str(ROOT / 'deploy/privileged/riverlb-privileged'))
spec = importlib.util.spec_from_loader(loader.name, loader)
broker = importlib.util.module_from_spec(spec)
loader.exec_module(broker)
policy = broker.policy


class Grammar(unittest.TestCase):
    def test_independent_ethernet_profile_preserves_empty_controller_field(self):
        instance = SimpleNamespace(state={}, configuration=dict(traffic_interfaces=['eth1'], management_interfaces=[]))
        for controller in ['', '--']:
            def execute(*args, **kwargs):
                return dict(code=0, stdout='eth1\n802-3-ethernet\n' + controller + '\n')
            manager = broker.nm_module.NetworkManager(instance, policy, execute, broker.success)
            self.assertEqual(manager.profile('12345678-1234-1234-1234-123456789abc'), 'eth1')

    def test_generated_network_shapes_and_inverse_identity(self):
        commands = [
            ['address', 'add', '192.0.2.1/24', 'dev', 'eth1'],
            ['address', 'add', '2001:db8::1/64', 'dev', 'vlan10'],
            ['link', 'add', 'link', 'eth1', 'name', 'vlan10', 'type', 'vlan', 'id', '10'],
            ['link', 'set', 'dev', 'vlan10', 'up'],
            ['link', 'del', 'dev', 'vlan10'],
            ['-4', 'route', 'add', '192.0.2.0/24', 'via', '198.51.100.1', 'dev', 'eth1', 'metric', '50', 'proto', '186'],
            ['-6', 'route', 'add', '2001:db8:2::/64', 'via', '2001:db8:1::1', 'dev', 'eth1', 'metric', '50', 'proto', '186', 'table', '1000001', 'onlink'],
            ['-4', 'route', 'add', 'table', '1000001', '192.0.2.0/24', 'dev', 'eth1', 'scope', 'link', 'proto', '186'],
            ['-6', 'route', 'add', 'table', '1000001', 'default', 'via', '2001:db8::1', 'dev', 'eth1', 'onlink', 'metric', '0', 'proto', '186'],
            ['-4', 'route', 'add', 'table', '1000001', 'unreachable', 'default', 'metric', '4294967295', 'proto', '186'],
            ['-6', 'rule', 'add', 'from', '2001:db8::1/128', 'lookup', '1000001', 'priority', '18600', 'protocol', '186'],
        ]
        for command in commands:
            with self.subTest(command=command):
                parsed = policy.network(command)
                self.assertEqual(parsed['argv'], command)
                if command[:2] == ['address', 'add'] or command[0] in {'-4', '-6'}:
                    inverse = list(command)
                    inverse[1 if command[0] == 'address' else 2] = 'del'
                    self.assertEqual(policy.network(inverse)['identity'], parsed['identity'])

    def test_forbidden_network_operations_and_injection(self):
        commands = [
            ['netns', 'exec', 'host', '/bin/sh'], ['-batch', '/tmp/commands'],
            ['link', 'set', 'dev', 'eth1', 'netns', '1'],
            ['link', 'set', 'dev', 'eth1', 'down'],
            ['address', 'flush', 'dev', 'eth1'],
            ['address', 'add', '192.0.2.1/24', 'dev', '../../eth1'],
            ['address', 'add', '192.0.2.1/24', 'dev', '-force'],
            ['address', 'add', '192.0.2.1/24', 'dev', 'eth1\nwhoami'],
            ['address', 'add', '127.0.0.1/8', 'dev', 'eth1'],
            ['-4', 'route', 'flush', 'table', 'main'],
            ['-4', 'route', 'add', 'table', '254', 'unreachable', 'default', 'metric', '4294967295', 'proto', '186'],
            ['-6', 'rule', 'add', 'from', '2001:db8::/64', 'lookup', '1000001', 'priority', '18600', 'protocol', '186'],
        ]
        for command in commands:
            with self.subTest(command=command), self.assertRaises(policy.Rejected):
                policy.network(command)

    def test_firewall_only_canonical_destination_rules(self):
        for version, ip in [('ipv4', '192.0.2.1'), ('ipv6', '2001:db8::1')]:
            rule = f'rule family="{version}" priority="18600" destination address="{ip}" port port="443" protocol="tcp" accept'
            for operation in ['add', 'remove', 'query']:
                result = policy.firewall(['--zone=public', '--permanent', f'--{operation}-rich-rule={rule}'])
                self.assertEqual(result['ip'], ip)
            for bad in [rule.replace('18600', '0'), rule + ' log', rule.replace('443', '0'),
                        rule.replace('tcp', 'all'), rule.replace(ip, '0.0.0.0/0')]:
                with self.assertRaises(policy.Rejected):
                    policy.firewall(['--zone=public', '--add-rich-rule=' + bad])
        for command in [['--reload'], ['--direct', '--add-rule', 'x'], ['--add-service=ssh'],
                        ['--zone=public;id', '--permanent', '--add-rich-rule=all']]:
            with self.assertRaises(policy.Rejected):
                policy.firewall(command)

    def test_ping_has_no_command_payload_or_file_options(self):
        self.assertEqual(policy.ping({'target': '192.0.2.1', 'timeout_ms': 1000})[-1], '192.0.2.1')
        for value in [{'target': '-f', 'timeout_ms': 1000},
                      {'target': '192.0.2.1', 'timeout_ms': True},
                      {'target': '192.0.2.1', 'timeout_ms': 60001},
                      {'target': '192.0.2.1', 'timeout_ms': 1, 'command': 'id'}]:
            with self.assertRaises(policy.Rejected):
                policy.ping(value)


class NetworkManagerPolicy(unittest.TestCase):
    def test_profiles_cannot_be_used_to_select_plugins_files_or_commands(self):
        identifier = '12345678-1234-1234-1234-123456789abc'
        prefix = ['--wait', '15', '--escape', 'no']
        good = prefix + ['connection', 'modify', '--temporary', 'uuid', identifier,
                         'connection.autoconnect', 'no']
        self.assertEqual(policy.nmcli(good)['uuid'], identifier)
        for command in [
            prefix + ['connection', 'delete', 'uuid', identifier],
            prefix + ['connection', 'import', 'type', 'vpn', 'file', '/root/secret'],
            prefix + ['-g', '802-1x.password', 'connection', 'show', 'uuid', identifier],
            prefix + ['connection', 'modify', '--temporary', 'uuid', identifier, 'connection.type', 'vpn'],
            prefix + ['connection', 'up', 'uuid', '--ask', 'ifname', 'eth1'],
            prefix + ['device', 'disconnect', '../eth1'],
        ]:
            with self.subTest(command=command), self.assertRaises(policy.Rejected):
                policy.nmcli(command)

    def test_bus_cannot_destroy_foreign_checkpoints_or_call_arbitrary_methods(self):
        prefix = ['--system', '--timeout=3s', '--json=short', 'call', policy.NM, policy.NM_PATH, policy.NM]
        good = prefix + ['CheckpointCreate', 'aouu', '1', policy.NM_PATH + '/Devices/2', '90', '2']
        self.assertEqual(policy.busctl(good)['kind'], 'create')
        for tail in [['CheckpointCreate', 'aouu', '1', policy.NM_PATH + '/Devices/2', '0', '1'],
                     ['CheckpointDestroy', 'o', ''], ['CheckpointDestroy', 'o', '/'],
                     ['Reload', 'u', '1'], ['Sleep', 'b', 'true']]:
            with self.subTest(tail=tail), self.assertRaises(policy.Rejected):
                policy.busctl(prefix + tail)

    def test_checkpoints_are_bound_to_the_real_peer_not_a_caller_claim(self):
        class Fake:
            configuration = dict(traffic_interfaces=['eth1'], management_interfaces=['eth0'])
            state = dict(nm_checkpoints={'/checkpoint': dict(interface='eth1', peer=[5, 1001, 1001],
                                                            deadline=10**12)})
        controller = broker.nm_module.NetworkManager(Fake(), policy, None, None)
        self.assertEqual(controller.checkpoint('eth1', (5, 1001, 1001))['interface'], 'eth1')
        with self.assertRaises(policy.Rejected):
            controller.checkpoint('eth1', (6, 1001, 1001))
        with self.assertRaises(policy.Rejected):
            controller.checkpoint('eth0', (5, 1001, 1001))


class Ownership(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        with patch.object(broker, 'save'):
            instance = broker.Broker(dict(version=1, uid=1001, gid=1001,
                                          traffic_interfaces=['eth1'], management_interfaces=['eth0']),
                                     Path(directory.name) / 'state.json')
        instance.checkpoint = lambda: None
        self.addCleanup(directory.cleanup)
        return instance

    def test_management_and_foreign_resources_are_never_removed(self):
        instance = self.fixture()
        links = [dict(ifname='eth0', ifindex=1), dict(ifname='eth1', ifindex=2)]
        with patch.object(broker, 'kernel_links', return_value=links), patch.object(broker, 'process') as execute:
            with self.assertRaises(policy.Rejected):
                instance.network({'argv': ['address', 'del', '192.0.2.1/24', 'dev', 'eth0']})
            result = instance.network({'argv': ['address', 'del', '192.0.2.2/24', 'dev', 'eth1']})
            self.assertFalse(result['changed'])
            execute.assert_not_called()
            rule = 'rule family="ipv4" priority="18600" destination address="192.0.2.2" port port="443" protocol="tcp" accept'
            result = instance.firewall({'argv': ['--zone=public', '--remove-rich-rule=' + rule]})
            self.assertFalse(result['changed'])
            execute.assert_not_called()

    def test_failed_creation_never_claims_ownership(self):
        instance = self.fixture()
        with patch.object(broker, 'kernel_links', return_value=[dict(ifname='eth1', ifindex=2)]), \
                patch.object(instance, 'present', return_value=False), \
                patch.object(broker, 'process', return_value=dict(code=2, stdout='', stderr='already exists')):
            result = instance.network({'argv': ['address', 'add', '192.0.2.2/24', 'dev', 'eth1']})
        self.assertEqual(result['code'], 2)
        self.assertEqual(instance.state['owned'], {})
        self.assertIsNone(instance.state['intent'])

    def test_borrowed_address_not_adopted_and_reboot_recreates_owned_address(self):
        instance = self.fixture()
        command = ['address', 'add', '192.0.2.2/24', 'dev', 'eth1']
        with patch.object(broker, 'kernel_links', return_value=[dict(ifname='eth1', ifindex=2)]), \
                patch.object(instance, 'present', return_value=True), patch.object(broker, 'process') as execute:
            self.assertFalse(instance.network({'argv': command})['changed'])
            execute.assert_not_called()
            self.assertEqual(instance.state['owned'], {})
        with patch.object(broker, 'kernel_links', return_value=[dict(ifname='eth1', ifindex=2)]), \
                patch.object(instance, 'present', return_value=False), \
                patch.object(broker, 'process', return_value=dict(code=0, stdout='', stderr='')) as execute:
            instance.network({'argv': command})
            self.assertEqual(len(instance.state['owned']), 1)
            # A kernel reboot removes the address, but the durable ownership survives.
            instance.network({'argv': command})
            self.assertEqual(execute.call_count, 2)
            self.assertEqual(len(instance.state['owned']), 1)

    def test_replaced_vlan_and_interrupted_intent_fail_closed(self):
        instance = self.fixture()
        key = json.dumps(['vlan', 'vlan10'])
        instance.state['owned'][key] = dict(ifindex=3)
        with patch.object(broker, 'kernel_links', return_value=[dict(ifname='vlan10', ifindex=4)]):
            with self.assertRaises(policy.Rejected):
                instance.device('vlan10')
        instance.state['intent'] = {'kind': 'network'}
        with patch.object(broker, 'process') as execute:
            with self.assertRaises(policy.Rejected):
                instance.network({'argv': ['link', 'set', 'dev', 'eth1', 'up']})
            execute.assert_not_called()

    def test_reboot_does_not_re_adopt_os_resources(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'state.json'
        path.touch()
        prior = dict(version=1, boot_id='prior-boot', intent=None, owned={
            'address': dict(kind='network'),
            'runtime_firewall': dict(kind='firewall', operation=dict(argv=[])),
            'persistent_firewall': dict(kind='firewall', operation=dict(argv=['--permanent']))})
        with patch.object(broker, 'load', return_value=prior), patch.object(broker, 'save'):
            instance = broker.Broker(dict(version=1, uid=1001, gid=1001,
                                          traffic_interfaces=['eth1'], management_interfaces=[]), path)
        self.assertEqual(set(instance.state['owned']), {'persistent_firewall'})
        self.assertEqual(instance.state['nm_checkpoints'], {})

    def test_console_reconciliation_preserves_uncertain_resource_and_other_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            operation = policy.network(['address', 'add', '192.0.2.70/24', 'dev', 'eth1'])
            key = json.dumps(operation['identity'])
            state = dict(version=1, owned={key: dict(kind='network'), 'other': dict(kind='network')},
                         intent=dict(kind='network', operation=operation))
            with patch.object(broker, 'STATE', Path(directory) / 'ownership.json'), \
                 patch.object(broker.os, 'geteuid', return_value=0), \
                 patch.object(broker, 'private'), patch.object(broker, 'load', return_value=state), \
                 patch.object(broker, 'save') as persisted, patch.object(broker, 'process') as execute:
                broker.reconcile_forget_intent()
                execute.assert_not_called()
                persisted.assert_called_once()
            self.assertIsNone(state['intent'])
            self.assertEqual(set(state['owned']), {'other'})


class Announcements(unittest.TestCase):
    def test_activation_callbacks_do_not_wait_for_pcs_provisioning(self):
        class PcsLock:
            def __enter__(self):
                raise AssertionError('OCF callback deadlocked behind its own pcs caller')

            def __exit__(self, *args):
                pass

        helper = broker.ha_module.HA(None, policy, None, None, None, broker.success)
        helper.lock = PcsLock()
        helper.announce = lambda data: {'changed': True}
        self.assertTrue(helper.dispatch(dict(operation='announce', data={}), (1, 1001, 1001))['changed'])

    def test_fixed_arp_and_ipv6_na_frames(self):
        mac = bytes([2, 0, 0, 0, 0, 1])
        arp = broker.ha_module.announcement(mac, ipaddress.ip_address('192.0.2.70'))
        self.assertEqual(len(arp), 42)
        self.assertEqual(arp[:6], b'\xff' * 6)
        self.assertEqual(arp[28:32], bytes([192, 0, 2, 70]))
        self.assertEqual(arp[38:42], arp[28:32])
        address = ipaddress.ip_address('2001:db8::70')
        na = broker.ha_module.announcement(mac, address)
        self.assertEqual(len(na), 86)
        self.assertEqual(na[21], 255)
        self.assertEqual(na[54:56], b'\x88\0')
        self.assertEqual(na[58], 0x20)
        self.assertEqual(na[62:78], address.packed)
        self.assertEqual(broker.ha_module.checksum(na[22:54] + struct.pack('!I', 32)
                                                 + b'\0\0\0\x3a' + na[54:]), 0)

    def test_no_raw_socket_without_authority_and_owned_assigned_address(self):
        instance = SimpleNamespace(lock=threading.Lock(), state={'owned': {}},
                                   mutable=lambda: None,
                                   device=lambda _: {'address': '02:00:00:00:00:01'},
                                   present=lambda _: True)
        helper = broker.ha_module.HA(instance, policy, None, None, None, broker.success)
        helper.settings = lambda: {'node_id': 'node-a'}
        for authority in [dict(quorate=False, fencing=True, owner='node-a'),
                          dict(quorate=True, fencing=False, owner='node-a'),
                          dict(quorate=True, fencing=True, owner='node-b'),
                          dict(quorate=True, fencing=True, owner='node-a')]:
            helper.process = lambda *args: dict(code=0, stdout=json.dumps(authority))
            with patch.object(broker.ha_module.socket, 'socket') as raw:
                with self.assertRaises(policy.Rejected):
                    helper.announce(dict(device='eth1', address='192.0.2.70'))
                raw.assert_not_called()
        operation = policy.network(['address', 'add', '192.0.2.70/24', 'dev', 'eth1'])
        instance.state['owned']['address'] = dict(kind='network', operation=operation)
        instance.present = lambda _: False
        with patch.object(broker.ha_module.socket, 'socket') as raw:
            with self.assertRaises(policy.Rejected):
                helper.announce(dict(device='eth1', address='192.0.2.70'))
            raw.assert_not_called()
        instance.present = lambda _: True
        with patch.object(broker.ha_module.socket, 'socket') as raw:
            raw.return_value.__enter__.return_value.sendto.return_value = 42
            self.assertTrue(helper.announce(dict(device='eth1', address='192.0.2.70'))['changed'])
            self.assertEqual(raw.call_args.args[2], 0)
            self.assertEqual(raw.return_value.__enter__.return_value.sendto.call_count, 3)


class Transport(unittest.TestCase):
    def frame(self, connection):
        size = struct.unpack('!I', broker.receive(connection, 4))[0]
        return json.loads(broker.receive(connection, size))

    def exchange(self, change=lambda v: None):
        class Fake:
            configuration = {'uid': os.geteuid()}
            calls = []

            def dispatch(self, action, parameters, peer):
                self.calls.append(action)
                return {'code': 0}
        fake = Fake()
        left, right = socket.socketpair()
        left.settimeout(2)
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        thread = threading.Thread(target=broker.client, args=(right, fake, slots))
        thread.start()
        try:
            hello = self.frame(left)
            request = dict(version=1, nonce=hello['nonce'], action='test', parameters={})
            change(request)
            data = json.dumps(request).encode()
            left.sendall(struct.pack('!I', len(data)) + data)
            response = self.frame(left)
        finally:
            left.close()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        return response, fake.calls

    def test_nonce_framing_and_unknown_fields(self):
        result, calls = self.exchange()
        self.assertTrue(result['ok'])
        self.assertEqual(calls, ['test'])
        for change in [lambda r: r.update(nonce='0' * 64), lambda r: r.update(version=True),
                       lambda r: r.update(command='/bin/sh')]:
            result, calls = self.exchange(change)
            self.assertFalse(result['ok'])
            self.assertEqual(calls, [])

    def test_previous_connection_request_cannot_be_replayed(self):
        previous = []
        result, _ = self.exchange(lambda request: previous.append(request['nonce']))
        self.assertTrue(result['ok'])
        result, calls = self.exchange(lambda request: request.update(nonce=previous[0]))
        self.assertFalse(result['ok'])
        self.assertEqual(calls, [])

    def test_slow_partial_frame_has_an_absolute_deadline(self):
        left, right = socket.socketpair()
        try:
            left.sendall(b'x')
            with patch.object(broker.time, 'monotonic', side_effect=[0, 0, 6]):
                with self.assertRaises(policy.Rejected):
                    broker.receive(right, 4)
        finally:
            left.close()
            right.close()

    @unittest.skipIf(os.geteuid() == 0, 'Root is an authorized console peer')
    def test_kernel_peer_uid_rejected_before_dispatch(self):
        fake = SimpleNamespace(configuration={'uid': os.geteuid() + 1})
        left, right = socket.socketpair()
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        thread = threading.Thread(target=broker.client, args=(right, fake, slots))
        thread.start()
        try:
            self.assertFalse(self.frame(left)['ok'])
        finally:
            left.close()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(slots.acquire(blocking=False))

    def test_received_descriptors_are_closed_even_when_control_is_truncated(self):
        for count in [1, 32]:
            with self.subTest(count=count):
                left, right = socket.socketpair()
                descriptor = os.open('/dev/null', os.O_RDONLY)
                try:
                    before = len(list(Path('/proc/self/fd').iterdir()))
                    left.sendmsg([b'1234'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                             array.array('i', [descriptor] * count))])
                    with self.assertRaises(policy.Rejected):
                        broker.receive(right, 4)
                    self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)
                finally:
                    os.close(descriptor)
                    left.close()
                    right.close()


if __name__ == '__main__':
    unittest.main()
