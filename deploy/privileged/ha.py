"""Fixed HA operations; private identities never enter the unprivileged daemon."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import socket
import struct
import threading
import time

ROOT = Path('/etc/riverlb-privileged')
RUN = Path('/run/riverlb-ha-deploy')
SETTINGS = ROOT / 'ha.json'
GROUP = ROOT / 'ha.group.json'
OUTGOING = Path('/var/lib/riverlb/ha-outgoing.json')
MAX_SYNC = 32 * 1024 * 1024


def checksum(data):
    data += b'\0' if len(data) % 2 else b''
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def announcement(mac, address):
    """Construct only gratuitous ARP or unsolicited, non-router IPv6 NA."""
    if address.version == 4:
        return (b'\xff' * 6 + mac + b'\x08\x06' + b'\0\x01\x08\0\x06\x04\0\x01'
                + mac + address.packed + b'\0' * 6 + address.packed)
    destination = ipaddress.ip_address('ff02::1').packed
    message = b'\x88\0\0\0\x20\0\0\0' + address.packed + b'\x02\x01' + mac
    pseudo = address.packed + destination + struct.pack('!I', len(message)) + b'\0\0\0\x3a'
    message = message[:2] + struct.pack('!H', checksum(pseudo + message)) + message[4:]
    return (b'\x33\x33\0\0\0\x01' + mac + b'\x86\xdd'
            + b'\x60\0\0\0\0\x20\x3a\xff' + address.packed + destination + message)


class HA:
    def __init__(self, broker, policy, load, save, process, success):
        self.broker, self.policy = broker, policy
        self.load, self.save, self.process, self.success = load, save, process, success
        self.lock = threading.Lock()
        self.sync_lock = threading.Lock()

    def identifier(self, value):
        self.policy.require(type(value) is str and bool(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', value)))
        return value

    def validate_group(self, value):
        self.policy.fields(value, {'cluster_id', 'node_id', 'peer_id', 'local_address', 'peer_address',
                                   'automatic_sync', 'floating_self_ips', 'fencing_resources'})
        for key in ['cluster_id', 'node_id', 'peer_id']:
            self.identifier(value[key])
        self.policy.require(value['node_id'] != value['peer_id'] and type(value['automatic_sync']) is bool)
        for key in ['local_address', 'peer_address']:
            self.policy.address(value[key])
            self.policy.require(not ipaddress.ip_address(value[key]).is_loopback)
        self.policy.require(value['local_address'] != value['peer_address'])
        for key in ['floating_self_ips', 'fencing_resources']:
            self.policy.require(type(value[key]) is list and len(value[key]) <= 256
                                and len(set(value[key])) == len(value[key]))
            for name in value[key]:
                self.identifier(name)
        return value

    def group(self):
        return self.validate_group(self.load(GROUP, limit=65536))

    def settings(self):
        if not SETTINGS.exists():
            return None
        value = self.load(SETTINGS, limit=65536)
        self.policy.fields(value, {'automatic_sync', 'cluster_id', 'node_id', 'peer_id', 'socket', 'state_file',
                                   'authority', 'floating_self_ips', 'ssh_target', 'ssh_port', 'ssh_program',
                                   'ssh_identity', 'ssh_known_hosts', 'peer_socket', 'peer_binary',
                                   'sync_interval_secs', 'max_sync_age_secs'})
        for key in ['cluster_id', 'node_id', 'peer_id']:
            self.identifier(value[key])
        self.policy.require(type(value['automatic_sync']) is bool and value['node_id'] != value['peer_id'])
        fixed = {'socket': '/run/riverlb/ha.sock', 'state_file': '/var/lib/riverlb/ha-state.json',
                 'authority': '/usr/libexec/riverlb/riverlb-authority', 'ssh_program': '/usr/bin/ssh',
                 'ssh_identity': str(ROOT / 'ha-sync-ed25519'), 'ssh_known_hosts': str(ROOT / 'ha-known-hosts'),
                 'peer_socket': '/run/riverlb/ha.sock', 'peer_binary': '/usr/bin/riverlb'}
        self.policy.require(all(value[key] == expected for key, expected in fixed.items()),
                            'Installed HA uses only fixed authority, credential and executable paths')
        self.policy.require(type(value['ssh_target']) is str and value['ssh_target'].startswith('root@'))
        self.policy.address(value['ssh_target'][5:])
        self.policy.require(type(value['ssh_port']) is int and 1 <= value['ssh_port'] <= 65535)
        self.policy.require(type(value['sync_interval_secs']) is int and 1 <= value['sync_interval_secs'] <= 60)
        self.policy.require(type(value['max_sync_age_secs']) is int
                            and value['sync_interval_secs'] * 3 <= value['max_sync_age_secs'] <= 3600)
        self.policy.require(type(value['floating_self_ips']) is list and len(value['floating_self_ips']) <= 256)
        for name in value['floating_self_ips']:
            self.identifier(name)
        return value

    def save_group(self, group):
        self.validate_group(group)
        value = self.settings() or dict(
            socket='/run/riverlb/ha.sock', state_file='/var/lib/riverlb/ha-state.json',
            authority='/usr/libexec/riverlb/riverlb-authority', ssh_program='/usr/bin/ssh', ssh_port=2223,
            ssh_identity=str(ROOT / 'ha-sync-ed25519'), ssh_known_hosts=str(ROOT / 'ha-known-hosts'),
            peer_socket='/run/riverlb/ha.sock', peer_binary='/usr/bin/riverlb', sync_interval_secs=2,
            max_sync_age_secs=300)
        for key in ['automatic_sync', 'cluster_id', 'node_id', 'peer_id', 'floating_self_ips']:
            value[key] = group[key]
        value['ssh_target'] = 'root@' + group['peer_address']
        self.save(SETTINGS, value)
        self.save(GROUP, group)
        return dict(saved=True, changed=True)

    def status(self):
        busy = self.process('/usr/bin/systemctl', ['show', '--property=ActiveState', '--value',
                                                  'riverlb-ha-deploy.service'])
        active = busy['code'] == 0 and busy['stdout'].strip() in {'active', 'activating', 'deactivating', 'reloading'}
        identity = self.load(ROOT / 'ha-deployment-identity.json', limit=65536) if (ROOT / 'ha-deployment-identity.json').exists() else None
        if identity is not None:
            identity = {key: identity.get(key) for key in ['sync_public_key', 'host_public_key',
                                                         'host_fingerprint', 'fence_agents']}
        result = self.load(RUN / 'result.json', limit=65536) if (RUN / 'result.json').exists() else None
        return dict(installed=Path('/usr/libexec/riverlb/riverlb-ha-deploy').is_file(),
                    busy=active, identity=identity, job=result)

    def submit(self, data):
        allowed = {'action', 'cluster_password', 'peer_sync_key', 'peer_host_key', 'peer_host_fingerprint',
                   'fence_resource', 'fence_agent', 'fence_parameters', 'fence_probe_action', 'fence_target'}
        self.policy.fields(data, allowed)
        self.policy.require(data['action'] in {'prepare', 'trust', 'authenticate', 'start', 'fence', 'fence_probe'})
        self.policy.require(all(type(data[key]) is str for key in allowed - {'fence_parameters'}))
        self.policy.require(type(data['fence_parameters']) is dict and len(data['fence_parameters']) <= 64)
        self.policy.require(len(json.dumps(data).encode()) <= 16000)
        self.settings()
        self.group()
        self.policy.require(not self.status()['busy'], 'An HA deployment job is already running')
        request = RUN / 'request.json'
        if request.exists():
            existing = self.load(request, limit=16384)
            self.policy.require(type(existing.get('created')) is int
                                and time.time() - existing['created'] > 60, 'An HA deployment job is queued')
            request.unlink()
        payload = dict(data, job=str(int.from_bytes(os.urandom(16), 'big')), created=int(time.time()))
        self.save(request, payload)
        started = self.process('/usr/bin/systemctl', ['start', '--no-block', 'riverlb-ha-deploy.service'])
        if started['code'] != 0:
            request.unlink(missing_ok=True)
            raise self.policy.Rejected('Could not start fixed HA deployment service')
        return dict(job=payload['job'], message='HA deployment queued; inspect deployment status', changed=True)

    def sync(self):
        settings = self.settings()
        self.policy.require(settings is not None)
        descriptor = os.open(OUTGOING, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            self.policy.require(stat.S_ISREG(info.st_mode) and info.st_uid == self.broker.configuration['uid']
                                and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_size <= MAX_SYNC)
            data = source.read(MAX_SYNC + 1)
            self.policy.require(len(data) <= MAX_SYNC)
        # Treat these bytes as untrusted data, never as a program or local configuration.
        return self.process('/usr/bin/ssh',
            ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
             '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
             '-o', 'UserKnownHostsFile=' + settings['ssh_known_hosts'], '-i', settings['ssh_identity'],
             '-p', str(settings['ssh_port']), '--', settings['ssh_target'],
             '/usr/bin/riverlb ha --socket /run/riverlb/ha.sock receive'], timeout=65, data=data)

    def announce(self, data):
        self.policy.fields(data, {'device', 'address'})
        device = self.policy.interface(data['device'])
        address = ipaddress.ip_address(self.policy.address(data['address']))
        self.policy.require(not address.is_loopback)
        settings = self.settings()
        self.policy.require(settings is not None)
        authority = json.loads(self.success(self.process('/usr/libexec/riverlb/riverlb-authority', []))['stdout'])
        self.policy.require(authority.get('quorate') is True and authority.get('fencing') is True
                            and authority.get('owner') == settings['node_id'], 'Local node has no HA authority')
        with self.broker.lock:
            self.broker.mutable()
            link = self.broker.device(device)
            owned = [entry['operation'] for entry in self.broker.state['owned'].values()
                     if entry.get('kind') == 'network'
                     and entry.get('operation', {}).get('identity', [])[:2] == ['address', device]
                     and ipaddress.ip_interface(entry['operation']['identity'][2]).ip == address]
            self.policy.require(any(self.broker.present(operation) for operation in owned),
                                'Only helper-owned, assigned addresses may be announced')
            mac_text = link.get('address', '')
            self.policy.require(bool(re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', mac_text)))
            mac = bytes.fromhex(mac_text.replace(':', ''))
            self.policy.require(mac != b'\0' * 6 and not mac[0] & 1)
            packet = announcement(mac, address)
            # Protocol zero receives no packets. Neither socket nor caller-provided
            # frame bytes ever cross the authenticated boundary.
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW | socket.SOCK_CLOEXEC, 0) as sender:
                sender.bind((device, 0))
                for _ in range(3):
                    self.policy.require(sender.sendto(packet, (device, int.from_bytes(packet[12:14], 'big'),
                                                              0, 1, packet[:6])) == len(packet))
        return dict(changed=True)

    def dispatch(self, parameters, peer):
        self.policy.fields(parameters, {'operation', 'data'})
        operation, data = parameters['operation'], parameters['data']
        self.policy.require(type(operation) is str)
        # Read paths never acquire the long-running synchronization/cluster lock.
        if operation in {'settings_read', 'group_read', 'deployment_status'}:
            self.policy.fields(data, set())
            if operation == 'settings_read':
                return self.settings()
            if operation == 'group_read':
                return self.group() if GROUP.exists() else None
            return self.status()
        if operation == 'authority':
            self.policy.fields(data, set())
            self.policy.require(self.settings() is not None)
            return self.process('/usr/libexec/riverlb/riverlb-authority', [])
        # pcs waits for OCF activation, which requests authority/announcements
        # through this broker. Never put those callbacks behind the pcs lock.
        if operation == 'announce':
            return self.announce(data)
        if operation == 'sync':
            self.policy.fields(data, set())
            with self.sync_lock:
                return self.sync()
        with self.lock:
            if operation == 'group_save':
                self.policy.fields(data, {'group'})
                return self.save_group(data['group'])
            if operation == 'group_action':
                self.policy.fields(data, {'action', 'target'})
                self.policy.require(data['action'] in {'setup', 'enable', 'failover', 'clear'})
                group = self.group()
                self.policy.require(data['target'] in {group['node_id'], group['peer_id']})
                payload = json.dumps(dict(action=data['action'], target=data['target'], group=group)).encode()
                return self.process('/usr/libexec/riverlb/riverlb-cluster', [], timeout=130, data=payload)
            if operation == 'deployment_submit':
                return self.submit(data)
        raise self.policy.Rejected('Unsupported HA delegation')
