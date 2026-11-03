"""NetworkManager delegation, restricted to appliance Ethernet profiles/checkpoints."""
import json
import time


class NetworkManager:
    def __init__(self, broker, policy, process, success):
        self.broker, self.policy, self.process, self.success = broker, policy, process, success
        self.broker.state.setdefault('nm_checkpoints', {})

    def permitted(self, name):
        self.policy.require(name in self.broker.configuration['traffic_interfaces'] +
                            self.broker.configuration['management_interfaces'],
                            'Ethernet adapter is not console-approved')
        return name

    def run_nm(self, arguments):
        return self.process('/usr/bin/nmcli', ['--wait', '15', '--escape', 'no', *arguments], timeout=25)

    def profile(self, identifier):
        self.policy.uuid(identifier)
        text = self.success(self.run_nm(['-g', 'connection.interface-name,connection.type,connection.controller',
                                        'connection', 'show', 'uuid', identifier]))['stdout'].rstrip('\n')
        rows = text.split('\n')
        self.policy.require(len(rows) == 3 and rows[1] == '802-3-ethernet' and rows[2] in {'', '--'},
                            'Only independent Ethernet profiles are delegated')
        name = rows[0]
        if name in {'', '--'}:
            active = []
            for candidate in self.broker.configuration['traffic_interfaces'] + self.broker.configuration['management_interfaces']:
                result = self.run_nm(['-g', 'GENERAL.CON-UUID', 'device', 'show', candidate])
                if result['code'] == 0 and result['stdout'].strip() == identifier:
                    active.append(candidate)
            self.policy.require(len(active) == 1, 'Unbound profile must be uniquely active on an approved adapter')
            name = active[0]
        return self.permitted(name)

    def prune(self):
        if not self.broker.state['nm_checkpoints']:
            return
        result = self.success(self.process('/usr/bin/busctl',
            ['--system', '--timeout=3s', '--json=short', 'get-property', self.policy.NM,
             self.policy.NM_PATH, self.policy.NM, 'Checkpoints']))
        active = json.loads(result['stdout'])['data']
        self.policy.require(type(active) is list and len(active) <= 128)
        retained = {key: value for key, value in self.broker.state['nm_checkpoints'].items() if key in active}
        if retained != self.broker.state['nm_checkpoints']:
            self.broker.state['nm_checkpoints'] = retained
            self.broker.checkpoint()

    def conflict(self, name):
        self.prune()
        self.policy.require(not any(item['interface'] == name
                                   for item in self.broker.state['nm_checkpoints'].values()),
                            'Complete or wait for interface checkpoint rollback before network changes')

    def checkpoint(self, name, peer):
        entries = [value for value in self.broker.state['nm_checkpoints'].values()
                   if value['interface'] == name and tuple(value['peer']) == peer
                   and value['deadline'] > time.time() and not value.get('rolled_back')]
        self.policy.require(len(entries) == 1, 'Interface change requires this peer\'s live checkpoint')
        return entries[0]

    def no_untagged_addresses(self, name, disconnect=False, properties=None):
        for entry in self.broker.state['owned'].values():
            if entry.get('kind') != 'network':
                continue
            operation = entry['operation']
            if operation['identity'][0] == 'address' and operation['identity'][1] == name:
                raise self.policy.Rejected('Remove managed untagged addresses before editing this OS profile')
            if operation['identity'][0] == 'vlan' and operation['argv'][3] == name:
                self.policy.require(not disconnect, 'Remove managed VLANs before disabling their parent')
                if properties is not None and '802-3-ethernet.mtu' in properties:
                    self.policy.require(int(properties['802-3-ethernet.mtu']) >= 1500,
                                        'A managed VLAN parent requires MTU 1500 or greater')

    def cli(self, arguments, peer):
        request = self.policy.nmcli(arguments)
        with self.broker.lock:
            self.broker.mutable()
            self.prune()
            name = self.profile(request['uuid']) if 'uuid' in request else request.get('interface')
            if name is not None:
                self.permitted(name)
                self.policy.require(request.get('interface', name) == name, 'Profile belongs to another interface')
            if request['kind'] != 'read':
                self.checkpoint(name, peer)
                if request['kind'] != 'confirm':
                    self.no_untagged_addresses(name, request['kind'] == 'disconnect', request.get('properties'))
                properties = request.get('properties', {})
                self.policy.require(properties.get('connection.interface-name', name) == name,
                                    'Cannot move profiles between interfaces')
            result = self.process('/usr/bin/nmcli', arguments, timeout=25)
            result['changed'] = result['code'] == 0 and request['kind'] != 'read'
            return result

    def bus(self, arguments, peer):
        request = self.policy.busctl(arguments)
        with self.broker.lock:
            self.broker.mutable()
            self.prune()
            kind = request['kind']
            if kind == 'read_device':
                self.permitted(request['interface'])
            elif kind == 'create':
                result = self.success(self.process('/usr/bin/busctl',
                    ['--system', '--timeout=3s', '--json=short', 'get-property', self.policy.NM,
                     request['device'], self.policy.NM + '.Device', 'Interface']))
                name = json.loads(result['stdout'])['data'][0]
                self.permitted(name)
                self.policy.require(not any(v['interface'] == name for v in self.broker.state['nm_checkpoints'].values()),
                                    'A broker checkpoint already covers this adapter')
            elif kind in {'destroy', 'rollback'}:
                record = self.broker.state['nm_checkpoints'].get(request['checkpoint'])
                self.policy.require(record is not None and tuple(record['peer']) == peer,
                                    'Cannot modify another peer\'s checkpoint')
                if kind == 'destroy':
                    self.policy.require(record['deadline'] > time.time() and not record.get('rolled_back'),
                                        'Cannot confirm an expired or rolled-back trial')
            result = self.process('/usr/bin/busctl', arguments)
            if result['code'] != 0:
                return result
            if kind == 'read_checkpoints':
                active = json.loads(result['stdout'])['data']
                # Kernel/NM state is authoritative after independent timer rollback.
                self.broker.state['nm_checkpoints'] = {
                    key: value for key, value in self.broker.state['nm_checkpoints'].items() if key in active}
                self.broker.checkpoint()
            elif kind == 'create':
                identifier = json.loads(result['stdout'])['data'][0]
                self.policy.busctl(['--system', '--timeout=3s', '--json=short', 'call', self.policy.NM,
                                   self.policy.NM_PATH, self.policy.NM, 'CheckpointDestroy', 'o', identifier])
                self.broker.state['nm_checkpoints'][identifier] = {
                    'interface': name, 'peer': list(peer), 'deadline': time.time() + 90}
                self.broker.checkpoint()
            elif kind == 'destroy':
                del self.broker.state['nm_checkpoints'][request['checkpoint']]
                self.broker.checkpoint()
            elif kind == 'rollback':
                outcomes = json.loads(result['stdout'])['data'][0]
                if outcomes and all(value == 0 for value in outcomes.values()):
                    self.broker.state['nm_checkpoints'][request['checkpoint']]['rolled_back'] = True
                    self.broker.checkpoint()
                    # Destroy only this completed rollback's checkpoint, never the global empty path.
                    final = self.process('/usr/bin/busctl',
                        ['--system', '--timeout=3s', '--json=short', 'call', self.policy.NM,
                         self.policy.NM_PATH, self.policy.NM, 'CheckpointDestroy', 'o', request['checkpoint']])
                    if final['code'] == 0:
                        del self.broker.state['nm_checkpoints'][request['checkpoint']]
                        self.broker.checkpoint()
            result['changed'] = result['code'] == 0 and kind not in {'read_checkpoints', 'read_device'}
            return result

    def dispatch(self, parameters, peer):
        self.policy.fields(parameters, {'tool', 'argv'})
        if parameters['tool'] == 'nmcli':
            return self.cli(parameters['argv'], peer)
        if parameters['tool'] == 'busctl':
            return self.bus(parameters['argv'], peer)
        if parameters['tool'] == 'ip_link':
            a = self.policy.argv(parameters['argv'])
            self.policy.require(len(a) == 5 and a[:3] == ['link', 'set', 'dev'] and a[4] == 'down')
            with self.broker.lock:
                self.broker.mutable()
                self.prune()
                name = self.permitted(self.policy.interface(a[3]))
                self.checkpoint(name, peer)
                self.no_untagged_addresses(name, disconnect=True)
                return self.process('/usr/sbin/ip', a)
        raise self.policy.Rejected('Unknown NetworkManager operation')
