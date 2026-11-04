"""Closed command grammars for the installed privileged broker. No shell syntax."""
import ipaddress
import re


class Rejected(ValueError):
    pass


def require(value, message='Privileged request rejected'):
    if not value:
        raise Rejected(message)


def fields(value, required, optional=()):
    require(type(value) is dict and set(required) <= value.keys() <= set(required) | set(optional))


def interface(value):
    require(type(value) is str and bool(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', value)))
    require(value not in {'.', '..', 'lo'})
    return value


def number(value, lower, upper):
    require(type(value) is str and bool(re.fullmatch(r'0|[1-9][0-9]*', value)))
    require(lower <= int(value) <= upper)
    return value


def address(value, family=None, prefix=False, network=False):
    require(type(value) is str and len(value) <= 64 and '%' not in value)
    try:
        parsed = ipaddress.ip_interface(value) if prefix else ipaddress.ip_address(value)
        ip = parsed.ip if prefix else parsed
        require(str(parsed) == value)
        require(family is None or ip.version == family)
        require(not ip.is_multicast and not ip.is_unspecified)
        if network:
            require(str(ipaddress.ip_network(value, strict=True)) == value)
    except ValueError as error:
        raise Rejected('Noncanonical IP address or prefix') from error
    return value


def destination(value, family):
    if value == 'default':
        return value
    # Network destinations can legitimately be 0.0.0.0/0 or ::/0.
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise Rejected('Noncanonical route destination') from error
    require(parsed.version == family and str(parsed) == value)
    require(not parsed.is_multicast)
    return value


def argv(value):
    require(type(value) is list and 1 <= len(value) <= 64)
    require(all(type(v) is str and len(v) <= 2048 and not any(ord(c) < 32 or ord(c) == 127 for c in v)
                for v in value))
    return value


def network(value):
    """Return validated semantics; the executor never receives a program/path."""
    a = argv(value)
    devices, operation, identity, source = [], None, None, None
    match a:
        case ['address', ('add' | 'del') as op, cidr, 'dev', dev]:
            address(cidr, prefix=True)
            require(not ipaddress.ip_interface(cidr).ip.is_loopback)
            devices = [interface(dev)]
            operation, identity = op, ('address', dev, cidr)
        case ['link', 'add', 'link', parent, 'name', name, 'type', 'vlan', 'id', tag]:
            interface(parent); interface(name); number(tag, 1, 4094)
            require(parent != name)
            devices = [parent]
            operation, identity = 'add', ('vlan', name)
        case ['link', 'del', 'dev', dev]:
            interface(dev)
            devices = [dev]
            operation, identity = 'del', ('vlan', dev)
        case ['link', 'set', 'dev', dev, 'up']:
            devices = [interface(dev)]
            operation, identity = 'up', ('link', dev)
        case [('-4' | '-6') as family, 'rule', ('add' | 'del') as op,
              'from', cidr, 'lookup', table, 'priority', '18600', 'protocol', '186']:
            version = 4 if family == '-4' else 6
            address(cidr, version, prefix=True)
            require(ipaddress.ip_interface(cidr).network.prefixlen == (32 if version == 4 else 128))
            number(table, 1_000_000, 17_777_215)
            operation, identity, source = op, ('rule', family, cidr, table), cidr
        case [('-4' | '-6') as family, 'route', ('add' | 'del') as op, *parts]:
            version = 4 if family == '-4' else 6
            match parts:
                case [dest, 'via', gateway, 'dev', dev, 'metric', metric, 'proto', '186', *tail]:
                    destination(dest, version); address(gateway, version); interface(dev)
                    number(metric, 0, 4_294_967_295)
                    require(not tail or len(tail) == 3 and tail[0] == 'table' and tail[2] == 'onlink')
                    if tail:
                        number(tail[1], 1_000_000, 17_777_215)
                    devices = [dev]
                case ['table', table, dest, 'dev', dev, 'scope', 'link', 'proto', '186']:
                    number(table, 1_000_000, 17_777_215); destination(dest, version)
                    devices = [interface(dev)]
                case ['table', table, 'default', 'via', gateway, 'dev', dev,
                      'onlink', 'metric', '0', 'proto', '186']:
                    number(table, 1_000_000, 17_777_215); address(gateway, version)
                    devices = [interface(dev)]
                case ['table', table, 'unreachable', 'default', 'metric', '4294967295', 'proto', '186']:
                    number(table, 1_000_000, 17_777_215)
                case _:
                    raise Rejected('Unsupported managed route')
            canonical = list(a)
            canonical[2] = 'add'
            operation, identity = op, ('route', *canonical)
        case _:
            raise Rejected('Unsupported managed network operation')
    addition = list(a)
    if a[0] == 'address':
        addition[1] = 'add'
    elif a[0] in {'-4', '-6'}:
        addition[2] = 'add'
    return dict(argv=list(a), operation=operation, identity=list(identity),
                devices=devices, addition=addition, source=source)


RICH = re.compile(r'rule family="(ipv4|ipv6)" priority="18600" destination address="([^" ]+)" '
                  r'port port="([0-9]+)" protocol="(tcp|udp)" accept')


def firewall(value):
    a = argv(value)
    if a == ['--get-default-zone']:
        return dict(argv=a, operation='query')
    if len(a) == 1 and a[0].startswith('--get-zone-of-interface='):
        interface(a[0].split('=', 1)[1])
        return dict(argv=a, operation='query')
    require(len(a) in {2, 3} and a[0].startswith('--zone='))
    zone = a[0].split('=', 1)[1]
    require(bool(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}', zone)))
    permanent = len(a) == 3
    require(not permanent or a[1] == '--permanent')
    match_rule = re.fullmatch(r'--(add|remove|query)-rich-rule=(.*)', a[-1])
    require(match_rule is not None)
    op, text = match_rule.groups()
    match = RICH.fullmatch(text)
    require(match is not None)
    family, ip, port, protocol = match.groups()
    address(ip, 4 if family == 'ipv4' else 6)
    require(not ipaddress.ip_address(ip).is_loopback)
    number(port, 1, 65535)
    return dict(argv=a, operation=op, ip=ip, port=int(port), protocol=protocol,
                identity=['firewall', zone, permanent, text], permanent=permanent)


def ping(value):
    fields(value, {'target', 'timeout_ms'}, {'source', 'device'})
    target = address(value['target'])
    require(type(value['timeout_ms']) is int and 1 <= value['timeout_ms'] <= 60_000)
    a = ['-n', '-c', '1', '-W', f"{value['timeout_ms'] / 1000:.3f}",
         '-4' if ipaddress.ip_address(target).version == 4 else '-6']
    if value.get('device') is not None:
        a += ['-I', interface(value['device'])]
    if value.get('source') is not None:
        a += ['-I', address(value['source'], ipaddress.ip_address(target).version)]
    return a + [target]

NM = 'org.freedesktop.NetworkManager'
NM_PATH = '/org/freedesktop/NetworkManager'
PROFILE_FIELDS = ('connection.type,connection.controller,connection.autoconnect,802-3-ethernet.mtu,'
                  'ipv4.route-metric,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.never-default,'
                  'ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.dns,ipv6.never-default')


def uuid(value):
    require(type(value) is str and bool(re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value)))
    return value


def nm_properties(parts):
    require(len(parts) % 2 == 0 and 0 < len(parts) <= 34)
    properties = dict(zip(parts[::2], parts[1::2]))
    require(len(properties) * 2 == len(parts), 'Duplicate NetworkManager property')
    if set(properties) == {'connection.autoconnect'}:
        require(properties['connection.autoconnect'] in {'yes', 'no'})
        return properties
    expected = {'connection.interface-name', 'connection.autoconnect', '802-3-ethernet.mtu'}
    expected |= {family + '.' + key for family in ['ipv4', 'ipv6'] for key in
                 ['method', 'addresses', 'gateway', 'dns', 'never-default', 'ignore-auto-dns', 'route-metric']}
    require(set(properties) == expected, 'Unsupported NetworkManager property')
    interface(properties['connection.interface-name'])
    require(properties['connection.autoconnect'] in {'yes', 'no'})
    number(properties['802-3-ethernet.mtu'], 1280, 9216)
    for name, version in [('ipv4', 4), ('ipv6', 6)]:
        method = properties[name + '.method']
        require(method in {'disabled', 'manual', 'auto'})
        addresses = properties[name + '.addresses'].split(',') if properties[name + '.addresses'] else []
        require(len(addresses) <= 16 and (method == 'manual') == bool(addresses))
        for item in addresses:
            address(item, version, prefix=True)
            require(not ipaddress.ip_interface(item).ip.is_loopback)
        dns = properties[name + '.dns'].split(',') if properties[name + '.dns'] else []
        require(len(dns) <= 8)
        for item in dns + ([properties[name + '.gateway']] if properties[name + '.gateway'] else []):
            address(item, version)
            require(not ipaddress.ip_address(item).is_loopback)
        for key in ['never-default', 'ignore-auto-dns']:
            require(properties[name + '.' + key] in {'yes', 'no'})
        number(properties[name + '.route-metric'], 1, 65535)
    return properties


def nmcli(value):
    a = argv(value)
    if a[:4] == ['--wait', '15', '--escape', 'no']:
        a = a[4:]
    elif a[:2] == ['--wait', '15']:
        a = a[2:]
    else:
        raise Rejected('Fixed NetworkManager command prefix required')
    match a:
        case ['-g', ('GENERAL.TYPE,GENERAL.CON-UUID' | 'GENERAL.CON-UUID'), 'device', 'show', name]:
            return dict(kind='read', interface=interface(name))
        case ['-g', 'UUID', 'connection', 'show']:
            return dict(kind='read')
        case ['-g', fields, 'connection', 'show', 'uuid', identifier]:
            require(fields in {'connection.interface-name', PROFILE_FIELDS})
            return dict(kind='read', uuid=uuid(identifier))
        case ['connection', 'modify', '--temporary', 'uuid', identifier, *parts]:
            return dict(kind='modify', uuid=uuid(identifier), temporary=True, properties=nm_properties(parts))
        case ['connection', 'modify', 'uuid', identifier, 'connection.autoconnect', value]:
            require(value in {'yes', 'no'})
            return dict(kind='confirm', uuid=uuid(identifier))
        case ['connection', 'add', 'save', 'no', 'type', 'ethernet', 'ifname', name, 'con-name', label, *parts]:
            interface(name)
            require(label == 'RiverLB ' + name)
            properties = nm_properties(parts)
            require(properties.get('connection.interface-name') == name)
            return dict(kind='add', interface=name, properties=properties)
        case ['connection', 'up', 'uuid', identifier, 'ifname', name]:
            return dict(kind='up', uuid=uuid(identifier), interface=interface(name))
        case ['device', 'disconnect', name]:
            return dict(kind='disconnect', interface=interface(name))
        case _:
            raise Rejected('Unsupported NetworkManager command')


def busctl(value):
    a = argv(value)
    prefix = ['--system', '--timeout=3s', '--json=short']
    require(a[:3] == prefix)
    if a[3:] == ['get-property', NM, NM_PATH, NM, 'Checkpoints']:
        return dict(kind='read_checkpoints')
    require(a[3:7] == ['call', NM, NM_PATH, NM])
    match a[7:]:
        case ['GetDeviceByIpIface', 's', name]:
            return dict(kind='read_device', interface=interface(name))
        case ['CheckpointCreate', 'aouu', '1', device, '90', '2']:
            require(bool(re.fullmatch(r'/org/freedesktop/NetworkManager/Devices/[0-9]+', device)))
            return dict(kind='create', device=device)
        case [('CheckpointDestroy' | 'CheckpointRollback') as method, 'o', checkpoint]:
            require(bool(re.fullmatch(r'/org/freedesktop/NetworkManager/Checkpoint/[0-9]+', checkpoint)))
            return dict(kind='destroy' if method == 'CheckpointDestroy' else 'rollback', checkpoint=checkpoint)
        case _:
            raise Rejected('Unsupported NetworkManager bus operation')
