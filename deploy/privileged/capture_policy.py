"""Closed capture selectors and fail-closed Ethernet/IP header extraction.

This module opens no sockets and writes no files. Captured transport payload and
options are never returned; unsupported encapsulations and fragments are dropped.
"""
from dataclasses import dataclass
import ipaddress
import re
import struct


DEFAULT_PROTECTED_PORTS = frozenset({22, 2223, 2224, 3121, 5404, 5405, 18090, 21064})
MAX_FRAME = 65599


def require(condition):
    if not condition:
        raise ValueError('Capture request is outside the diagnostic policy')


@dataclass(frozen=True)
class Request:
    interface: str
    host: str
    port: int
    protocol: str
    duration_seconds: int
    max_bytes: int


def validate(value, interfaces, management_networks, protected_ports=DEFAULT_PROTECTED_PORTS):
    """The caller supplies independently trusted interface/exclusion inventory."""
    require(type(value) is dict and set(value) == {
        'interface', 'host', 'port', 'protocol', 'duration_seconds', 'max_bytes'})
    interface = value['interface']
    require(type(interface) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', interface)
            and interface in interfaces and interface != 'lo')
    require(type(value['host']) is str and len(value['host']) <= 45 and '%' not in value['host'])
    host = ipaddress.ip_address(value['host'])
    require(not (host.is_unspecified or host.is_loopback or host.is_multicast
                 or host.is_link_local or host.is_reserved)
            and getattr(host, 'ipv4_mapped', None) is None)
    require(not any(host in network for network in management_networks))
    port = value['port']
    require(type(port) is int and 1 <= port <= 65535 and port not in protected_ports)
    require(type(value['protocol']) is str and value['protocol'] in {'tcp', 'udp'})
    seconds, maximum = value['duration_seconds'], value['max_bytes']
    require(type(seconds) is int and 1 <= seconds <= 60)
    require(type(maximum) is int and 4096 <= maximum <= 16 * 1024 * 1024)
    return Request(interface, str(host), port, value['protocol'], seconds, maximum)


def headers(frame, request, management_networks, protected_ports=DEFAULT_PROTECTED_PORTS):
    """Return a PCAP-ready prefix containing base headers only, or no record.

    Original length remains the wire length in the PCAP record. Truncation is
    deliberate: TCP options and transport payload are excluded from stored bytes.
    IPv4 options, IPv6 extensions, fragments and unsupported protocols are dropped.
    """
    if type(frame) is not bytes or not 14 <= len(frame) <= MAX_FRAME:
        return None
    ethertype = int.from_bytes(frame[12:14], 'big')
    offset = 14
    for _ in range(2):
        if ethertype not in {0x8100, 0x88a8}:
            break
        if len(frame) < offset + 4:
            return None
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], 'big')
        offset += 4
    if ethertype == 0x0800:
        if len(frame) < offset + 20 or frame[offset] != 0x45:
            return None
        total = int.from_bytes(frame[offset + 2:offset + 4], 'big')
        fragment = int.from_bytes(frame[offset + 6:offset + 8], 'big')
        if fragment & 0xbfff or total < 20 or offset + total > len(frame):
            return None
        protocol = frame[offset + 9]
        source = ipaddress.ip_address(frame[offset + 12:offset + 16])
        destination = ipaddress.ip_address(frame[offset + 16:offset + 20])
        transport, end = offset + 20, offset + total
    elif ethertype == 0x86dd:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            return None
        length = int.from_bytes(frame[offset + 4:offset + 6], 'big')
        if length == 0 or offset + 40 + length > len(frame):
            return None
        protocol = frame[offset + 6]
        source = ipaddress.ip_address(frame[offset + 8:offset + 24])
        destination = ipaddress.ip_address(frame[offset + 24:offset + 40])
        transport, end = offset + 40, offset + 40 + length
    else:
        return None
    if any(source in network or destination in network for network in management_networks):
        return None
    if protocol == 6 and request.protocol == 'tcp':
        if transport + 20 > end:
            return None
        length = (frame[transport + 12] >> 4) * 4
        if length < 20 or transport + length > end:
            return None
        keep = 20
    elif protocol == 17 and request.protocol == 'udp':
        if transport + 8 > end:
            return None
        length = int.from_bytes(frame[transport + 4:transport + 6], 'big')
        if length < 8 or transport + length > end:
            return None
        keep = 8
    else:
        return None
    source_port, destination_port = struct.unpack_from('!HH', frame, transport)
    if source_port in protected_ports or destination_port in protected_ports:
        return None
    if not ((str(source) == request.host and source_port == request.port)
            or (str(destination) == request.host and destination_port == request.port)):
        return None
    return frame[:transport + keep]
