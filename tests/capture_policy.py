"""Pure synthetic packet privacy/policy checks; no capture sockets or host state."""
import importlib.util
import ipaddress
from pathlib import Path
import random
import struct
import sys
import unittest

spec = importlib.util.spec_from_file_location('riverlb_capture_policy', Path(__file__).resolve().parents[1] / 'deploy/privileged/capture_policy.py')
capture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = capture
spec.loader.exec_module(capture)
NETWORKS = [ipaddress.ip_network('10.88.0.0/24'), ipaddress.ip_network('fd88:1::/64')]
PAYLOAD = b'private-synthetic-credential-payload'
OPTIONS = b'opts'


def request(**changes):
    return dict(interface='ens4', host='10.88.10.100', port=18080, protocol='tcp',
                duration_seconds=15, max_bytes=4*1024*1024, **changes)


def packet(family=4, protocol='tcp', source=None, destination=None,
           source_port=40000, destination_port=18080, options=False, vlans=0):
    source = ipaddress.ip_address(source or ('10.88.10.1' if family == 4 else 'fd88:16::1'))
    destination = ipaddress.ip_address(destination or ('10.88.10.100' if family == 4 else 'fd88:16::100'))
    if protocol == 'tcp':
        transport = bytearray(20)
        struct.pack_into('!HH', transport, 0, source_port, destination_port)
        transport[12] = 0x60 if options else 0x50
        transport = bytes(transport) + (OPTIONS if options else b'') + PAYLOAD
        number = 6
    else:
        transport = struct.pack('!HHHH', source_port, destination_port, 8+len(PAYLOAD), 0) + PAYLOAD
        number = 17
    if family == 4:
        ip = bytearray(20)
        ip[0] = 0x45
        struct.pack_into('!H', ip, 2, 20+len(transport))
        ip[9] = number
        ip[12:16], ip[16:20] = source.packed, destination.packed
        ethertype = 0x0800
    else:
        ip = bytearray(40)
        ip[0] = 0x60
        struct.pack_into('!H', ip, 4, len(transport))
        ip[6] = number
        ip[8:24], ip[24:40] = source.packed, destination.packed
        ethertype = 0x86dd
    ethernet = b'\x02'*12 + struct.pack('!H', 0x8100 if vlans else ethertype)
    for i in range(vlans):
        ethernet += struct.pack('!HH', 123, 0x8100 if i+1 < vlans else ethertype)
    return ethernet + bytes(ip) + transport


class PolicyTests(unittest.TestCase):
    def validate(self, value=None):
        return capture.validate(value or request(), {'ens4'}, NETWORKS)

    def test_closed_request_and_independent_scope(self):
        self.assertEqual(self.validate().host, '10.88.10.100')
        changes = [dict(interface='ens3'), dict(interface='lo'), dict(interface='ens4;id'),
                   dict(host='10.88.0.11'), dict(host='fd88:1::1'), dict(host='::'),
                   dict(host='fe80::1%ens4'), dict(host='127.0.0.1'), dict(host='224.0.0.1'),
                   dict(host='10.88.10.0/24'), dict(host='--interface'), dict(port=22),
                   dict(port=18090), dict(port=True), dict(port=0), dict(port=65536),
                   dict(protocol='tcp or udp'), dict(protocol=['tcp']), dict(duration_seconds=True),
                   dict(duration_seconds=0), dict(duration_seconds=61), dict(max_bytes=4095),
                   dict(max_bytes=16*1024*1024+1), dict(max_bytes=True), dict(filter='port 80')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate({**request(), **change})
        value=request();value.pop('host')
        with self.assertRaises(ValueError):self.validate(value)

    def test_ipv4_ipv6_tcp_udp_strip_payload_options_and_padding(self):
        for family in [4, 6]:
            for protocol in ['tcp', 'udp']:
                for vlans in [0, 1, 2]:
                    with self.subTest(family=family, protocol=protocol, vlans=vlans):
                        host='10.88.10.100' if family == 4 else 'fd88:16::100'
                        config=self.validate({**request(), 'host':host, 'protocol':protocol})
                        raw=packet(family, protocol, options=protocol == 'tcp', vlans=vlans)
                        kept=capture.headers(raw+b'private-padding', config, NETWORKS)
                        self.assertIsNotNone(kept)
                        self.assertEqual(len(kept), 14+vlans*4+(20 if family == 4 else 40)+(20 if protocol == 'tcp' else 8))
                        self.assertNotIn(PAYLOAD, kept)
                        self.assertNotIn(OPTIONS, kept)
                        self.assertNotIn(b'private-padding', kept)
                        self.assertTrue(raw.startswith(kept))

    def test_endpoint_pair_and_reverse_direction(self):
        config=self.validate()
        self.assertIsNotNone(capture.headers(packet(source='10.88.10.100', destination='10.88.10.1', source_port=18080, destination_port=40000), config, NETWORKS))
        for raw in [packet(destination='10.88.10.101'), packet(destination_port=18081),
                    packet(source='10.88.10.100', destination='10.88.10.1'),
                    packet(source='10.88.0.11'), packet(source_port=22), packet(protocol='udp')]:
            self.assertIsNone(capture.headers(raw, config, NETWORKS))

    def test_fragments_extensions_options_malformed_lengths_and_encapsulation(self):
        config=self.validate()
        raw=packet()
        for field, value in [(14,0x46), (20,0x20), (21,1), (16,255), (23,1), (46,0x40)]:
            frame=bytearray(raw);frame[field]=value
            self.assertIsNone(capture.headers(bytes(frame), config, NETWORKS))
        for prefix in range(len(raw)):
            self.assertIsNone(capture.headers(raw[:prefix], config, NETWORKS))
        self.assertIsNone(capture.headers(packet(vlans=3), config, NETWORKS))
        v6=bytearray(packet(6));v6[20]=44
        config6=self.validate({**request(),'host':'fd88:16::100'})
        self.assertIsNone(capture.headers(bytes(v6), config6, NETWORKS))
        self.assertIsNone(capture.headers(packet(6,source='fd88:1::1'), config6, NETWORKS))
        udp=bytearray(packet(protocol='udp'));udp[38:40]=b'\x00\x07'
        self.assertIsNone(capture.headers(bytes(udp), self.validate({**request(),'protocol':'udp'}), NETWORKS))

    def test_untrusted_bytes_are_bounded_and_fail_closed(self):
        rng=random.Random(16)
        config=self.validate()
        for length in range(1000):
            self.assertIsNone(capture.headers(rng.randbytes(length), config, NETWORKS))
        self.assertIsNone(capture.headers(b'x'*(capture.MAX_FRAME+1), config, NETWORKS))
        self.assertIsNone(capture.headers(bytearray(packet()), config, NETWORKS))


if __name__ == '__main__':unittest.main()
