#!/usr/bin/env python3
"""ASTF raw TCP request/response through a full proxy, not HTTP or TLS emulation."""
import ipaddress
from trex.astf.api import (ASTFProgram, ASTFIPGenDist, ASTFIPGenGlobal, ASTFIPGen,
                          ASTFTCPClientTemplate, ASTFTCPServerTemplate,
                          ASTFAssociationRule, ASTFAssociation, ASTFTemplate, ASTFProfile)


class RiverLBProfile:
    def get_profile(self, **kwargs):
        vip = str(ipaddress.IPv4Address(kwargs.get('vip', '198.18.10.100')))
        first = str(ipaddress.IPv4Address(kwargs.get('client_start', '198.18.10.64')))
        last = str(ipaddress.IPv4Address(kwargs.get('client_end', '198.18.10.127')))
        if int(ipaddress.IPv4Address(first)) > int(ipaddress.IPv4Address(last)):
            raise ValueError('client_start must be <= client_end')
        response_bytes = int(kwargs.get('response_bytes', 1024))
        port = int(kwargs.get('port', 9000))
        if not 1 <= response_bytes <= 1048576 or not 1 <= port <= 65535:
            raise ValueError('response_bytes 1..1048576; port 1..65535')
        client, server = ASTFProgram(), ASTFProgram()
        client.send(b'R' * 64)
        client.recv(response_bytes)
        server.recv(64)
        server.send(b'S' * response_bytes)
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset='0.0.0.0'),
                          dist_client=ASTFIPGenDist(ip_range=[first, last], distribution='seq'),
                          dist_server=ASTFIPGenDist(ip_range=[vip, vip], distribution='seq'))
        template = ASTFTemplate(
            client_template=ASTFTCPClientTemplate(program=client, ip_gen=ip_gen, port=port, cps=1),
            server_template=ASTFTCPServerTemplate(program=server,
                assoc=ASTFAssociation(ASTFAssociationRule(port=port))))
        return ASTFProfile(default_ip_gen=ip_gen, templates=template)


def register():
    return RiverLBProfile()
