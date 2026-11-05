#!/usr/bin/python3 -I
"""Fixed private capture worker for the installed privileged broker.

The broker supplies only a random job ID and a root-owned request file.
There is no caller-selected command, path, namespace, filter or output descriptor.
"""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time


ROOT = Path('/run/riverlb-captures')
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C'}


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def limits():
    for kind, maximum in [(resource.RLIMIT_CPU, 5), (resource.RLIMIT_AS, 128*1024*1024),
                          (resource.RLIMIT_FSIZE, 16*1024*1024), (resource.RLIMIT_NOFILE, 32),
                          (resource.RLIMIT_CORE, 0)]:
        _, hard = resource.getrlimit(kind)
        maximum = maximum if hard == resource.RLIM_INFINITY else min(hard, maximum)
        resource.setrlimit(kind, (maximum, maximum))
    os.nice(10)


def drop_capabilities():
    """Keep the already-open packet FD private; never pass it to the daemon."""
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(47, 4, 0, 0, 0) != 0:
        raise OSError('Capture privilege restriction failed')
    if libc.capset(ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data*2)())) != 0:
        raise OSError('Capture capability drop failed')


def inventory(management_interfaces):
    import ipaddress
    if (type(management_interfaces) is not list or not 1 <= len(management_interfaces) <= 64
            or any(type(n) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', n) is None
                   for n in management_interfaces)):
        raise ValueError('Invalid trusted management inventory')
    program = Path('/usr/sbin/ip').resolve(strict=True)
    for path in [program, *program.parents]:
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe inventory executable')
    result = subprocess.run(['/usr/sbin/ip', '-j', 'address', 'show'], capture_output=True,
                            timeout=5, env=ENV, close_fds=True)
    if result.returncode or len(result.stdout) > 2*1024*1024:
        raise ValueError('Capture inventory unavailable')
    links = json.loads(result.stdout)
    if type(links) is not list or len(links) > 1024:
        raise ValueError('Invalid kernel inventory')
    networks = []
    for name in management_interfaces:
        link = next((link for link in links if link.get('ifname') == name), None)
        if link is None or not link.get('addr_info'):
            raise ValueError('Management exclusions unavailable')
        for address in link['addr_info']:
            networks.append(ipaddress.ip_network(str(address['local'])+'/'+str(address['prefixlen']), strict=False))
    return links, networks


def run(directory, configuration, policy, files, stop):
    if (type(configuration) is not dict
            or set(configuration) != {'request', 'interface_index', 'management_interfaces', 'protected_ports'}
            or type(configuration['request']) is not dict
            or type(configuration['interface_index']) is not int
            or configuration['interface_index'] <= 0):
        raise ValueError('Invalid private capture configuration')
    # Subscribe before inventory/binding. Address or link changes queued during
    # setup cancel capture before any packet can be written.
    changed = False
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as events:
        events.bind((0, 1 | 0x10 | 0x100))
        links, networks = inventory(configuration['management_interfaces'])
        interface = configuration['request'].get('interface')
        link = next((link for link in links if link.get('ifname') == interface), None)
        if link is None or link.get('ifindex') != configuration['interface_index']:
            raise ValueError('Capture interface changed')
        extra = configuration['protected_ports']
        if type(extra) is not list or len(extra)>16 or any(type(p) is not int or not 1<=p<=65535 for p in extra):
            raise ValueError('Invalid management port exclusions')
        protected = policy.DEFAULT_PROTECTED_PORTS | set(extra)
        request = policy.validate(configuration['request'], {interface}, networks, protected)
        # Protocol zero avoids receiving from every NIC between creation/bind.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as packets:
            packets.bind((request.interface, 3))  # ETH_P_ALL, bound interface only.
            packets.setblocking(False)
            drop_capabilities()

            def receive(deadline):
                nonlocal changed
                ready, _, _ = select.select([events, packets], [], [], max(0, min(.2, deadline-time.monotonic())))
                if events in ready:
                    changed = True
                    return None
                if packets not in ready:
                    return None
                try:
                    frame, address = packets.recvfrom(policy.MAX_FRAME)
                except BlockingIOError:
                    return None
                return frame if address[0] == request.interface else None

            result = files.write(directory, request, receive,
                                 lambda frame: policy.headers(frame, request, networks, protected),
                                 lambda: changed or stop.is_set())
            # Linux AF_PACKET v1 counters include filtered and kernel-dropped
            # packets; reading them never changes forwarding state.
            received, dropped = struct.unpack('II', packets.getsockopt(263, 6, 8))
            result.update(kernel_received=received, kernel_dropped=dropped)
            if changed:
                result['reason'] = 'network_changed'
            return result


def read_configuration(directory):
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Unsafe capture directory')
        fd = os.open('request.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as file:
            info = os.fstat(file.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 32768):
                raise ValueError('Unsafe private capture request')
            data = file.read(32769)
            if len(data) > 32768:
                raise ValueError('Private capture request exceeds limit')
            return json.loads(data)
    finally:
        os.close(parent)


def status(directory, value):
    temporary = directory/'.status.new'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as file:
            json.dump(value, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, directory/'status.json')
    finally:
        temporary.unlink(missing_ok=True)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or re.fullmatch(r'[0-9a-f]{32}', sys.argv[1]) is None:
        return 2
    os.umask(0o077)
    directory = ROOT/sys.argv[1]
    trusted = False
    try:
        configuration = read_configuration(directory)
        trusted = True
        policy = load_module('riverlb_capture_policy', 'capture_policy.py')
        files = load_module('riverlb_capture_file', 'capture_file.py')
        limits()
        stop = threading.Event()
        ending = threading.Event()
        signal.signal(signal.SIGUSR1, lambda *_: stop.set())
        def terminate(*_):
            stop.set()
            ending.set()
        for kind in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(kind, terminate)
        result = run(directory, configuration, policy, files, stop)
        status(directory, dict(state='complete', **result))
        # Keep only the private file, not a packet socket, for a fixed retention
        # interval. A cancel signal cannot renew this timer. Unit stop/removal
        # interrupts retention and systemd also removes the runtime directory.
        ending.wait(600)
        return 0
    except Exception:
        # Never include exception/packet/request bytes in diagnostics.
        if trusted:
            try:
                status(directory, dict(state='failed', reason='worker_failed'))
            except Exception:
                pass
        return 1
    finally:
        if trusted:
            try:
                cleanup(directory)
            except Exception:
                pass  # RuntimeDirectory cleanup provides an independent bound.


def cleanup(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Unsafe capture cleanup directory')
    allowed = {'request.json', 'status.json', 'capture.pcap', '.status.new'}
    children = list(directory.iterdir())
    for path in children:
        info = path.lstat()
        if (path.name not in allowed or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('Unsafe capture cleanup file')
    for path in children:
        path.unlink()
    directory.rmdir()


if __name__ == '__main__':sys.exit(main())
