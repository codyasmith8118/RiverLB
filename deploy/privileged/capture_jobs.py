"""Single-job private capture lifecycle. No caller-selected paths or units."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import syslog
import threading
import time


ROOT = Path('/run/riverlb-captures')
FILES = {'request.json', 'status.json', 'capture.pcap', '.status.new'}
RETENTION = 600


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


selectors = module('riverlb_capture_policy', 'capture_policy.py')
pcap = module('riverlb_capture_file', 'capture_file.py')


class Capture:
    def __init__(self, broker, policy, process, success, root=ROOT, owner_uid=0,
                 clock=time.monotonic, wall=time.time, janitor=True):
        self.broker, self.policy, self.process, self.success = broker, policy, process, success
        self.root, self.owner_uid, self.clock, self.wall = root, owner_uid, clock, wall
        self.lock = threading.RLock()
        self.job = None
        self.available = False
        self.ending = threading.Event()
        try:
            self.directory(root)
            entries = list(root.iterdir())
            self.policy.require(len(entries) <= 1, 'Capture storage requires console recovery')
            for path in entries:
                self.identifier(path.name)
                self.erase(path.name)
            self.available = True
        except Exception:
            # Optional diagnostic damage must not disable core networking/HA.
            syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_WARNING, 'RiverLB capture storage unavailable')
        if janitor and self.available:
            threading.Thread(target=self.sweep, daemon=True).start()

    def directory(self, path):
        info = path.lstat()
        self.policy.require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.owner_uid
                            and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe capture directory')

    def identifier(self, value):
        self.policy.require(type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value) is not None)
        return value

    def owner(self, value):
        self.policy.require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None)
        return value

    def unit(self, identifier):
        return 'riverlb-capture@' + self.identifier(identifier) + '.service'

    def systemctl(self, *arguments):
        return self.success(self.process('/usr/bin/systemctl', list(arguments), timeout=5))['stdout']

    def stop_unit(self, identifier):
        unit = self.unit(identifier)
        result = self.process('/usr/bin/systemctl', ['stop', unit], timeout=5)
        if result['code'] != 0:
            text = self.systemctl('show', unit, '--property=LoadState,ActiveState,MainPID,ControlPID')
            values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
            self.policy.require(values.get('LoadState') == 'not-found'
                                or (values.get('ActiveState') in {'inactive', 'failed'}
                                    and values.get('MainPID') == '0' and values.get('ControlPID') == '0'),
                                'Capture worker did not stop')

    def reset_unit(self, identifier):
        result = self.process('/usr/bin/systemctl', ['reset-failed', self.unit(identifier)], timeout=5)
        if result['code'] != 0:
            text = self.systemctl('show', self.unit(identifier), '--property=LoadState')
            self.policy.require('LoadState=not-found' in text)

    def management_networks(self):
        links = json.loads(self.success(self.process('/usr/sbin/ip', ['-j', 'address', 'show']))['stdout'])
        networks = []
        names = self.broker.configuration['management_interfaces']
        self.policy.require(type(names) is list and 1 <= len(names) <= 64)
        for name in names:
            link = next((link for link in links if link.get('ifname') == name), None)
            self.policy.require(link is not None and bool(link.get('addr_info')), 'Management exclusions unavailable')
            for address in link['addr_info']:
                networks.append(ipaddress.ip_network(str(address['local'])+'/'+str(address['prefixlen']), strict=False))
        return networks

    def file(self, path, limit):
        self.directory(path.parent)
        info = path.lstat()
        self.policy.require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner_uid
                            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                            and info.st_size <= limit, 'Unsafe capture file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            raise ValueError('Capture file changed')
        return fd, opened

    def read(self, path, limit):
        fd, _ = self.file(path, limit)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(limit + 1)
        self.policy.require(len(data) <= limit)
        return json.loads(data)

    def erase(self, identifier):
        path = self.root / self.identifier(identifier)
        if not path.exists():
            self.stop_unit(identifier)
            self.reset_unit(identifier)
            return
        self.directory(path)
        entries = list(path.iterdir())
        self.policy.require(all(p.name in FILES for p in entries), 'Unknown capture storage entry')
        # Stop the entire fixed worker cgroup, including any inventory child.
        self.stop_unit(identifier)
        for item in path.iterdir() if path.exists() else []:
            self.policy.require(item.name in FILES)
            fd, _ = self.file(item, 16*1024*1024)
            os.close(fd)
            item.unlink()
        if path.exists():
            path.rmdir()
        # Failure state must not retain an unbounded set of template instances.
        self.reset_unit(identifier)

    def sweep(self):
        while not self.ending.wait(1):
            try:
                with self.lock:
                    self.refresh()
            except Exception:
                syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_WARNING, 'RiverLB capture cleanup failed')

    def refresh(self):
        if self.job is None:
            return
        job = self.job
        path = self.root / job['id'] / 'status.json'
        if job['finished'] is None:
            if path.exists():
                value = self.read(path, 4096)
                if value.get('state') == 'failed':
                    self.policy.fields(value, {'state', 'reason'})
                    self.policy.require(value['reason'] == 'worker_failed')
                else:
                    self.policy.fields(value, {'state', 'reason', 'bytes', 'packets', 'observed', 'kernel_received', 'kernel_dropped'})
                    self.policy.require(value['state'] == 'complete'
                                        and value['reason'] in {'canceled', 'time_limit', 'byte_limit', 'packet_limit', 'network_changed'})
                    self.policy.require(all(type(value[k]) is int for k in ['bytes', 'packets', 'observed'])
                                        and 24 <= value['bytes'] <= job['request']['max_bytes']
                                        and 0 <= value['packets'] <= value['observed'] <= 200000)
                    self.policy.require(all(type(value[k]) is int and 0 <= value[k] <= 0xffffffff
                                            for k in ['kernel_received', 'kernel_dropped'])
                                        and value['kernel_dropped'] <= value['kernel_received'])
                age = max(0, self.wall() - path.stat().st_mtime)
                job['finished'] = self.clock() - min(RETENTION, age)
                job.update(value)
            else:
                if self.clock() > job['started'] + job['request']['duration_seconds'] + 10:
                    self.stop_unit(job['id'])
                text = self.systemctl('show', self.unit(job['id']), '--property=ActiveState,ExecMainStatus,Result')
                values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                self.policy.require(values.get('ActiveState') in {'active', 'activating', 'deactivating', 'inactive', 'failed'})
                if values['ActiveState'] in {'inactive', 'failed'}:
                    job['finished'] = self.clock()
                    job['state'], job['reason'] = 'failed', 'worker_failed'
        if job['finished'] is not None and not job.get('audited', False):
            syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, json.dumps(dict(
                service='riverlb-capture', event='stopped', id=job['id'], reason=job['reason'],
                bytes=job.get('bytes',0), packets=job.get('packets',0),
                kernel_dropped=job.get('kernel_dropped',0))))
            job['audited']=True
        if job['state'] == 'complete' and not (self.root/job['id']).exists():
            self.job = None
            return
        if job['finished'] is not None and self.clock() >= job['finished'] + RETENTION:
            self.erase(job['id'])
            self.job = None

    def view(self):
        job = self.job
        if job is None:
            return dict(state='idle')
        remaining = (job['finished'] + RETENTION - self.clock()) if job['finished'] is not None else None
        return dict(id=job['id'], state=job['state'], reason=job.get('reason'), request=dict(job['request']),
                    bytes=job.get('bytes', 0), packets=job.get('packets', 0),
                    kernel_received=job.get('kernel_received', 0), kernel_dropped=job.get('kernel_dropped', 0),
                    retention_seconds=max(0, int(remaining)) if remaining is not None else None)

    def start(self, owner, value, extra):
        self.policy.require(self.job is None, 'A capture already exists; delete it or wait for expiry')
        self.policy.require(type(value) is dict and type(value.get('interface')) is str)
        link = self.broker.device(value['interface'])
        name = link['ifname']
        self.policy.require(name not in self.broker.configuration['management_interfaces'])
        self.policy.require(type(extra) is list and len(extra)<=16 and all(type(p) is int and 1<=p<=65535 for p in extra))
        protected=selectors.DEFAULT_PROTECTED_PORTS | set(extra)
        self.policy.require(len(protected)<=16)
        request = selectors.validate(value, {name}, self.management_networks(), protected)
        identifier = secrets.token_hex(16)
        path = self.root / identifier
        path.mkdir(mode=0o700)
        try:
            fd = os.open(path/'request.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(dict(request=request.__dict__, interface_index=link['ifindex'],
                               management_interfaces=self.broker.configuration['management_interfaces'],protected_ports=sorted(protected)), stream)
                stream.flush()
                os.fsync(stream.fileno())
            self.job = dict(id=identifier, owner=owner, request=request.__dict__, started=self.clock(),
                            finished=None, state='running')
            # Type=exec returns after exec, not after the bounded capture ends.
            self.systemctl('start', self.unit(identifier))
        except Exception:
            self.erase(identifier)
            self.job = None
            raise
        return self.view()

    def export(self, offset):
        job = self.job
        self.policy.require(job['state'] == 'complete', 'Capture is not exportable')
        self.policy.require(type(offset) is int and 0 <= offset <= job['bytes'])
        fd, info = self.file(self.root/job['id']/'capture.pcap', job['request']['max_bytes'])
        with os.fdopen(fd, 'rb') as stream:
            self.policy.require(info.st_size == job['bytes'] and stream.read(24) == pcap.PCAP_HEADER,
                                'Capture file does not match completed output')
            if 'sha256' not in job:
                stream.seek(0)
                digest = hashlib.sha256()
                while data := stream.read(65536):
                    digest.update(data)
                job['sha256'] = digest.hexdigest()
                job['inode'] = (info.st_dev, info.st_ino)
            self.policy.require(job['inode'] == (info.st_dev, info.st_ino))
            stream.seek(offset)
            data = stream.read(min(65536, info.st_size-offset))
        return dict(offset=offset, total=info.st_size, data=base64.b64encode(data).decode('ascii'), sha256=job['sha256'])

    def peer(self, peer):
        self.policy.require(peer[1] in {0, self.broker.configuration['uid']})
        if peer[1] == 0:
            self.policy.require(os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/'+str(peer[0])+'/ns/net').st_ino,
                                'Foreign capture namespace rejected')
            return
        # No CAP_SYS_PTRACE: use PID 1's root-protected service identity and
        # applied namespace restrictions, not an untrusted namespace assertion.
        for unit in ['riverlb.service', 'riverlb-ha.service']:
            result = self.process('/usr/bin/systemctl', ['show', unit, '--property=MainPID,User,PrivateNetwork,NetworkNamespacePath,RestrictNamespaces'], timeout=5)
            if result['code'] != 0:
                continue
            values = dict(line.split('=', 1) for line in result['stdout'].splitlines() if '=' in line)
            if (values.get('MainPID') == str(peer[0]) and values.get('User') == 'riverlb'
                    and values.get('PrivateNetwork') == 'no' and values.get('NetworkNamespacePath') == ''
                    and values.get('RestrictNamespaces') == 'yes'):
                return
        self.policy.require(False, 'Capture requires the protected installed daemon')

    def dispatch(self, parameters, peer):
        self.peer(peer)
        self.policy.require(type(parameters) is dict and type(parameters.get('operation')) is str)
        operation = parameters['operation']
        if operation == 'stop_all':
            self.policy.fields(parameters, {'operation'})
            with self.lock:
                if self.job is not None:
                    self.erase(self.job['id']);self.job=None
                    return dict(changed=True)
                return dict(changed=False)
        self.policy.require(self.available, 'Capture storage unavailable')
        if operation == 'interfaces':
            self.policy.fields(parameters, {'operation'})
            names = []
            for name in self.broker.configuration['traffic_interfaces']:
                try:
                    link = self.broker.device(name)
                    names.append(dict(name=name, index=link['ifindex']))
                except ValueError:
                    continue
            return dict(interfaces=names)
        with self.lock:
            self.refresh()
            if operation == 'start':
                self.policy.fields(parameters, {'operation', 'owner', 'request', 'protected_ports'})
                result=self.start(self.owner(parameters['owner']), parameters['request'],parameters['protected_ports'])
                return dict(result,changed=True)
            self.policy.require(operation in {'status', 'cancel', 'delete', 'export'})
            self.policy.fields(parameters, {'operation', 'owner'}, {'id'} if operation == 'status' else {'id', 'offset'} if operation == 'export' else {'id'})
            owner = self.owner(parameters['owner'])
            if operation == 'status' and 'id' not in parameters:
                if self.job is not None and self.job['owner'] != owner:
                    return dict(state='busy')
                return self.view()
            identifier = self.identifier(parameters.get('id'))
            self.policy.require(self.job is not None and self.job['id'] == identifier and self.job['owner'] == owner,
                                'Capture unavailable')
            if operation == 'export':
                return self.export(parameters.get('offset'))
            if operation == 'cancel':
                if self.job['finished'] is None:
                    self.systemctl('kill', '--kill-whom=main', '--signal=USR1', self.unit(identifier))
                self.refresh()
                return self.view()
            if operation == 'delete':
                self.erase(identifier)
                self.job = None
                return dict(state='idle')
            return self.view()
