"""Boot read-only appliance images using private disposable overlays.

Run only through scripts/test-image.sh. This fixture generates per-guest temporary credentials;
its private overlays must never be shipped as appliance images.
"""
import hashlib
import http.client
import json
import os
import secrets
import re
from pathlib import Path
import socket
import socketserver
import shlex
import shutil
import ssl
import subprocess
import threading
import time
from vnc import Console
from installer import SerialChannel, shell_status
from platform_identity import reference, measure
from package_inventory import RPM_QUERY_FORMAT, parse_rpm_query

if os.environ.get('RIVERLB_VM_TEST') != 'disposable-container':
    raise SystemExit('Use scripts/test-image.sh; do not run against production disks')
PROFILE = reference(Path(__file__).with_name('kvm-reference.json'))
OUTPUT = Path('/output')
OUTPUT.mkdir(mode=0o700, exist_ok=True)
os.umask(0o077)
FIRMWARE = os.environ.get('RIVERLB_IMAGE_FIRMWARE', 'bios')
if FIRMWARE not in ('bios', 'uefi'):
    raise SystemExit('Invalid test firmware')


def wait(function, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, ssl.SSLError, http.client.HTTPException):
            pass
        time.sleep(1)
    raise AssertionError(f'Timed out: {function}')


class Guest:
    def __init__(self, name, number):
        self.name = name
        self.admin_password = secrets.token_hex(20) + 'a9'
        self.root_password = secrets.token_hex(20) + 'b8'
        self.vnc = 5910 + number
        self.management_mac = f'52:54:00:45:00:{self.vnc % 256:02x}'
        self.traffic_mac = f'52:54:00:45:01:{self.vnc % 256:02x}'
        self.https = 18443 + number
        self.traffic = 18480 + number
        self.serial = OUTPUT / (name + '.serial.log')
        self.channel_path = OUTPUT / (name + '.serial.sock')
        self.channel = None
        self.shell_ready = False
        self.overlay = OUTPUT / (name + '.qcow2')
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', '/base/riverlb.qcow2', str(self.overlay)], check=True)
        self.process = None
        self.certificate = None
        self.cookie = None
        self.nvram = OUTPUT / (name + '.efivars.fd')
        if FIRMWARE == 'uefi':
            shutil.copyfile('/base/efivars.fd', self.nvram)

    def start(self):
        log = (OUTPUT / (self.name + '.qemu.log')).open('a')
        self.process = subprocess.Popen(['/usr/libexec/qemu-kvm', '-machine', 'accel=kvm', '-cpu', 'host',
            '-m', str(PROFILE['memory_mib']), '-smp', str(PROFILE['cpus']), '-display', 'none', '-vnc', f'127.0.0.1:{self.vnc - 5900}',
            '-drive', f'file={self.overlay},format=qcow2,if=virtio', '-boot', 'c',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{self.https}-:18090',
            '-device', f'virtio-net-pci,netdev=net0,mac={self.management_mac}',
            '-netdev', f'user,id=traffic,net=10.0.3.0/24,hostfwd=tcp:127.0.0.1:{self.traffic}-10.0.3.15:18080',
            '-device', f'virtio-net-pci,netdev=traffic,mac={self.traffic_mac}',
            '-monitor', f'unix:{OUTPUT}/{self.name}.monitor,server=on,wait=off',
            '-chardev',f'socket,id=probe,path={self.channel_path},server=on,wait=off,logfile={self.serial}',
            '-serial','chardev:probe'] + (
                ['-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
                 '-drive', f'if=pflash,format=raw,unit=1,file={self.nvram}'] if FIRMWARE == 'uefi' else []), stdout=log, stderr=log)
        log.close()
        wait(lambda: self.console_ready(), 60)
        self.channel=SerialChannel(self.channel_path)
        self.shell_ready=False

    def console_ready(self):
        if self.process.poll() is not None:
            raise AssertionError((OUTPUT / (self.name + '.qemu.log')).read_text())
        console = Console(self.vnc)
        console.close()
        return True

    def screenshot(self, suffix='console'):
        console = Console(self.vnc)
        console.screenshot(OUTPUT / (self.name + '-' + suffix + '.png'))
        console.close()

    def setup(self):
        # Boot delays are bounded; screenshots and HTTPS checks expose failures.
        time.sleep(30)
        self.screenshot('before-setup')
        console = Console(self.vnc)
        for answer in (self.name, '1', 'admin', self.admin_password, self.admin_password, self.root_password, self.root_password, 'APPLY'):
            console.type(answer + '\n')
            time.sleep(2)
        console.close()
        wait(lambda: ssl.get_server_certificate(('127.0.0.1', self.https)), 120)
        self.certificate = ssl.get_server_certificate(('127.0.0.1', self.https))
        self.screenshot('after-setup')
        self.login()

    def request(self, path, method='GET', body=None):
        context = ssl.create_default_context(cadata=self.certificate)
        class Connection(http.client.HTTPSConnection):
            def connect(connection):
                connection.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', self.https), timeout=5), server_hostname='10.0.2.15')
        connection = Connection('10.0.2.15', 18090, timeout=5, context=context)
        headers = {'X-RiverLB-Request': 'configure', 'Content-Type': 'application/json'}
        if self.cookie:
            headers['Cookie'] = self.cookie
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        data = response.read()
        cookie = response.getheader('Set-Cookie')
        connection.close()
        assert response.status == 200, (response.status, data)
        return json.loads(data), cookie

    def login(self):
        _, cookie = self.request('/api/v1/auth/login', 'POST', dict(username='admin', password=self.admin_password))
        self.cookie = cookie.split(';', 1)[0]
        status = self.request('/api/v1/appliance')[0]
        assert status['hostname'] == self.name and status['role'] == 'standalone', status
        return status

    def inspect(self):
        # Authenticate through the real console, then prove an executed UART
        # challenge before sending metadata code. No network audit port is opened.
        if not self.shell_ready:
            console=Console(self.vnc);console.chord('ctrl','alt','f2');time.sleep(2)
            console.type('root\n');time.sleep(2);console.type(self.root_password+'\n');time.sleep(2)
            console.type('exec </dev/ttyS0 >/dev/ttyS0 2>&1\n');console.close()
            assert shell_status(self.channel,self.serial,'true',seconds=20)[0]==0
            self.shell_ready=True
        code = f"""import json,pathlib,subprocess,os
p=pathlib.Path('/var/lib/riverlb')
def out(args):return subprocess.run(args,text=True,stdout=subprocess.PIPE).stdout.strip()
data=dict(machine_id=pathlib.Path('/etc/machine-id').read_text().strip(),selinux=out(['getenforce']),ssh_enabled=out(['systemctl','is-enabled','sshd']),root_state=out(['passwd','-S','root']).split()[1],database_mode=p.joinpath('riverlb.db').stat().st_mode & 511,setup_completed=p.joinpath('.firstboot.complete').exists(),firmware='uefi' if pathlib.Path('/sys/firmware/efi').exists() else 'bios')
data['cpus']=os.cpu_count()
data['memory_kib']=int(next(l.split()[1] for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemTotal:')))
data['disk_bytes']=int(pathlib.Path('/sys/class/block/vda/size').read_text())*512
data['disk_driver']=pathlib.Path('/sys/class/block/vda/device/driver').resolve().name
interfaces={{p.joinpath('address').read_text().strip():p.name for p in pathlib.Path('/sys/class/net').iterdir() if p.joinpath('device').exists()}}
data['management_interface']=interfaces[{self.management_mac!r}]
data['traffic_interface']=interfaces[{self.traffic_mac!r}]
data['nic_drivers']=[pathlib.Path('/sys/class/net/'+data[k]+'/device/driver').resolve().name for k in ['management_interface','traffic_interface']]
data['management_addresses']=[a['local'] for x in json.loads(out(['ip','-j','-4','address','show','dev',data['management_interface']])) for a in x['addr_info']]
data['traffic_dhcp']=out(['nmcli','-g','DHCP4.OPTION','device','show',data['traffic_interface']])
pid=out(['systemctl','show','riverlb','-p','MainPID','--value'])
fields=dict(l.split(':',1) for l in pathlib.Path('/proc/'+pid+'/status').read_text().splitlines() if ':' in l)
data['service_uid']=int(fields['Uid'].split()[0]);data['service_caps']=int(fields['CapEff'].strip(),16)
data['rpm_inventory']=out(['rpm','-qa','--qf',{RPM_QUERY_FORMAT!r}])
print('RIVERLB_BOOT_METADATA='+json.dumps(data))
"""
        command='python3 -c '+shlex.quote(code)
        status,output=shell_status(self.channel,self.serial,command,seconds=30)
        assert status==0,'Guest metadata probe failed'
        match=re.search(r'RIVERLB_BOOT_METADATA=(\{[^\r\n]+\})',output)
        assert match,'Executed metadata reply missing'
        data=json.loads(match.group(1))
        assert len(data['machine_id']) == 32, data
        assert data['selinux'] == 'Enforcing' and data['ssh_enabled'] == 'disabled', data
        assert data['root_state'] == 'P' and data['setup_completed'], data
        assert data['database_mode'] == 0o600, data
        assert data['firmware'] == FIRMWARE, data
        assert data['cpus']==PROFILE['cpus'] and 3*1024**2<data['memory_kib']<=PROFILE['memory_mib']*1024
        assert data['disk_bytes']==PROFILE['disk_gib']*1024**3 and data['disk_driver']=='virtio_blk'
        assert data['nic_drivers']==['virtio_net','virtio_net']
        assert '10.0.2.15' in data['management_addresses'] and not data['traffic_dhcp']
        assert data['service_uid']>0 and data['service_caps']==0x400
        inventory = parse_rpm_query(data.pop('rpm_inventory'), FIRMWARE)
        inventory_path = OUTPUT / 'installed-rpms.json'
        if inventory_path.exists():
            assert json.loads(inventory_path.read_text()) == inventory, 'Clone package inventories differ'
        else:
            inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + '\n')
        self.screenshot('console-recovery')
        return data

    def shutdown(self):
        if self.process is None or self.process.poll() is not None:
            return
        with socket.socket(socket.AF_UNIX) as monitor:
            monitor.connect(str(OUTPUT / (self.name + '.monitor')))
            monitor.recv(4096)
            monitor.sendall(b'system_powerdown\n')
        try:
            self.process.wait(timeout=60)
            if self.channel is not None:self.channel.close();self.channel=None
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
            raise AssertionError('Guest did not shut down cleanly')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            data = self.request.recv(256)
            if data:
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


def transfer(guest):
    with socket.create_connection(('127.0.0.1', guest.traffic), timeout=3) as client:
        client.sendall(b'booted-appliance-traffic')
        return client.recv(256) == b'booted-appliance-traffic'


def main():
    platform = measure(PROFILE)
    guests = []
    backend = socketserver.ThreadingTCPServer(('0.0.0.0', 18082), Echo)
    backend.daemon_threads = True
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    try:
        first = Guest('lb-fixture-a', 0)
        guests.append(first)
        first.start()
        first.setup()
        first_identity = first.inspect()
        config, _ = first.request('/api/v1/config')
        # Management and forwarding must use separate NICs under the installed
        # privilege policy. The second SLIRP network is private to this guest.
        config['config']['network'] = dict(vlans=[dict(name='traffic',interface=first_identity['traffic_interface'],role='external')],
            self_ips=[dict(name='traffic-local',address='10.0.3.15/24',vlan='traffic')])
        config['config']['virtual_servers'] = [dict(name='boot-test', listen='10.0.3.15:18080', ingress_vlan='traffic', algorithm='round_robin', members=['10.0.3.2:18082'])]
        applied,_ = first.request('/api/v1/config', 'PUT', dict(config=config['config'], revision=config['revision']))
        if applied['confirmation']['pending']:
            first.request('/api/v1/config/confirm','POST',dict(revision=applied['revision']))
        wait(lambda: transfer(first), 30)
        def completed_statistics():
            counters = first.request('/api/v1/statistics')[0]['virtual_servers'][0]['traffic']
            return counters if counters['completed'] >= 1 else None
        previous_counters = wait(completed_statistics, 30)
        assert previous_counters['bytes_in'] > 0 and previous_counters['bytes_out'] > 0
        first.shutdown()
        for _ in range(2):
            first.start()
            wait(lambda: ssl.get_server_certificate(('127.0.0.1', first.https)), 120)
            assert ssl.get_server_certificate(('127.0.0.1', first.https)) == first.certificate
            first.login()
            restored, _ = first.request('/api/v1/config')
            assert restored['config']['virtual_servers'][0]['name'] == 'boot-test'
            counters = first.request('/api/v1/statistics')[0]['virtual_servers'][0]['traffic']
            for field in ('accepted', 'completed', 'bytes_in', 'bytes_out'):
                assert counters[field] >= previous_counters[field], (field, counters, previous_counters)
            wait(lambda: transfer(first), 30)
            def incremented_statistics():
                value=first.request('/api/v1/statistics')[0]['virtual_servers'][0]['traffic']
                return value if value['completed']>counters['completed'] else None
            previous_counters=wait(incremented_statistics,30)
            first.shutdown()
        second = Guest('lb-fixture-b', 1)
        guests.append(second)
        second.start()
        second.setup()
        second_identity = second.inspect()
        assert first_identity['machine_id'] != second_identity['machine_id']
        assert first.certificate != second.certificate
        second.shutdown()
        (OUTPUT / 'report.json').write_text(json.dumps(dict(status='passed', firmware=FIRMWARE, platform=platform, tests=[
            'console setup', 'verified HTTPS login', 'real firewalld VIP TCP forwarding',
            'clean shutdown', 'reboot configuration/account/certificate persistence',
            'persisted traffic statistics', 'independent clone certificates and machine IDs',
            'two completed-appliance reboots', 'separate management and traffic NICs',
            'SELinux enforcing', 'SSH disabled', 'console recovery login', 'private database permissions']), indent=2) + '\n')
        print('Booted appliance setup, HTTPS, traffic, reboot and unique clone certificates passed', flush=True)
    finally:
        for guest in guests:
            if guest.process is not None and guest.process.poll() is None:
                try:
                    guest.screenshot('failure')
                except Exception:
                    pass
                guest.process.terminate()
                try:
                    guest.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    guest.process.kill()
            if guest.channel is not None:guest.channel.close();guest.channel=None
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    main()
