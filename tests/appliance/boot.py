"""Boot read-only appliance images using private disposable overlays.

Run only through scripts/test-image.sh. This fixture uses known test credentials;
its private overlays must never be shipped as appliance images.
"""
import hashlib
import http.client
import json
import os
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

if os.environ.get('RIVERLB_VM_TEST') != 'disposable-container':
    raise SystemExit('Use scripts/test-image.sh; do not run against production disks')
OUTPUT = Path('/output')
OUTPUT.mkdir(mode=0o700, exist_ok=True)
os.umask(0o077)
ADMIN_PASSWORD = 'fixture-admin-password-123'
ROOT_PASSWORD = 'fixture-console-password-123'
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
        self.vnc = 5910 + number
        self.https = 18443 + number
        self.traffic = 18480 + number
        self.audit = 18500 + number
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
            '-m', '2048', '-smp', '2', '-display', 'none', '-vnc', f'127.0.0.1:{self.vnc - 5900}',
            '-drive', f'file={self.overlay},format=qcow2,if=virtio', '-boot', 'c',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{self.https}-:18090,hostfwd=tcp:127.0.0.1:{self.traffic}-:18080,hostfwd=tcp:127.0.0.1:{self.audit}-:18083',
            '-device', f'virtio-net-pci,netdev=net0,mac=52:54:00:45:00:{self.vnc % 256:02x}',
            '-monitor', f'unix:{OUTPUT}/{self.name}.monitor,server=on,wait=off'] + (
                ['-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
                 '-drive', f'if=pflash,format=raw,unit=1,file={self.nvram}'] if FIRMWARE == 'uefi' else []), stdout=log, stderr=log)
        log.close()
        wait(lambda: self.console_ready(), 60)

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
        for answer in (self.name, '1', 'admin', ADMIN_PASSWORD, ADMIN_PASSWORD, ROOT_PASSWORD, ROOT_PASSWORD, 'APPLY'):
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
        _, cookie = self.request('/api/v1/auth/login', 'POST', dict(username='admin', password=ADMIN_PASSWORD))
        self.cookie = cookie.split(';', 1)[0]
        status = self.request('/api/v1/appliance')[0]
        assert status['hostname'] == self.name and status['role'] == 'standalone', status
        return status

    def inspect(self):
        # Operator console recovery, then a one-request metadata server confined
        # to this guest's private NAT. No credentials or key contents are exported.
        console = Console(self.vnc)
        console.chord('ctrl', 'alt', 'f2')
        time.sleep(2)
        console.type('root\n')
        time.sleep(2)
        console.type(ROOT_PASSWORD + '\n')
        time.sleep(2)
        code = """import http.server,json,pathlib,subprocess
p=pathlib.Path('/var/lib/riverlb')
def out(args):return subprocess.run(args,text=True,stdout=subprocess.PIPE).stdout.strip()
data=dict(machine_id=pathlib.Path('/etc/machine-id').read_text().strip(),selinux=out(['getenforce']),ssh_enabled=out(['systemctl','is-enabled','sshd']),root_state=out(['passwd','-S','root']).split()[1],database_mode=p.joinpath('riverlb.db').stat().st_mode & 511,setup_completed=p.joinpath('.firstboot.complete').exists(),firmware='uefi' if pathlib.Path('/sys/firmware/efi').exists() else 'bios')
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps(data).encode())
 def log_message(self,*args):pass
server=http.server.HTTPServer(('10.0.2.15',18083),H);server.handle_request();server.server_close()
"""
        # Lowercase hex avoids long runs of shifted keys in the guest console.
        command = 'firewall-cmd --add-port=18083/tcp >/dev/null && python3 -c ' + shlex.quote('exec(bytes.fromhex("' + code.encode().hex() + '").decode())')
        console.type(command + '\n')
        console.close()
        def retrieve():
            connection = http.client.HTTPConnection('127.0.0.1', self.audit, timeout=5)
            connection.request('GET', '/')
            response = connection.getresponse()
            data = response.read()
            connection.close()
            return json.loads(data)
        data = wait(retrieve, 30)
        assert len(data['machine_id']) == 32, data
        assert data['selinux'] == 'Enforcing' and data['ssh_enabled'] == 'disabled', data
        assert data['root_state'] == 'P' and data['setup_completed'], data
        assert data['database_mode'] == 0o600, data
        assert data['firmware'] == FIRMWARE, data
        self.screenshot('console-recovery')
        console = Console(self.vnc)
        console.type('firewall-cmd --remove-port=18083/tcp >/dev/null\n')
        console.close()
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
        config['config']['virtual_servers'] = [dict(name='boot-test', listen='10.0.2.15:18080', algorithm='round_robin', members=['10.0.2.2:18082'])]
        first.request('/api/v1/config', 'PUT', dict(config=config['config'], revision=config['revision']))
        wait(lambda: transfer(first), 30)
        def completed_statistics():
            counters = first.request('/api/v1/statistics')[0]['virtual_servers'][0]['traffic']
            return counters if counters['completed'] >= 1 else None
        previous_counters = wait(completed_statistics, 30)
        assert previous_counters['bytes_in'] > 0 and previous_counters['bytes_out'] > 0
        first.shutdown()
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
        first.shutdown()
        second = Guest('lb-fixture-b', 1)
        guests.append(second)
        second.start()
        second.setup()
        second_identity = second.inspect()
        assert first_identity['machine_id'] != second_identity['machine_id']
        assert first.certificate != second.certificate
        second.shutdown()
        (OUTPUT / 'report.json').write_text(json.dumps(dict(status='passed', firmware=FIRMWARE, tests=[
            'console setup', 'verified HTTPS login', 'real firewalld VIP TCP forwarding',
            'clean shutdown', 'reboot configuration/account/certificate persistence',
            'persisted traffic statistics', 'independent clone certificates and machine IDs',
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
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    main()
