"""Exercise installed RPMs inside a disposable container; never run on the host."""
import base64
import json
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import socket
import socketserver
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

if os.environ.get("RIVERLB_PACKAGE_TEST") != "disposable-container":
    raise SystemExit("Run through scripts/test-rpm.sh; this fixture changes installed appliance state")
assert os.geteuid() == 0, 'Run this installed-package fixture only as container root'

config = Path("/etc/riverlb/riverlb.toml")
assert config.stat().st_mode & 0o777 == 0o600
assert Path("/var/lib/riverlb").stat().st_mode & 0o777 == 0o700
assert "Conflicts=riverlb-ha.service" in Path("/usr/lib/systemd/system/riverlb.service").read_text()
assert "Conflicts=riverlb.service" in Path("/usr/lib/systemd/system/riverlb-ha.service.d/packaging.conf").read_text()
for helper in ("riverlb-authority", "riverlb-cluster", "riverlb-ha-deploy"):
    assert os.access(f"/usr/libexec/riverlb/{helper}", os.X_OK)
assert os.access("/usr/lib/ocf/resource.d/riverlb/traffic", os.X_OK)
for unit in ('riverlb-ha-deploy.service','riverlb-ha-activate.service','riverlb-ha-sshd.service'):
    assert Path('/usr/lib/systemd/system',unit).is_file()
assert Path('/usr/lib/tmpfiles.d/riverlb-ha.conf').is_file()
# Metadata must work without Internet access. Missing optional SDKs often leave
# an executable installed but unusable, so exercise imports separately as well.
fencing_agents = (
    'fence_vmware_rest', 'fence_vmware_soap', 'fence_pve', 'fence_virsh',
    'fence_virt', 'fence_xvm', 'fence_aws', 'fence_azure_arm', 'fence_gce',
    'fence_riverlb_openstack', 'fence_nutanix_ahv', 'fence_redfish', 'fence_ipmilan',
    'fence_idrac', 'fence_ilo5', 'fence_apc', 'fence_apc_snmp', 'fence_wti',
    'fence_riverlb_hyperv',
)
for agent in fencing_agents:
    metadata = subprocess.run(['/usr/sbin/' + agent, '-o', 'metadata'],
                              check=True, capture_output=True, text=True, timeout=15)
    document = ET.fromstring(metadata.stdout)
    assert document.tag == 'resource-agent', agent
    actions = {action.get('name') for action in document.findall('./actions/action')}
    assert {'off', 'status'} <= actions, (agent, actions)
    assert document.findall('./parameters/parameter'), agent
catalog = json.loads(subprocess.check_output(
    ['/usr/libexec/riverlb/riverlb-ha-deploy', '--fencing-catalog'], text=True, timeout=60))
expected_platforms = {'vmware', 'hyperv', 'proxmox', 'kvm', 'aws', 'azure', 'gcp',
                      'openstack', 'nutanix', 'ovirt', 'physical', 'pdu'}
assert expected_platforms <= {item['id'] for item in catalog['platforms'] if item['available']}
assert set(fencing_agents) <= {item['name'] for item in catalog['agents']}
for agent in catalog['agents']:
    assert 'off' in agent['actions'], agent['name']
    assert not {'skip_race_check', 'disable_timeout', 'network_fencing', 'action'} & {
        field['name'] for field in agent['parameters']}, agent['name']
if os.environ.get('RIVERLB_FENCING_CATALOG_OUTPUT'):
    Path(os.environ['RIVERLB_FENCING_CATALOG_OUTPUT']).write_text(json.dumps(catalog, indent=2) + '\n')
for profile, modules in {
    'common': ('pycurl',),
    'aws': ('boto3', 'botocore.exceptions'),
    'azure': ('azure.identity', 'azure.mgmt.compute', 'azure.mgmt.network'),
    'google': ('googleapiclient.discovery', 'google.auth', 'httplib2', 'socks'),
}.items():
    directories = [str(path) for path in Path('/usr/lib/fence-agents/support', profile).glob('lib*/python*/site-packages')]
    assert directories, profile
    fixture = 'import sys,importlib; sys.path[:0]=' + repr(directories) + '; '
    fixture += '[importlib.import_module(name) for name in ' + repr(modules) + ']'
    subprocess.run([sys.executable, '-c', fixture], check=True, capture_output=True, timeout=15)
subprocess.run([sys.executable, '-c',
    'import sys; sys.path.insert(0,"/usr/lib/riverlb/fencing/openstack"); '
    'from novaclient import client; from keystoneauth1 import loading,session; '
    'assert loading.get_plugin_loader("password"); '
    'assert client.Client("2",session=session.Session()).servers'],
    check=True, capture_output=True, timeout=15)
assert Path('/usr/share/riverlb/ha/hyperv/riverlb-hyperv-fence.ps1').is_file()
assert Path('/usr/share/doc/riverlb-ha/fence-agents-source/fence_pve.py.in').is_file()
# Exercise the exact stdin-only CIB command used by the GUI, entirely offline.
with tempfile.TemporaryDirectory() as cib_fixture:
    cib_file=Path(cib_fixture)/'cib.xml'
    cib_file.write_bytes(subprocess.check_output(['cibadmin','--empty']))
    cib_environment={**os.environ,'CIB_file':str(cib_file)}
    primitive='<primitive id="fixture-fence" class="stonith" type="fence_ipmilan"><instance_attributes id="fixture-attributes"><nvpair id="fixture-hosts" name="pcmk_host_list" value="fixture-a"/></instance_attributes></primitive>'
    subprocess.run(['cibadmin','--create','--scope','resources','--xml-pipe'],input=primitive,text=True,check=True,env=cib_environment)
    assert 'fixture-fence' in subprocess.check_output(['cibadmin','--query'],text=True,env=cib_environment)
assert not Path("/etc/riverlb/ha.json").exists()
assert not Path("/var/lib/riverlb/riverlb.db").exists()
assert Path('/usr/share/selinux/packages/riverlb-sandbox.cil').is_file()
assert 'riverlb-sandbox' in subprocess.check_output(['semodule', '-l'], text=True)
assert 'ExecCondition=/usr/sbin/riverlb-setup --check-ready' in Path('/usr/lib/systemd/system/riverlb.service.d/firstboot-gate.conf').read_text()
assert subprocess.run(['riverlb-setup', '--check-ready']).returncode == 1
assert not Path('/var/lib/riverlb/riverlb.db').exists()
assert not Path("/etc/systemd/system/multi-user.target.wants/riverlb.service").exists()
assert not Path("/etc/systemd/system/multi-user.target.wants/riverlb-ha.service").exists()

subprocess.run(["riverlb", "admin", "--database", "/var/lib/riverlb/riverlb.db"],
               input="Package-test-password-123\n", text=True, check=True)
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            data = self.request.recv(256)
            if data:
                self.request.sendall(data)
        except (TimeoutError, ConnectionError):
            pass

backend = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
backend.daemon_threads = True
thread = threading.Thread(target=backend.serve_forever, daemon=True)
thread.start()
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    vip_port = reservation.getsockname()[1]
process = subprocess.Popen(["riverlb", "serve", "--config", str(config),
                            "--database", "/var/lib/riverlb/riverlb.db", "--external-network"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(process.stdout.read())
        try:
            with urllib.request.urlopen("http://127.0.0.1:18090/login") as response:
                assert response.status == 200
            break
        except urllib.error.URLError:
            time.sleep(0.1)
    else:
        raise AssertionError("Packaged daemon did not become ready")
    request = urllib.request.Request("http://127.0.0.1:18090/api/v1/auth/login",
                                     data=json.dumps(dict(username="admin", password="Package-test-password-123")).encode(),
                                     headers={"Content-Type": "application/json", "X-RiverLB-Request": "configure"}, method="POST")
    with urllib.request.urlopen(request) as response:
        assert response.status == 200
        cookie = response.headers.get("Set-Cookie")
        assert cookie

    def api(route, body=None, expected=200, authenticated=True):
        headers = {"Content-Type": "application/json", "Origin": "http://127.0.0.1:18090",
                   "X-RiverLB-Request": "configure"}
        if authenticated:
            headers['Cookie'] = cookie.split(';', 1)[0]
        request = urllib.request.Request('http://127.0.0.1:18090/api/v1/' + route,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == expected, (route, response.status, expected)
            return json.load(response)

    def local_status(body=None):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect('/run/riverlb/operations.sock')
            connection.sendall(json.dumps(body or dict(action='status')).encode() + b'\n')
            response = bytearray()
            while b'\n' not in response:
                chunk = connection.recv(16384)
                assert chunk and len(response) + len(chunk) <= 2 * 1024 * 1024
                response.extend(chunk)
            return json.loads(response)
    # Add the first virtual server through authenticated management after an empty boot.
    with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18090/api/v1/config",
                                                       headers={"Cookie": cookie.split(";", 1)[0]})) as response:
        saved = json.load(response)
    traffic = saved["config"]
    traffic["virtual_servers"] = [dict(name="package-smoke", listen=f"127.0.0.1:{vip_port}",
                                      algorithm="round_robin", members=[f"127.0.0.1:{backend.server_address[1]}"])]
    request = urllib.request.Request("http://127.0.0.1:18090/api/v1/config",
                                     data=json.dumps(dict(config=traffic, revision=saved["revision"])).encode(),
                                     headers={"Content-Type": "application/json", "Cookie": cookie.split(";", 1)[0],
                                              "Origin": "http://127.0.0.1:18090", "X-RiverLB-Request": "configure"}, method="PUT")
    with urllib.request.urlopen(request) as response:
        assert response.status == 200
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", vip_port), timeout=2) as client:
                client.sendall(b"packaged-traffic")
                assert client.recv(256) == b"packaged-traffic"
            break
        except (OSError, AssertionError):
            time.sleep(0.1)
    else:
        raise AssertionError("Packaged virtual server did not forward TCP traffic")

    # Test the installed fixed socket with real peer credentials. Its directory
    # is created for a direct installed CLI start without a systemd manager.
    runtime = Path('/run/riverlb')
    local = runtime / 'operations.sock'
    for path, expected_mode in ((runtime, 0o700), (local, 0o600)):
        metadata = path.lstat()
        assert metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == expected_mode
    assert stat.S_ISSOCK(local.lstat().st_mode)
    snapshot = local_status()
    assert set(snapshot) == {'version', 'revision', 'management', 'management_secure',
                             'confirmation_pending', 'ha_role', 'virtual_servers'}
    current = api('config')
    assert snapshot['revision'] == current['revision']
    assert snapshot['management'] == '127.0.0.1:18090'
    assert snapshot['management_secure'] is False
    assert snapshot['confirmation_pending'] is False
    assert snapshot['ha_role'] == 'standalone'
    assert len(snapshot['virtual_servers']) == 1
    virtual = snapshot['virtual_servers'][0]
    assert set(virtual) == {'name', 'enabled', 'state', 'healthy_members'}
    assert virtual['name'] == 'package-smoke' and virtual['enabled'] is True
    assert 'error' in local_status(dict(action='configure'))
    assert 'error' in local_status(dict(action='status', include_keys=True))

    # A child drops to an unprivileged fixed UID/GID in this disposable container
    # and must fail before obtaining any local management status.
    denied = subprocess.run([sys.executable, '-c',
        "import socket; s=socket.socket(socket.AF_UNIX); "
        "\ntry: s.connect('/run/riverlb/operations.sock')"
        "\nexcept PermissionError: raise SystemExit(0)"
        "\nraise SystemExit(1)"], user=65534, group=65534, extra_groups=[], capture_output=True, timeout=5)
    assert denied.returncode == 0, 'Non-root local IPC access must be refused'

    # Sign only the actual installed package executable. Fixture trust and its
    # private key exist solely in this container and are never release inputs.
    api('updates/status', expected=401, authenticated=False)
    assert api('updates/status')['trust_configured'] is True
    packaged_trust = Path('/etc/riverlb-updater/update-trust.json')
    packaged_bytes = packaged_trust.read_bytes()
    assert packaged_trust.stat().st_uid == 0
    assert stat.S_IMODE(packaged_trust.stat().st_mode) == 0o644
    publisher = json.loads(packaged_bytes)
    assert publisher['format'] == 1 and len(publisher['keys']) == 1
    assert publisher['keys'][0]['id'] == hashlib.sha256(base64.b64decode(publisher['keys'][0]['public_key'])).hexdigest()
    with tempfile.TemporaryDirectory(prefix='riverlb-package-signing-') as directory:
        fixture = Path(directory)
        key = fixture / 'fixture-private.pem'
        bundle = fixture / 'fixture.rlbupdate'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key],
                       check=True, capture_output=True)
        key.chmod(0o600)
        version = subprocess.check_output(['riverlb', '--version'], text=True).strip().split()[-1]
        subprocess.run([sys.executable, '/tests/sign-update.py', '--binary', '/usr/lib/riverlb/base/riverlb',
                        '--key', key, '--version', version, '--sequence', '41', '--output', bundle],
                       check=True, capture_output=True)
        trust = Path('/etc/riverlb-updater/update-trust.json')
        assert trust.parent.is_dir() and trust.read_bytes() == packaged_bytes
        shutil.copyfile(bundle.with_suffix('.trust.json'), trust)
        trust.chmod(0o644)
        assert trust.stat().st_uid == 0
        try:
            started = time.monotonic()
            result = subprocess.run(['riverlb', 'update-verify', '--bundle', bundle, '--sequence', '40'],
                                    check=True, capture_output=True, text=True, timeout=30)
            assert json.loads(result.stdout)['sequence'] == 41
            elapsed = time.monotonic() - started
            print(f'Installed full-payload signed verifier: {bundle.stat().st_size} bytes in {elapsed:.2f}s (30s deadline)')
            replay = subprocess.run(['riverlb', 'update-verify', '--bundle', bundle, '--sequence', '41'],
                                    capture_output=True, text=True, timeout=30)
            assert replay.returncode != 0, 'The installed verifier must reject a consumed sequence'
            status = api('updates/status')
            assert status['trust_configured'] is True and status['staged'] is False
            assert status['installed_version'] == version and status['activation_supported'] is True
            signed = json.loads(bundle.read_text())
            staged = api('updates/stage', signed)
            assert staged['manifest']['sequence'] == 41 and staged['manifest']['version'] == version
            saved_bundle = Path('/var/lib/riverlb/riverlb.update-bundle.json')
            metadata = saved_bundle.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
            assert stat.S_IMODE(metadata.st_mode) == 0o600
            original = hashlib.sha256(saved_bundle.read_bytes()).digest()
            status = api('updates/status')
            assert status['staged'] is True and status['state']['candidate']['sequence'] == 41
            assert status['state']['highest_sequence'] == 0, 'Staging alone must not consume the activation sequence'
            for field in ('signature', 'payload'):
                malformed = dict(signed)
                malformed[field] = ('A' if signed[field][0] != 'A' else 'B') + signed[field][1:]
                rejection = api('updates/stage', malformed, expected=409)
                assert 'error' in rejection
                assert hashlib.sha256(saved_bundle.read_bytes()).digest() == original
                assert api('updates/status')['state']['candidate']['sequence'] == 41
            malformed = dict(signed, manifest=signed['manifest'] + ' ')
            api('updates/stage', malformed, expected=409)
            assert hashlib.sha256(saved_bundle.read_bytes()).digest() == original
            assert not Path('/var/lib/riverlb-updater/recovery.json').exists()
            selector = Path('/usr/lib/riverlb/current')
            assert not selector.exists() and not selector.is_symlink(), 'This package test never activates a bundle'
        finally:
            trust.write_bytes(packaged_bytes)
            trust.chmod(0o644)
finally:
    process.terminate()
    try:
        output, _ = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        raise AssertionError("Packaged daemon failed to stop cleanly")
    backend.shutdown()
    backend.server_close()
    assert process.returncode == 0, output
assert Path("/var/lib/riverlb/riverlb.db").exists()
assert not Path('/run/riverlb/operations.sock').exists(), 'Installed shutdown must remove its own readiness socket'
print("Installed RPM login, TCP forwarding, root-only local IPC, signed update CLI/API staging, tamper/replay rejection and clean shutdown passed")
