#!/usr/bin/env python3
"""EVE-root-only development RPM deployment; never use on production appliances."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time

ROOT = Path('/root/riverlb-eve-lab')
NODES = {'a': '10.77.0.11', 'b': '10.77.0.12'}


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=180, **kwargs).stdout


def ssh(node, *args):
    return run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={ROOT}/guest-known-hosts', '-i', str(ROOT / 'id_ed25519'),
                'root@' + NODES[node], shlex.join(args)])


def copy(node, source, destination):
    run(['scp', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
         '-o', f'UserKnownHostsFile={ROOT}/guest-known-hosts', '-i', str(ROOT / 'id_ed25519'),
         str(source), 'root@' + NODES[node] + ':' + destination])


def unpack(bundle, digest, destination):
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != digest:
        raise ValueError('Transferred bundle checksum mismatch')
    with tarfile.open(bundle) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise ValueError('Duplicate archive member')
        for member in members:
            if (not member.isfile() or Path(member.name).name != member.name or
                    member.name not in {'deployment.json', 'build-manifest.json'} and
                    not re.fullmatch(r'riverlb[-a-zA-Z0-9_.]*\.rpm', member.name)):
                raise ValueError('Unexpected archive member')
            if member.size > 256 * 1024 * 1024:
                raise ValueError('Oversized archive member')
        archive.extractall(destination, filter='data')
    receipt = json.loads((destination / 'deployment.json').read_text())
    manifest = json.loads((destination / 'build-manifest.json').read_text())
    if (receipt['repository'] != 'codyasmith8118/RiverLB' or receipt['branch'] != 'release-2.0' or
            not re.fullmatch('[0-9a-f]{40}', receipt['commit']) or
            manifest['commit'] != receipt['commit'] or manifest['dirty']):
        raise ValueError('Unexpected development source')
    required = {'ci.yml', 'security.yml', 'rpm.yml'}
    if not required.issubset({Path(r['path']).name for r in receipt['workflows']}):
        raise ValueError('Missing CI evidence')
    if any(r['conclusion'] != 'success' for r in receipt['workflows']):
        raise ValueError('Non-passing CI evidence')
    actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.glob('*.rpm')}
    if actual != receipt['packages']:
        raise ValueError('RPM bundle does not match its evidence')
    return receipt


def health(node):
    code = '''import json,ssl,urllib.request,time
from pathlib import Path
p=Path('/etc/riverlb');d=json.loads(Path('/var/lib/riverlb/.firstboot.complete').read_text())
c=ssl.create_default_context(cafile=str(p/'device.crt'))
for _ in range(45):
 try:
  with urllib.request.urlopen('https://'+d['address']+':18090/healthz',context=c,timeout=2) as r:
   if r.status==200:break
 except OSError:pass
 time.sleep(1)
else:raise SystemExit('HTTPS did not become healthy')
'''
    ssh(node, 'python3', '-c', code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not ROOT.is_dir():
        parser.error('Run only as root on the configured EVE development host')
    os.umask(0o077)
    with open(ROOT / '.development-deploy.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deployments = ROOT / 'deployments'
        deployments.mkdir(exist_ok=True, mode=0o700)
        transaction = deployments / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        transaction.mkdir(mode=0o700)
        receipt = unpack(args.bundle, args.sha256, transaction)
        current_file = ROOT / 'development-current.json'
        if not current_file.exists():
            raise RuntimeError('Missing known previous RPM set; initialize baseline before deployment')
        previous = json.loads(current_file.read_text())
        old_packages = [Path(p) for p in previous['packages']]
        if (not old_packages or not all(p.is_file() for p in old_packages) or
                any(hashlib.sha256(p.read_bytes()).hexdigest() != previous.get('package_sha256', {}).get(str(p))
                    for p in old_packages)):
            raise RuntimeError('Rollback RPMs unavailable')
        # This lab has standalone core + appliance packages. Refuse HA or signed-update
        # selections rather than interfering with those separate lifecycle mechanisms.
        for node in NODES:
            if ssh(node, 'hostname').strip() != 'riverlb-' + node:
                raise RuntimeError('Unexpected appliance at private management address')
            ssh(node, 'systemctl', 'is-active', 'riverlb')
            ssh(node, 'test', '!', '-e', '/usr/lib/riverlb/current')
            ssh(node, 'test', '!', '-L', '/usr/lib/riverlb/current')
            if 'riverlb-ha-' in ssh(node, 'rpm', '-qa', '--qf', '%{NAME}-%{VERSION}\n'):
                raise RuntimeError('HA requires a separate reviewed deployment procedure')
            health(node)
            if ssh(node, 'sha256sum', '/usr/lib/riverlb/base/riverlb').split()[0] != previous['nodes'][node]['binary_sha256']:
                raise RuntimeError('Installed binary drifted from the recorded rollback baseline')
        packages = sorted(p for p in transaction.glob('*.rpm') if not p.name.startswith('riverlb-ha-'))
        if len(packages) != 2:
            raise RuntimeError('Expected standalone core and appliance RPMs')
        changed = []
        stopped = []
        guest = '/root/riverlb-development/' + transaction.name
        try:
            for node in NODES:
                ssh(node, 'mkdir', '-p', '-m', '700', guest + '/new', guest + '/previous')
                for p in packages:
                    copy(node, p, guest + '/new/' + p.name)
                for p in old_packages:
                    copy(node, p, guest + '/previous/' + p.name)
                stopped.append(node)
                ssh(node, 'systemctl', 'stop', 'riverlb')
                # Turso/SQLite files are copied only after the daemon has stopped.
                state = json.loads(ssh(node, 'python3', '-c',
                                       "import json,pathlib;print(json.dumps([p for p in ['etc/riverlb','var/lib/riverlb','var/lib/riverlb-updater'] if pathlib.Path('/'+p).exists()]))"))
                ssh(node, 'tar', '--xattrs', '--selinux', '-C', '/', '-czf', guest + '/state.tgz', *state)
                changed.append(node)
                ssh(node, 'rpm', '-Uvh', '--replacepkgs', '--oldpackage',
                    *[guest + '/new/' + p.name for p in packages])
                ssh(node, 'restorecon', '-RF', '/etc/riverlb', '/var/lib/riverlb')
                ssh(node, 'systemctl', 'daemon-reload')
                ssh(node, 'systemctl', 'start', 'riverlb')
                health(node)
                installed = json.loads(ssh(node, 'cat', '/usr/share/doc/riverlb/build-manifest.json'))
                if installed['commit'] != receipt['commit']:
                    raise RuntimeError('Installed source manifest mismatch')
                # RPM digest validation covers the launcher-selected baseline executable.
                sha = ssh(node, 'sha256sum', '/usr/lib/riverlb/base/riverlb').split()[0]
                receipt.setdefault('nodes', {})[node] = {'binary_sha256': sha, 'backup': guest + '/state.tgz'}
            if len({n['binary_sha256'] for n in receipt['nodes'].values()}) != 1:
                raise RuntimeError('Appliances have different executables')
            for script in ['check-management.py', 'check-support.py', 'validate-lab.py', 'check-live-flows.py']:
                output = run(['python3', str(ROOT / script)])
                (transaction / (script + '.log')).write_text(output)
            support = json.loads((ROOT / 'support-check.json').read_text())
            flows = json.loads((ROOT / 'live-flow-check.json').read_text())
            validation = json.loads((ROOT / 'validation.json').read_text())
            if (not all(v['code'] == 0 for v in support.values()) or
                    not all(v['result']['rows'] for v in flows.values()) or
                    not all(v['passed'] for k, v in validation['checks'].items() if k.startswith('load_'))):
                raise RuntimeError('Lab validation did not pass')
            receipt['status'] = 'passed'
            receipt['package_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in packages}
            receipt['packages'] = [str(p) for p in packages]
            receipt['previous'] = previous
            (transaction / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
            temporary = current_file.with_suffix('.new')
            temporary.write_text(json.dumps(receipt, indent=2) + '\n')
            temporary.replace(current_file)
            print(json.dumps({'status': 'passed', 'commit': receipt['commit'], 'receipt': str(transaction / 'result.json')}))
        except Exception as error:
            failures = []
            for node in stopped:
                if node not in changed:
                    try:
                        ssh(node, 'systemctl', 'start', 'riverlb')
                    except Exception:
                        failures.append(node)
            for node in reversed(changed):
                try:
                    ssh(node, 'systemctl', 'stop', 'riverlb')
                    ssh(node, 'tar', '-tzf', guest + '/state.tgz')
                    ssh(node, 'rpm', '-Uvh', '--oldpackage', '--replacepkgs',
                        *[guest + '/previous/' + p.name for p in old_packages])
                    # Remove newly created DB sidecars before restoring the stopped state.
                    ssh(node, 'rm', '-rf', '/etc/riverlb', '/var/lib/riverlb', '/var/lib/riverlb-updater')
                    ssh(node, 'tar', '--xattrs', '--selinux', '-C', '/', '-xzf', guest + '/state.tgz')
                    ssh(node, 'restorecon', '-RF', '/etc/riverlb', '/var/lib/riverlb')
                    ssh(node, 'systemctl', 'daemon-reload')
                    ssh(node, 'systemctl', 'start', 'riverlb')
                    health(node)
                except Exception:
                    failures.append(node)
            (transaction / 'failure.json').write_text(json.dumps({'status': 'failed', 'error': str(error),
                                                                 'rollback_failed_nodes': failures}, indent=2))
            raise RuntimeError('Deployment failed; rollback failed nodes: ' + ','.join(failures)) from error


if __name__ == '__main__':
    main()
