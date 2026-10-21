#!/usr/bin/env python3
"""Maintainer-only online capture. Normal builds consume the resulting locked snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = 'docker.io/library/almalinux@sha256:ba31c3299856068f77bc10574cad51b0a4f6a3dafb882668656e1639bee63db6'
SOURCES = ['Cargo.lock', 'deploy/ha/vendor/openstack-requirements.txt', 'appliance/base-media.json',
           'packaging/container/Containerfile', 'appliance/tools/Containerfile',
           'appliance/tools/remaster-iso.py', 'appliance/tools/installer-branding.py',
           'tests/appliance/Containerfile.network-manager', 'packaging/toolchain.lock.json',
           'appliance/packer/appliance.pkr.hcl']
ROLES = {'runtime': BASE, 'builder': 'localhost/riverlb-builder:alma10.2',
         'tools': 'localhost/riverlb-image-tools:alma10.2',
         'network_tests': 'localhost/riverlb-network-tests:alma10.2'}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def capture_tools(tree):
    """Validate vendor signatures before retaining binaries and their provenance."""
    import tempfile
    import urllib.request
    import zipfile
    lock = json.loads((ROOT / 'packaging/toolchain.lock.json').read_text())
    tools = tree / 'tools'
    provenance = tree / 'toolchain-provenance'
    tools.mkdir(exist_ok=True)
    provenance.mkdir(exist_ok=True)
    key = provenance / 'hashicorp.asc'
    key.write_bytes(urllib.request.urlopen(lock['key_url'], timeout=60).read())
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        details = subprocess.check_output(['gpg', '--homedir', home, '--batch', '--with-colons', '--show-keys', str(key)], text=True)
        fingerprint = next(line.split(':')[9] for line in details.splitlines() if line.startswith('fpr:'))
        if fingerprint != lock['signing_fingerprint']:
            raise ValueError('HashiCorp signing key fingerprint mismatch')
        run(['gpg', '--homedir', home, '--batch', '--import', key])
        for name, tool in lock['tools'].items():
            checksum = provenance / (name + '.SHA256SUMS')
            signature = provenance / (name + '.SHA256SUMS.sig')
            checksum.write_bytes(urllib.request.urlopen(tool['checksums_url'], timeout=60).read())
            signature.write_bytes(urllib.request.urlopen(tool['checksums_url'] + '.sig', timeout=60).read())
            run(['gpg', '--homedir', home, '--batch', '--verify', signature, checksum])
            filename = tool['url'].rsplit('/', 1)[1]
            entries = dict((line.split()[1].lstrip('*'), line.split()[0]) for line in checksum.read_text().splitlines())
            if entries.get(filename) != tool['sha256']:
                raise ValueError('Signed checksum differs from toolchain lock: ' + name)
            archive = provenance / filename
            archive.write_bytes(urllib.request.urlopen(tool['url'], timeout=60).read())
            if digest(archive) != tool['sha256']:
                raise ValueError('Tool archive checksum mismatch: ' + name)
            with zipfile.ZipFile(archive) as bundle:
                binaries = [item for item in bundle.infolist() if '/' not in item.filename and
                            (item.filename == name or item.filename.startswith(name + '_v'))]
                if len(binaries) != 1:
                    raise ValueError('Unexpected tool archive layout: ' + name)
                (tools / name).write_bytes(bundle.read(binaries[0]))
                (tools / name).chmod(0o755)
    env = dict(os.environ, PACKER_PLUGIN_PATH=str(tree / 'packer-plugins'))
    run([tools / 'packer', 'plugins', 'install', '--path', tools / 'packer-plugin-qemu', 'github.com/hashicorp/qemu'], env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reseal', action='store_true', help='Revalidate and seal an existing unpublished capture')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', required=True, help='Retained HTTPS download URL for build-inputs.tar.gz')
    parser.add_argument('--snapshot-id', required=True)
    args = parser.parse_args()
    assert args.url.startswith('https://'), 'Retained snapshot must use HTTPS'
    output = args.output.resolve()
    if args.reseal:
        tree = output / 'snapshot'
        inventory = json.loads((tree / 'inventory.json').read_text())
        if inventory['snapshot_id'] != args.snapshot_id:
            raise ValueError('An unpublished reseal must retain its snapshot ID')
        previous = json.loads((ROOT / 'packaging/build-inputs.lock.json').read_text())
        images = previous['images']
    else:
        output.mkdir(parents=True, exist_ok=False)
        tree = output / 'snapshot'
        (tree / 'images').mkdir(parents=True)
        images = {}
        inventory = dict(schema=1, snapshot_id=args.snapshot_id, captured_utc=int(time.time()), images={},
                         base_media=json.loads((ROOT / 'appliance/base-media.json').read_text()))
        for role, reference in ROLES.items():
            image = json.loads(subprocess.check_output(['podman', 'image', 'inspect', reference]))[0]
            image_id = image['Id'].removeprefix('sha256:')
            archive = tree / 'images' / (role + '.oci.tar')
            run(['podman', 'save', '--format=oci-archive', '--output', archive, reference])
            package_format = '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{SOURCERPM}\t%{LICENSE}\n'
            packages = subprocess.check_output(['podman', 'run', '--rm', '--pull=never', '--network=none',
                '--entrypoint', 'rpm', 'sha256:' + image_id, '-qa', '--qf', package_format], text=True)
            images[role] = dict(id='sha256:' + image_id, archive=str(archive.relative_to(tree)))
            inventory['images'][role] = dict(reference=reference, image_id='sha256:' + image_id,
                                              packages=sorted(packages.splitlines()))
            print('Retained image:', role, image_id, flush=True)
        repository = ROOT / 'dist/rpm/ha-dependencies'
        assert repository.is_dir(), 'Capture a tested HA RPM closure with scripts/build-rpm.sh first'
        shutil.copytree(repository, tree / 'rpm-repository')
        key_path = tree / 'almalinux-10.asc'
        key_path.write_bytes(subprocess.check_output(['podman', 'run', '--rm', '--pull=never', '--network=none',
            '--entrypoint', 'cat', images['runtime']['id'], '/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10']))
        fingerprints = subprocess.check_output(['gpg', '--batch', '--with-colons', '--show-keys', str(key_path)], text=True)
        fingerprint = next(line.split(':')[9] for line in fingerprints.splitlines() if line.startswith('fpr:'))
        assert fingerprint == inventory['base_media']['checksum_signing_fingerprint'], fingerprint
        inventory['rpm_signing_key'] = dict(fingerprint=fingerprint, sha256=digest(key_path))
        (tree / 'wheels').mkdir()
        run(['podman', 'run', '--rm', '--pull=never', '--security-opt=no-new-privileges',
            '--entrypoint', 'python3', '-v', f'{ROOT / "deploy/ha/vendor/openstack-requirements.txt"}:/requirements.txt:ro,z',
            '-v', f'{tree / "wheels"}:/wheels:Z', images['builder']['id'], '-m', 'pip', 'download',
            '--require-hashes', '--only-binary=:all:', '--dest', '/wheels', '-r', '/requirements.txt'])
        with (output / 'cargo-vendor-config.txt').open('w') as config:
            run(['cargo', 'vendor', '--locked', '--versioned-dirs', tree / 'cargo-vendor'], cwd=ROOT, stdout=config)
        # Record each original vendor RPM NEVRA, source RPM, license and byte digest.
        rpm_metadata = subprocess.check_output(['podman', 'run', '--rm', '--pull=never', '--network=none',
            '--entrypoint', '/bin/bash', '-v', f'{tree}:/inputs:ro,Z', images['runtime']['id'], '-eu', '-c',
            "rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\t%{SOURCERPM}\\t%{LICENSE}\\n' /inputs/rpm-repository/*.rpm"], text=True)
        inventory['repository_packages'] = sorted(rpm_metadata.splitlines())
    capture_tools(tree)
    inventory['sources'] = {name: digest(ROOT / name) for name in SOURCES}
    inventory['files'] = {}
    for path in sorted(tree.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Snapshot symlinks are not supported: ' + str(path))
        if path.is_file() and path != tree / 'inventory.json':
            inventory['files'][str(path.relative_to(tree))] = dict(sha256=digest(path), size=path.stat().st_size)
    inventory_path = tree / 'inventory.json'
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + '\n')
    archive = output / 'build-inputs.tar.gz'
    # Canonical archive metadata; the retained byte digest is the trust anchor.
    epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=ROOT))
    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        info.mtime = epoch
        info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
        return info
    import gzip
    with archive.open('wb') as dest, gzip.GzipFile(fileobj=dest, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for path in sorted(tree.rglob('*')):
                tar.add(path, arcname=str(path.relative_to(tree)), recursive=False, filter=normalize)
    lock = dict(schema=1, snapshot_id=args.snapshot_id, url=args.url, sha256=digest(archive),
                size=archive.stat().st_size,
                unpacked_size=sum(p.stat().st_size for p in tree.rglob('*') if p.is_file()),
                inventory_sha256=digest(inventory_path), sources=inventory['sources'], images=images,
                rpm_signing_key=inventory['rpm_signing_key'])
    (ROOT / 'packaging/build-inputs.lock.json').write_text(json.dumps(lock, sort_keys=True, indent=2) + '\n')
    print('Snapshot:', archive, 'SHA256:', lock['sha256'], flush=True)


if __name__ == '__main__':
    main()
