#!/usr/bin/env python3
"""Fetch and verify retained build inputs. Never resolve current OS repositories."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 2 * 1024 ** 3
MAX_UNPACKED = 16 * 1024 ** 3


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '\\' in name
            or any(ord(c) < 32 for c in name) or str(path) != name or name == '.'):
        raise ValueError('Unsafe snapshot path: ' + repr(name))
    return path


def read_lock(path):
    lock = json.loads(path.read_text())
    if lock['schema'] != 1 or not 0 < lock['size'] <= MAX_ARCHIVE or not 0 < lock['unpacked_size'] <= MAX_UNPACKED:
        raise ValueError('Unsupported snapshot schema or size')
    for key in ('sha256', 'inventory_sha256'):
        if len(lock[key]) != 64 or any(c not in '0123456789abcdef' for c in lock[key]):
            raise ValueError('Invalid snapshot digest')
    url = urllib.parse.urlsplit(lock['url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('Snapshot URL must be HTTPS without embedded credentials')
    return lock


def verify_sources(root, lock):
    for name, expected in lock['sources'].items():
        relative(name)
        if digest(root / name) != expected:
            raise ValueError('Build inputs changed; intentionally refresh the snapshot: ' + name)


def verify_tree(root, lock):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Snapshot must be a regular directory')
    if (root / 'inventory.json').is_symlink() or not (root / 'inventory.json').is_file():
        raise ValueError('Snapshot inventory must be a regular file')
    if digest(root / 'inventory.json') != lock['inventory_sha256']:
        raise ValueError('Snapshot inventory checksum mismatch')
    inventory = json.loads((root / 'inventory.json').read_text())
    if inventory['schema'] != 1 or inventory['snapshot_id'] != lock['snapshot_id'] or inventory['sources'] != lock['sources']:
        raise ValueError('Snapshot inventory identity mismatch')
    expected_files = set(inventory['files']) | {'inventory.json'}
    actual_files = set()
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Snapshot contains a link or special file')
        if path.is_file():
            actual_files.add(str(path.relative_to(root)))
    if actual_files != expected_files:
        raise ValueError('Snapshot contains missing or unexpected files')
    for name, entry in inventory['files'].items():
        relative(name)
        path = root / name
        if path.stat().st_size != entry['size'] or digest(path) != entry['sha256']:
            raise ValueError('Snapshot file checksum mismatch: ' + name)
    if digest(root / 'almalinux-10.asc') != lock['rpm_signing_key']['sha256']:
        raise ValueError('OS signing key mismatch')
    return inventory


def extract(archive, target, lock):
    seen = set()
    size = 0
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            relative(member.name)
            if member.name in seen or not (member.isdir() or member.isfile()):
                raise ValueError('Snapshot contains duplicate paths, links or special files')
            seen.add(member.name)
            path = target / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                size += member.size
                if member.size < 0 or size > lock['unpacked_size']:
                    raise ValueError('Snapshot expands beyond its locked size')
                path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, path.open('xb') as dest:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    if size != lock['unpacked_size']:
        raise ValueError('Incomplete snapshot archive')
    verify_tree(target, lock)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Refusing a non-HTTPS snapshot redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(lock, archive):
    opener = urllib.request.build_opener(HTTPSRedirect())
    partial = archive.with_suffix('.partial')
    try:
        count = 0
        with opener.open(lock['url'], timeout=60) as response, partial.open('xb') as output:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > lock['size']:
                    raise ValueError('Snapshot download exceeds locked size')
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if count != lock['size'] or digest(partial) != lock['sha256']:
            raise ValueError('Snapshot download checksum/size mismatch')
        os.replace(partial, archive)
    finally:
        partial.unlink(missing_ok=True)


def prepare(lock, cache, project=ROOT):
    verify_sources(project, lock)
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / (lock['sha256'] + '.lock')).open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        archive = cache / (lock['sha256'] + '.tar.gz')
        if not archive.exists():
            download(lock, archive)
        if archive.is_symlink() or archive.stat().st_size != lock['size'] or digest(archive) != lock['sha256']:
            raise ValueError('Cached archive checksum/size mismatch; no fallback is permitted')
        target = cache / lock['sha256']
        if target.exists() or target.is_symlink():
            verify_tree(target, lock)
        else:
            with tempfile.TemporaryDirectory(prefix='.extract-', dir=cache) as stage:
                tree = Path(stage) / 'snapshot'
                tree.mkdir()
                extract(archive, tree, lock)
                os.replace(tree, target)
        return target


def load_image(root, lock, role):
    image = lock['images'][role]
    relative(image['archive'])
    image_id = image['id']
    if not image_id.startswith('sha256:') or len(image_id) != 71:
        raise ValueError('Invalid locked container identity')
    exists = subprocess.run(['podman', 'image', 'exists', image_id], check=False)
    if exists.returncode:
        subprocess.run(['podman', 'load', '--input', str(root / image['archive'])], check=True,
                       stdout=subprocess.DEVNULL)
    actual = json.loads(subprocess.check_output(['podman', 'image', 'inspect', image_id]))[0]['Id']
    if actual.removeprefix('sha256:') != image_id.removeprefix('sha256:'):
        raise ValueError('Loaded container identity mismatch')
    return image_id


def verify_signatures(root, runtime):
    script = '''set -euo pipefail
export LC_ALL=C
mkdir /tmp/riverlb-rpmkeys
rpm --dbpath /tmp/riverlb-rpmkeys --initdb
rpm --dbpath /tmp/riverlb-rpmkeys --import /inputs/almalinux-10.asc
rpmkeys --dbpath /tmp/riverlb-rpmkeys --checksig /inputs/rpm-repository/*.rpm
'''
    result = subprocess.run(['podman', 'run', '--rm', '--pull=never', '--network=none',
        '--security-opt=no-new-privileges', '--entrypoint', '/bin/bash',
        '-v', f'{root}:/inputs:ro,Z', runtime, '-c', script], check=True, text=True, capture_output=True)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != len(list((root / 'rpm-repository').glob('*.rpm'))) or not lines or not all(line.endswith('digests signatures OK') for line in lines):
        raise ValueError('Repository RPMs must have valid signatures from the pinned OS key')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'image', 'verify'])
    parser.add_argument('role', nargs='?', choices=['builder', 'runtime', 'tools', 'network_tests'])
    parser.add_argument('--lock', type=Path, default=ROOT / 'packaging/build-inputs.lock.json')
    args = parser.parse_args()
    lock = read_lock(args.lock)
    cache = Path(os.environ.get('RIVERLB_BUILD_INPUTS_CACHE', str(ROOT / 'dist/build-inputs'))).resolve()
    root = prepare(lock, cache)
    runtime = load_image(root, lock, 'runtime')
    verify_signatures(root, runtime)
    image = load_image(root, lock, args.role) if args.role else None
    if args.command == 'image':
        if image is None:
            parser.error('image requires a role')
        print(image)
    elif args.command == 'prepare':
        print(root)
    else:
        print('Verified retained snapshot, file hashes, image identity and vendor RPM signatures')


if __name__ == '__main__':
    main()
