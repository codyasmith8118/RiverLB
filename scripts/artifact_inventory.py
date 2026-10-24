"""Inspect original RPM/ISO bytes without installing packages or mounting disks."""
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
from software_inventory import component, relative, sha256
from package_inventory import validate_inventory


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        block = stream.read(size - len(data))
        if not block:
            raise ValueError('Truncated RPM payload')
        data.extend(block)
    return bytes(data)


def rpm_payload(path, retain=None):
    """Read newc CPIO as a stream; never create paths supplied by an archive."""
    process = subprocess.Popen(['rpm2cpio', str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    files, kept = {}, {}
    hardlinks = {}
    spool = tempfile.TemporaryFile() if retain else None
    try:
        total = 0
        while True:
            header = exact(process.stdout, 110)
            if header[:6] not in (b'070701', b'070702'):
                raise ValueError('Unsupported RPM payload')
            fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
            mode, size, name_size = fields[1], fields[6], fields[11]
            if not 0 < name_size < 16384 or size > 2 * 1024 ** 3:
                raise ValueError('Invalid RPM payload member size')
            raw_name = exact(process.stdout, name_size)
            if raw_name[-1:] != b'\0':
                raise ValueError('Invalid RPM payload name')
            name = raw_name[:-1].decode().removeprefix('./').lstrip('/')
            exact(process.stdout, -(110 + name_size) % 4)
            if name == 'TRAILER!!!':
                break
            # filesystem.rpm legitimately owns the archive root ("./"). It is
            # metadata, not a payload file; never accept root-named file contents.
            if name in ('', '.'):
                if stat.S_ISDIR(mode) and size == 0:
                    continue
                raise ValueError('Invalid RPM root directory entry')
            # systemd unit names contain literal POSIX backslashes such as
            # system-systemd\x2dcryptsetup.slice. Preserve those exact bytes in
            # the inventory; validate only the documented hex-escape spelling.
            # All other backslashes and traversal/noncanonical paths still fail.
            relative(re.sub(r'\\x[0-9a-fA-F]{2}', '_', name))
            total += size
            if total > 8 * 1024 ** 3:
                raise ValueError('Oversized RPM payload')
            h = hashlib.sha256()
            keep = bool(retain and retain(name))
            linked = stat.S_ISREG(mode) and fields[4] > 1
            offset = spool.tell() if spool and linked else None
            data = bytearray()
            remaining = size
            while remaining:
                block = exact(process.stdout, min(remaining, 1024 * 1024))
                h.update(block)
                if keep:
                    data.extend(block)
                if spool and linked:
                    spool.write(block)
                remaining -= len(block)
            exact(process.stdout, -size % 4)
            if stat.S_ISDIR(mode):
                continue
            if name in files:
                raise ValueError('Duplicate RPM payload path')
            files[name] = {'sha256': h.hexdigest(), 'size': size, 'mode': format(stat.S_IMODE(mode), '04o'),
                           'type': 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else 'special'}
            if linked:
                group = hardlinks.setdefault((fields[7], fields[8], fields[0]), {'paths': [], 'content': None, 'kept': []})
                group['paths'].append(name)
                if keep:
                    group['kept'].append(name)
                if size:
                    if group['content'] and group['content'][:2] != (size, h.hexdigest()):
                        raise ValueError('Conflicting RPM hardlink payloads')
                    group['content'] = (size, h.hexdigest(), offset)
            if keep:
                if not stat.S_ISREG(mode):
                    raise ValueError('Retained payload member must be a regular file')
                kept[name] = bytes(data)
        if len(process.stdout.read(4096)) == 4096:
            raise ValueError('Unexpected data after CPIO trailer')
        if process.wait(timeout=30):
            raise ValueError('RPM payload decoding failed')
        # newc stores hardlink contents on one member, often the last alias.
        # Resolve every pathname to that content instead of hashing empty aliases.
        for group in hardlinks.values():
            size, digest, offset = group['content'] or (0, hashlib.sha256(b'').hexdigest(), None)
            for name in group['paths']:
                files[name].update(size=size, sha256=digest)
            if group['kept']:
                data = b''
                if size:
                    spool.seek(offset)
                    data = exact(spool, size)
                for name in group['kept']:
                    kept[name] = data
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)
        if spool:
            spool.close()
    return files, kept


def rpm_metadata(path):
    fields = ('name', 'epochnum', 'version', 'release', 'arch', 'license', 'sourcerpm', 'url')
    values = subprocess.check_output(['rpm', '-qp', '--qf', '\t'.join('%{' + f.upper() + '}' for f in fields), str(path)],
                                     text=True, stderr=subprocess.DEVNULL).split('\t')
    if len(values) != len(fields) or any('\r' in v or '\n' in v for v in values):
        raise ValueError('Invalid RPM metadata')
    result = dict(zip(fields, values))
    result['nevra'] = '{name}-{version}-{release}.{arch}'.format(**result)
    result['sha256'] = sha256(path)
    return result


def os_catalog(root):
    folder = Path(root) / 'packaging/third-party'
    catalog = json.loads((folder / 'runtime-packages.lock.json').read_text())
    base = json.loads((Path(root) / 'appliance/base-media.json').read_text())
    inputs = json.loads((Path(root) / 'packaging/build-inputs.lock.json').read_text())
    if catalog['schema'] != 1 or catalog['base_iso_sha256'] != base['sha256'] or catalog['rpm_key_sha256'] != inputs['rpm_signing_key']['sha256']:
        raise ValueError('OS metadata origin mismatch')
    archive = folder / 'runtime-notices.tar.gz'
    if sha256(archive) != catalog['notices_sha256']:
        raise ValueError('OS notice archive changed')
    packages = {}
    expected = {}
    for entry in catalog['packages']:
        if entry['nevra'] in packages or not entry['source_url'].startswith('https://') or not entry['license']:
            raise ValueError('Invalid OS package/source catalog')
        packages[entry['nevra']] = entry
        for notice in entry['notices']:
            relative(notice['path'])
            expected[notice['path']] = notice['sha256']
    notices = {}
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if not member.isfile() or member.name in notices or member.name not in expected or member.size > 16 * 1024 * 1024:
                raise ValueError('Unexpected OS notice archive member')
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError('OS notice archive exceeds size limit')
            data = source.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != expected[member.name]:
                raise ValueError('OS notice digest mismatch')
            notices[member.name] = data
    if set(notices) != set(expected):
        raise ValueError('OS notice archive coverage mismatch')
    return catalog, packages, notices


def add_os_package(inv, entry, notices, occurrences):
    ref = inv.add(component('rpm/almalinux', entry['name'], entry['version'] + '-' + entry['release'], entry['sha256'],
                            entry['license'], entry['source_url'],
                            qualifier='?arch=' + entry['arch'] + '&epoch=' + entry['epochnum'],
                            scope='required' if occurrences else 'excluded',
                            properties={'riverlb:source-rpm': entry['sourcerpm'],
                                        'riverlb:occurrences': ','.join(sorted(occurrences)),
                                        'riverlb:hash-scope': 'signed upstream RPM archive'}))
    for notice in entry['notices']:
        inv.notice(ref, 'os/' + notice['path'], notices[notice['path']], entry['source_url'])
    return ref


def inspect_iso(path, destination):
    """Extract only public candidate media into an owned scratch directory."""
    subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(path), '-extract', '/', str(destination)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {}
    for item in sorted(destination.rglob('*')):
        if item.is_symlink():
            result[str(item.relative_to(destination))] = {'symlink': str(item.readlink())}
        elif item.is_file():
            result[str(item.relative_to(destination))] = {'sha256': sha256(item), 'size': item.stat().st_size}
    if not result or 'images/install.img' not in result or 'riverlb-packages.tar' not in result:
        raise ValueError('ISO payload incomplete')
    return result


def runtime_manifest(install_image, catalog):
    result = subprocess.check_output(['unsquashfs', '-cat', str(install_image), 'root/lorax-packages.log'], stderr=subprocess.DEVNULL)
    if hashlib.sha256(result).hexdigest() != catalog['runtime_manifest_sha256']:
        raise ValueError('Installer runtime package manifest changed')
    packages = result.decode().splitlines()
    expected = {p['nevra'] for p in catalog['packages'] if p['installer_runtime']}
    if set(packages) != expected or len(packages) != len(expected):
        raise ValueError('Installer runtime package coverage mismatch')
    return set(packages)


def verify_embedded_packages(path, package_root):
    expected = {str(p.relative_to(package_root)): sha256(p) for p in package_root.glob('*.rpm')}
    expected.update({str(p.relative_to(package_root)): sha256(p) for p in (package_root / 'ha-dependencies').rglob('*.rpm')})
    found = {}
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./').removesuffix('/')
            if not name or name == '.':
                continue
            relative(name)
            if member.isdir():
                continue
            if not member.isfile() or member.size > 1024 ** 3:
                raise ValueError('Unexpected ISO package archive member')
            if name.endswith('.rpm'):
                if name not in expected or name in found:
                    raise ValueError('Untracked/duplicate RPM in ISO payload')
                stream = archive.extractfile(member)
                h = hashlib.sha256()
                while block := stream.read(1024 * 1024):
                    h.update(block)
                found[name] = h.hexdigest()
    if found != expected:
        raise ValueError('ISO embedded RPM set/digests differ from qualified candidates')
    return sorted(found)


def installed_packages(path, firmware):
    value = json.loads(Path(path).read_text())
    return validate_inventory(value, firmware)


def verify_application_archive(path, root, software, manifest, compiler, binary_sha256):
    root, software = Path(root), Path(software)
    platform = next(line.removeprefix('host: ') for line in compiler.splitlines() if line.startswith('host: '))
    prefix = f'riverlb-{manifest["version"]}-{platform}-{manifest["commit"][:12]}'
    if Path(path).name != prefix + '.tar.gz':
        raise ValueError('Application archive name differs from source/platform')
    expected = {'riverlb': binary_sha256, 'LICENSE': sha256(root / 'LICENSE'),
                'compiler.txt': hashlib.sha256(compiler.encode()).hexdigest()}
    for name in ('riverlb-authority', 'riverlb-cluster', 'riverlb-traffic', 'riverlb-ha.service'):
        expected['deploy/ha/' + name] = sha256(root / 'deploy/ha' / name)
    for name in ('sbom.cdx.json', 'licenses.json', 'notices.tar.gz'):
        expected['software/' + name] = sha256(software / name)
    found, data = {}, {}
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            if not member.isfile() or member.size > 1024 ** 3 or not member.name.startswith(prefix + '/'):
                raise ValueError('Unexpected application archive member')
            name = member.name.removeprefix(prefix + '/')
            relative(name)
            if name in found or name not in set(expected) | {'README.md', 'manifest.json', 'SHA256SUMS'}:
                raise ValueError('Untracked/duplicate application payload')
            source = archive.extractfile(member)
            h = hashlib.sha256()
            retained = bytearray()
            while block := source.read(1024 * 1024):
                h.update(block)
                if name in ('manifest.json', 'SHA256SUMS'):
                    retained.extend(block)
                    if len(retained) > 1024 * 1024:
                        raise ValueError('Oversized application metadata')
            found[name] = h.hexdigest()
            if retained:
                data[name] = bytes(retained)
    if set(found) != set(expected) | {'README.md', 'manifest.json', 'SHA256SUMS'} or any(found[k] != v for k, v in expected.items()):
        raise ValueError('Application archive differs from built binary/source/inventory')
    declared = {}
    for line in data['SHA256SUMS'].decode().splitlines():
        digest, name = line.split('  ', 1)
        name = name.removeprefix('./')
        relative(name)
        if name in declared:
            raise ValueError('Duplicate application checksum')
        declared[name] = digest
    if declared != {k: v for k, v in found.items() if k != 'SHA256SUMS'}:
        raise ValueError('Application checksum coverage/content mismatch')
    expected_manifest = {**manifest, 'format_version': 2, 'platform': platform, 'binary_sha256': binary_sha256,
                         'signed': False, 'purpose': 'build-candidate', 'compiler_sha256': expected['compiler.txt'],
                         'sbom_sha256': expected['software/sbom.cdx.json']}
    if json.loads(data['manifest.json']) != expected_manifest:
        raise ValueError('Application manifest/source/compiler mismatch')
    return found
