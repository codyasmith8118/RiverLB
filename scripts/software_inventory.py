"""Deterministic CycloneDX component inventories from retained distribution bytes.

This module never resolves registries, executes source packages, or reads runtime
configuration. Maintainer capture tools retain missing upstream metadata separately.
"""
import csv
import email
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib
import urllib.parse
import zipfile

REPOSITORY = 'https://github.com/codyasmith8118/RiverLB'
LEGAL_PREFIXES = ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'UNLICENSE')


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def encoded(value):
    return urllib.parse.quote(value, safe='.-_')


def relative(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or '..' in p.parts or '\\' in value or str(p) != value or any(ord(c) < 32 for c in value):
        raise ValueError('Unsafe inventory path')
    return p


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def legal(name):
    return PurePosixPath(name).name.upper().startswith(LEGAL_PREFIXES)


def norm(name):
    return re.sub('[-_.]+', '-', name).lower()


def component(kind, name, version, digest, license_name, source, *, qualifier='', scope='required', properties=None):
    if (not name or not version or not re.fullmatch('[a-f0-9]{64}', digest) or not license_name
            or license_name.strip().upper() in ('UNKNOWN', 'NONE', '(NONE)', 'NOASSERTION') or not source.startswith('https://')):
        raise ValueError('Incomplete component identity, license or source')
    purl = f'pkg:{kind}/{encoded(name)}@{encoded(version)}' + qualifier
    return {'type': 'application' if name == 'riverlb' else 'library', 'bom-ref': purl,
            'name': name, 'version': version, 'scope': scope, 'purl': purl,
            'hashes': [{'alg': 'SHA-256', 'content': digest}],
            'licenses': [{'license': {'name': license_name}}],
            'externalReferences': [{'type': 'distribution', 'url': source}],
            'properties': [{'name': k, 'value': str(v)} for k, v in sorted((properties or {}).items())]}


class Inventory:
    def __init__(self):
        self.components = {}
        self.dependencies = {}
        self.notices = {}
        self.license_records = {}

    def add(self, item):
        ref = item['bom-ref']
        if ref in self.components:
            raise ValueError('Duplicate component identity: ' + ref)
        self.components[ref] = item
        self.dependencies[ref] = set()
        self.license_records[ref] = {'name': item['name'], 'version': item['version'], 'scope': item['scope'],
                                    'licenses': item['licenses'], 'sources': item['externalReferences'], 'notices': []}
        return ref

    def notice(self, ref, path, data, source):
        path = str(relative(path))
        if not data or len(data) > 16 * 1024 * 1024:
            raise ValueError('Invalid notice size')
        if path in self.notices and self.notices[path] != data:
            raise ValueError('Conflicting notice bytes')
        self.notices[path] = data
        self.license_records[ref]['notices'].append({'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'source': source})

    def cargo(self, root, inputs, metadata, root_ref):
        lock = tomllib.loads((root / 'Cargo.lock').read_text())
        locked = {(p['name'], p['version']): p for p in lock['package'] if 'source' in p}
        selected = {(p['name'], p['version']) for p in metadata['packages']}
        supplement_root = root / 'packaging/third-party/cargo'
        supplemental = json.loads((supplement_root / 'index.json').read_text())
        supplemental = {(p['name'], p['version']): p for p in supplemental['crates']}
        vendors = {}
        for folder in (inputs / 'cargo-vendor').iterdir():
            package = tomllib.loads((folder / 'Cargo.toml').read_text())['package']
            key = package['name'], package['version']
            if key in vendors:
                raise ValueError('Duplicate retained crate')
            vendors[key] = folder, package
        if set(vendors) != set(locked):
            raise ValueError('Cargo.lock and retained crate inventory differ')
        refs = {}
        for key, (folder, package) in sorted(vendors.items()):
            name, version = key
            checksum = json.loads((folder / '.cargo-checksum.json').read_text())['package']
            if checksum != locked[key]['checksum'] or locked[key]['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
                raise ValueError('Crate checksum/source mismatch')
            url = f'https://static.crates.io/crates/{encoded(name)}/{encoded(name)}-{encoded(version)}.crate'
            license_name = package.get('license')
            if not license_name and package.get('license-file'):
                license_file = folder / str(relative(package['license-file']))
                license_name = 'License file SHA256 ' + sha256(license_file)
            ref = self.add(component('cargo', name, version, checksum, license_name, url,
                                     scope='required' if key in selected else 'excluded',
                                     properties={'riverlb:hash-scope': 'upstream crate archive',
                                                 'riverlb:selection': 'linux-x86_64 build graph' if key in selected else 'locked other-target/build input'}))
            refs[key] = ref
            # Preserve publisher metadata/README as well as every supplied legal file.
            paths = [p for p in folder.rglob('*') if p.is_file() and (legal(p.name) or p.name in ('Cargo.toml', 'Cargo.toml.orig') or p.name.upper().startswith('README'))]
            if package.get('license-file'):
                path = folder / str(relative(package['license-file']))
                if not path.is_file():
                    raise ValueError('Declared crate license file absent')
                paths = sorted(set(paths) | {path})
            supplied_license = bool(package.get('license-file')) or any(legal(p.name) for p in paths)
            for path in sorted(paths):
                if path.is_symlink():
                    raise ValueError('Notice symlink')
                part = str(path.relative_to(folder))
                self.notice(ref, f'cargo/{name}-{version}/{part}', path.read_bytes(), url + '#' + urllib.parse.quote(part))
            if key in selected and not supplied_license:
                extra = supplemental.get(key)
                if not extra or extra['crate_sha256'] != checksum:
                    raise ValueError('Missing reviewed upstream notice capture: ' + name)
                vcs = json.loads((folder / '.cargo_vcs_info.json').read_text())['git']['sha1']
                if extra['commit'] != vcs or extra['repository'] != package['repository']:
                    raise ValueError('Upstream notice origin mismatch')
                self.license_records[ref]['notice_kind'] = extra['notice_kind']
                for entry in extra['notices']:
                    path = supplement_root / str(relative(entry['path']))
                    if path.is_symlink() or sha256(path) != entry['sha256']:
                        raise ValueError('Upstream notice digest mismatch')
                    self.notice(ref, f'cargo/{name}-{version}/upstream/{entry["path"]}', path.read_bytes(), entry['url'])
        # Platform-filtered dependency edges come from Cargo itself, never names guessed from source text.
        ids = {p['id']: refs.get((p['name'], p['version'])) for p in metadata['packages']}
        ids[metadata['resolve']['root']] = root_ref
        for node in metadata['resolve']['nodes']:
            ref = ids.get(node['id'])
            if ref:
                self.dependencies[ref].update(ids[d['pkg']] for d in node['deps'] if ids.get(d['pkg']))
        return refs

    def python(self, root, inputs):
        text = (root / 'deploy/ha/vendor/openstack-requirements.txt').read_text()
        locked = {}
        for line in text.replace('\\\n', ' ').splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s]+)\s+((?:--hash=sha256:[a-f0-9]{64}\s*)+)', line)
            if not match:
                raise ValueError('Unsupported SDK lock entry')
            key = norm(match[1]), match[2]
            if key in locked:
                raise ValueError('Duplicate SDK lock entry')
            locked[key] = set(re.findall(r'sha256:([a-f0-9]{64})', match[3]))
        source_lock = json.loads((root / 'packaging/third-party/python-sources.lock.json').read_text())['packages']
        seen = set()
        refs = []
        for wheel in sorted((inputs / 'wheels').glob('*.whl')):
            wheel_hash = sha256(wheel)
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    raise ValueError('Duplicate wheel member')
                for name in names:
                    relative(name.removesuffix('/'))
                records = [n for n in names if n.endswith('.dist-info/METADATA')]
                top = [n for n in records if len(PurePosixPath(n).parts) == 2]
                if len(top) != 1:
                    raise ValueError('Invalid root wheel distribution')
                own = email.message_from_bytes(archive.read(top[0]))
                own_key = norm(own['Name']), own['Version']
                if own_key in seen or wheel_hash not in locked.get(own_key, set()):
                    raise ValueError('SDK wheel differs from hash lock')
                seen.add(own_key)
                for path in sorted(records):
                    metadata = email.message_from_bytes(archive.read(path))
                    key = norm(metadata['Name']), metadata['Version']
                    source = source_lock.get(key[0] + '==' + key[1])
                    origin = {'wheel': wheel.name, 'wheel_sha256': wheel_hash, 'metadata_path': path}
                    if not source or origin not in source['origins']:
                        raise ValueError('Missing Python source/embedded-distribution capture')
                    directory = PurePosixPath(path).parent
                    embedded = path != top[0]
                    if embedded:
                        record = str(directory / 'RECORD')
                        if record not in names:
                            raise ValueError('Missing vendored distribution file inventory')
                        members = {path}
                        for row in csv.reader(io.StringIO(archive.read(record).decode())):
                            if row and '..' not in PurePosixPath(row[0]).parts:
                                candidate = str(directory.parent / row[0])
                                if candidate in names:
                                    members.add(candidate)
                        h = hashlib.sha256()
                        for name in sorted(members):
                            h.update(name.encode() + b'\0' + hashlib.sha256(archive.read(name)).digest())
                        digest = h.hexdigest()
                    else:
                        digest = wheel_hash
                    license_name = metadata.get('License-Expression') or metadata.get('License')
                    if not license_name:
                        license_name = '; '.join(c for c in metadata.get_all('Classifier', []) if c.startswith('License ::'))
                    qualifier = '?embedded_in=' + encoded(wheel.name) if embedded else ''
                    ref = self.add(component('pypi', key[0], key[1], digest, license_name, source['source_url'],
                                             qualifier=qualifier, properties={
                                                 'riverlb:hash-scope': 'actual vendored RECORD files' if embedded else 'retained wheel archive',
                                                 'riverlb:source-sha256': source['source_sha256'],
                                                 'riverlb:containing-wheel-sha256': wheel_hash,
                                                 'riverlb:metadata-path': path}))
                    refs.append(ref)
                    self.notice(ref, f'python/{encoded(key[0])}-{encoded(key[1])}/{encoded(wheel.name)}/{path}', archive.read(path), source['source_url'])
                    for name in names:
                        if name.startswith(str(directory) + '/') and (legal(name) or '/licenses/' in name) and not name.endswith('/'):
                            self.notice(ref, f'python/{encoded(key[0])}-{encoded(key[1])}/{encoded(wheel.name)}/{name}', archive.read(name), source['source_url'])
                # A separate pass handles the root appearing after a vendored METADATA.
                root_ref = f'pkg:pypi/{encoded(own_key[0])}@{encoded(own_key[1])}'
                self.dependencies[root_ref].update(ref for ref in refs if self.components[ref]['properties'] and any(p['value'] == wheel_hash for p in self.components[ref]['properties'] if p['name'] == 'riverlb:containing-wheel-sha256') and ref != root_ref)
        if seen != set(locked):
            raise ValueError('SDK lock coverage mismatch')
        return refs

    def document(self, root_component, properties):
        return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                'metadata': {'component': root_component, 'properties': [{'name': k, 'value': str(v)} for k, v in sorted(properties.items())]},
                'components': [self.components[k] for k in sorted(self.components) if k != root_component['bom-ref']],
                'dependencies': [{'ref': k, 'dependsOn': sorted(v)} for k, v in sorted(self.dependencies.items())]}

    def write(self, output, document):
        output.mkdir(parents=True, exist_ok=True)
        (output / 'sbom.cdx.json').write_bytes(canonical(document))
        (output / 'licenses.json').write_bytes(canonical({'schema': 1, 'components': self.license_records}))
        with (output / 'notices.tar.gz').open('wb') as target, gzip.GzipFile(fileobj=target, mode='wb', mtime=0, filename='') as compressed:
            with tarfile.open(fileobj=compressed, mode='w|') as archive:
                for name, data in sorted(self.notices.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data); entry.mode = 0o644; entry.mtime = 0
                    archive.addfile(entry, io.BytesIO(data))


def source_inventory(root, inputs, metadata, binary, manifest, agent=None):
    root, inputs, binary = Path(root), Path(inputs), Path(binary)
    lock = json.loads((root / 'packaging/build-inputs.lock.json').read_text())
    if sha256(inputs / 'inventory.json') != lock['inventory_sha256']:
        raise ValueError('Retained input inventory identity mismatch')
    retained = json.loads((inputs / 'inventory.json').read_text())
    for name, item in retained['files'].items():
        if name.startswith(('cargo-vendor/', 'wheels/')):
            path = inputs / str(relative(name))
            if path.is_symlink() or sha256(path) != item['sha256']:
                raise ValueError('Retained source bytes changed: ' + name)
    if manifest['build_inputs'] != lock or manifest['cargo_lock_sha256'] != sha256(root / 'Cargo.lock'):
        raise ValueError('Build manifest/lock mismatch')
    if not re.fullmatch('[a-f0-9]{40}', manifest['commit']):
        raise ValueError('Invalid source commit')
    package = tomllib.loads((root / 'Cargo.toml').read_text())['package']
    if package['version'] != manifest['version']:
        raise ValueError('Application version mismatch')
    inv = Inventory()
    app = component('generic', 'riverlb', manifest['version'], sha256(binary), package['license'],
                    REPOSITORY + '/archive/' + manifest['commit'] + '.tar.gz',
                    properties={'riverlb:source-commit': manifest['commit'], 'riverlb:hash-scope': 'application executable'})
    root_ref = inv.add(app)
    inv.notice(root_ref, 'riverlb/LICENSE', (root / 'LICENSE').read_bytes(), REPOSITORY + '/blob/' + manifest['commit'] + '/LICENSE')
    inv.cargo(root, inputs, metadata, root_ref)
    inv.dependencies[root_ref].update(inv.python(root, inputs))
    source = root / 'deploy/ha/vendor/fence-agents/fence_pve.py.in'
    if sha256(source) != '2285ab56ac41b25690e67e1eb2cfc14910e133bca28d24d328b1d7b96e4ae406':
        raise ValueError('Vendored fence agent changed without provenance review')
    if not (source.parent / 'COPYING.applications').is_file():
        raise ValueError('Vendored fence-agent license absent')
    ref = inv.add(component('generic', 'fence_pve', '4.16.0', sha256(agent or source), 'GPL-2.0-or-later',
                            'https://github.com/ClusterLabs/fence-agents/blob/05fd299e094c6981b4c5b943dee03a29e78ee016/agents/pve/fence_pve.py',
                            properties={'riverlb:source-template-sha256': sha256(source),
                                        'riverlb:hash-scope': 'rendered executable' if agent else 'retained source template'}))
    inv.dependencies[root_ref].add(ref)
    for path in sorted(source.parent.iterdir()):
        if path.is_file():
            inv.notice(ref, 'fence-agents/' + path.name, path.read_bytes(), REPOSITORY + '/blob/' + manifest['commit'] + '/deploy/ha/vendor/fence-agents/' + path.name)
    properties = {'riverlb:source-commit': manifest['commit'], 'riverlb:cargo-lock-sha256': sha256(root / 'Cargo.lock'),
                  'riverlb:input-snapshot-sha256': lock['sha256'], 'riverlb:input-inventory-sha256': lock['inventory_sha256'],
                  'riverlb:builder-image': manifest.get('builder_image', lock['images']['builder']['id']), 'riverlb:dirty': str(manifest['dirty']).lower(),
                  'riverlb:scope': 'all locked Cargo crates (non-selected targets excluded), private SDK wheels including vendored distributions, application and vendored fence agent'}
    return inv, inv.document(app, properties)
