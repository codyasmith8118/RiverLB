#!/usr/bin/env python3
"""Maintainer-only online capture of metadata for the pinned installer runtime.

Run in the retained AlmaLinux builder. Normal builds never call this program or
resolve repositories. Package signatures are checked against the retained OS key.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def query(path):
    fields = ['NAME', 'EPOCHNUM', 'VERSION', 'RELEASE', 'ARCH', 'LICENSE', 'SOURCERPM', 'URL']
    row = subprocess.check_output(['rpm', '-qp', '--qf', '\t'.join('%{' + f + '}' for f in fields), str(path)], text=True)
    values = row.split('\t')
    if len(values) != len(fields) or any('\n' in v or '\r' in v for v in values):
        raise ValueError('Invalid package metadata')
    return dict(zip((f.lower() for f in fields), values))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-list', type=Path, required=True)
    parser.add_argument('--base-config', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extra-rpms', type=Path, action='append', default=[])
    args = parser.parse_args()
    args.output.mkdir(exist_ok=True, parents=True)
    packages = sorted(set(args.runtime_list.read_text().splitlines()))
    if not packages or any(not p or '/' in p or p.startswith('-') for p in packages):
        raise ValueError('Invalid runtime package manifest')
    rpms = args.output / 'rpms'
    rpms.mkdir(exist_ok=True)
    common = ['dnf', '-y', '--releasever=10.2']
    run(common + ['download', '--destdir', str(rpms)] + packages)
    paths = {p.name: p for p in rpms.glob('*.rpm')}
    for extra in args.extra_rpms:
        for path in extra.rglob('*.rpm'):
            if path.name in paths and digest(path) != digest(paths[path.name]):
                raise ValueError('Conflicting bytes for an RPM filename: ' + path.name)
            paths[path.name] = path
    with tempfile.TemporaryDirectory() as folder:
        run(['rpm', '--dbpath', folder, '--initdb'])
        run(['rpm', '--dbpath', folder, '--import', str(args.key)])
        for rpm in sorted(paths.values()):
            result = subprocess.check_output(['rpmkeys', '--dbpath', folder, '--checksig', str(rpm)], text=True)
            if not result.strip().endswith('digests signatures OK'):
                raise ValueError('Package is not signed by the pinned OS key: ' + rpm.name)
    entries = []
    notice_root = args.output / 'notices'
    notice_root.mkdir(exist_ok=True)
    for rpm in sorted(paths.values()):
        item = query(rpm)
        item['nevra'] = '{name}-{version}-{release}.{arch}'.format(**item)
        item['sha256'] = digest(rpm)
        item['installer_runtime'] = item['nevra'] in packages
        if item['license'] in ('', '(none)') or item['sourcerpm'] in ('', '(none)'):
            raise ValueError('Unexpected or incomplete package metadata: ' + rpm.name)
        license_paths = subprocess.check_output(['rpm', '-qp', '--licensefiles', str(rpm)], text=True).splitlines()
        item['notices'] = []
        for path in license_paths:
            if path == '(contains no files)':
                continue
            # Streaming extraction to stdout never creates paths from an RPM.
            if not path.startswith('/usr/') or '..' in Path(path).parts:
                raise ValueError('Unexpected RPM license path: ' + path)
            producer = subprocess.Popen(['rpm2cpio', str(rpm)], stdout=subprocess.PIPE)
            try:
                result = subprocess.run(['cpio', '--extract', '--to-stdout', '--quiet', '.' + path],
                                        stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            finally:
                producer.stdout.close()
                if producer.wait(timeout=30) not in (0, -13):
                    raise ValueError('Failed to read RPM license payload')
            # RPM may mark a whole directory as a license; it has no file bytes.
            if not result.stdout:
                continue
            if len(result.stdout) > 16 * 1024 * 1024:
                raise ValueError('Oversized license file')
            destination = notice_root / item['nevra'] / path.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(result.stdout)
            item['notices'].append(dict(path=str(destination.relative_to(notice_root)), sha256=digest(destination)))
        entries.append(item)
    if {e['nevra'] for e in entries if e['installer_runtime']} != set(packages):
        raise ValueError('Runtime package coverage mismatch')
    sources = sorted({e['sourcerpm'] for e in entries})
    locations = subprocess.check_output(common + ['--enablerepo=*-source', 'repoquery', '--arch=src', '--location'] +
                                        [name.removesuffix('.rpm') for name in sources], text=True)
    source_urls = {}
    for line in locations.splitlines():
        parsed = urllib.parse.urlsplit(line)
        if parsed.scheme in ('http', 'https') and parsed.hostname in ('repo.almalinux.org', 'vault.almalinux.org'):
            source_urls[Path(parsed.path).name] = urllib.parse.urlunsplit(('https', parsed.netloc, parsed.path, '', ''))
    if set(sources) - set(source_urls):
        raise ValueError('Missing corresponding source URLs: ' + repr(sorted(set(sources) - set(source_urls))))
    def available(url):
        with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=30) as response:
            if response.status != 200:
                raise ValueError('Source archive unavailable: ' + url)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(available, [source_urls[name] for name in sources]))
    for entry in entries:
        entry['source_url'] = source_urls[entry['sourcerpm']]
    with (args.output / 'runtime-notices.tar.gz').open('wb') as dest, gzip.GzipFile(fileobj=dest, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as archive:
            selected = {entry['path'] for item in entries for entry in item['notices']}
            for path in (notice_root / name for name in sorted(selected)):
                if path.is_file():
                    info = archive.gettarinfo(str(path), arcname=str(path.relative_to(notice_root)))
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    info.mode = 0o644
                    with path.open('rb') as source:
                        archive.addfile(info, source)
    result = dict(schema=1, base_iso_sha256=json.loads(args.base_config.read_text())['sha256'],
                  runtime_manifest_sha256=digest(args.runtime_list), rpm_key_sha256=digest(args.key),
                  notices_sha256=digest(args.output / 'runtime-notices.tar.gz'), packages=entries)
    (args.output / 'runtime-packages.lock.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print('Captured exact metadata and source references for', len(entries), 'runtime packages')


if __name__ == '__main__':
    main()
