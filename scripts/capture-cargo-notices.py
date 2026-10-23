#!/usr/bin/env python3
"""Capture missing crate notices from the exact VCS commit recorded in each crate.

Maintainer-only online tool. Build-time inventory uses only retained bytes/hashes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
import urllib.parse
import urllib.request

PREFIXES = ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'UNLICENSE')


def legal(path):
    return path.name.upper().startswith(PREFIXES)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    selected = {(p['name'], p['version']) for p in json.loads(args.metadata.read_text())['packages']}
    args.output.mkdir(parents=True, exist_ok=True)
    trees = {}
    modes = {}
    entries = []
    for folder in sorted(args.vendor.iterdir()):
        package = tomllib.loads((folder / 'Cargo.toml').read_text())['package']
        if (package['name'], package['version']) not in selected or any(p.is_file() and legal(p) for p in folder.rglob('*')):
            continue
        vcs = json.loads((folder / '.cargo_vcs_info.json').read_text())['git']['sha1']
        repository = urllib.parse.urlsplit(package['repository'])
        project = repository.path.strip('/').removesuffix('.git')
        if repository.hostname != 'github.com' or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', project) or not re.fullmatch('[a-f0-9]{40}', vcs):
            raise ValueError('Review unsupported VCS origin: ' + folder.name)
        identity = (project, vcs)
        if identity not in trees:
            modes[identity] = 'upstream-license-files'
            root = json.loads(subprocess.check_output(['gh', 'api', f'repos/{project}/git/trees/{vcs}'], timeout=60))
            paths = [e['path'] for e in root['tree'] if e['type'] == 'blob' and legal(Path(e['path']))]
            # Preserve nested legal notices when upstream keeps a license collection.
            for entry in root['tree']:
                if entry['type'] == 'tree' and entry['path'].lower() in ('licenses', 'licences'):
                    subtree = json.loads(subprocess.check_output(['gh', 'api', f'repos/{project}/git/trees/{entry["sha"]}?recursive=1'], timeout=60))
                    if subtree.get('truncated'):
                        raise ValueError('Truncated notice tree')
                    paths += [entry['path'] + '/' + e['path'] for e in subtree['tree'] if e['type'] == 'blob']
            origins = [(path, f'https://raw.githubusercontent.com/{project}/{vcs}/' + urllib.parse.quote(path, safe='/'))
                       for path in sorted(paths)]
            if not origins:
                # Some crates put their actual license grant only in README.
                # Preserve that grant and the explicitly linked Apache text;
                # never invent a copyright holder or substitute an MIT template.
                readme_url = f'https://raw.githubusercontent.com/{project}/{vcs}/README.md'
                with urllib.request.urlopen(readme_url, timeout=30) as response:
                    grant = response.read(2 * 1024 * 1024).decode()
                origins = [('README.md', readme_url), ('Cargo.toml', f'https://raw.githubusercontent.com/{project}/{vcs}/Cargo.toml')]
                modes[identity] = 'upstream-declarations-no-license-file'
                if 'Apache-2.0' in package.get('license', '') and 'https://www.apache.org/licenses/LICENSE-2.0' in grant:
                    origins.append(('LICENSE-APACHE-2.0.txt', 'https://www.apache.org/licenses/LICENSE-2.0.txt'))
                    modes[identity] = 'upstream-grant-and-linked-license-text'
            files = []
            for path, url in origins:
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(2 * 1024 * 1024 + 1)
                if not data or len(data) > 2 * 1024 * 1024:
                    raise ValueError('Invalid notice size')
                destination = args.output / 'files' / project / vcs / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                files.append(dict(path=str(destination.relative_to(args.output)), url=url, sha256=sha(data)))
            if not files:
                raise ValueError('No upstream notice files: ' + folder.name)
            trees[identity] = files
        checksum = json.loads((folder / '.cargo-checksum.json').read_text())['package']
        entries.append(dict(name=package['name'], version=package['version'], crate_sha256=checksum,
                            repository=package['repository'], commit=vcs, notice_kind=modes[identity], notices=trees[identity]))
        print('Retained exact upstream notices:', folder.name, flush=True)
    (args.output / 'index.json').write_text(json.dumps(dict(schema=1, crates=entries), sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
