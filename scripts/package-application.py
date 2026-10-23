#!/usr/bin/env python3
"""Package an explicit compiled binary with its verified SBOM/notices allowlist."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from software_inventory import canonical, sha256


def package(root, binary, software, manifest, compiler, output):
    root, binary, software, output = map(Path, (root, binary, software, output))
    sbom = json.loads((software / 'sbom.cdx.json').read_text())
    properties = {p['name']: p['value'] for p in sbom['metadata']['properties']}
    if (sbom['metadata']['component']['hashes'] != [{'alg': 'SHA-256', 'content': sha256(binary)}]
            or properties['riverlb:source-commit'] != manifest['commit']
            or properties['riverlb:cargo-lock-sha256'] != manifest['cargo_lock_sha256']):
        raise ValueError('Application/SBOM/source mismatch')
    platform = next(line.removeprefix('host: ') for line in compiler.splitlines() if line.startswith('host: '))
    if 'linux' not in platform:
        raise ValueError('Application archive requires a Linux compiler target')
    name = f'riverlb-{manifest["version"]}-{platform}-{manifest["commit"][:12]}'
    files = {'riverlb': binary.read_bytes(), 'LICENSE': (root / 'LICENSE').read_bytes(),
             'README.md': b'''# RiverLB unsigned application candidate\n\nThis development archive contains the application, HA helpers, software inventory\nand preserved third-party notices. Its ABI matches the recorded compiler/builder.\nIt is not a production-qualified appliance or a signed offline update bundle.\nRun ./riverlb --help and consult the source docs before deployment. There is no\ndefault administrator password. HA also needs configured fencing and peer trust.\nsoftware/ records dependency inventory and source availability. Its SHA256SUMS\ndetects corruption; publisher identity requires the protected Sigstore provenance.\n''',
             'compiler.txt': compiler.encode()}
    for helper in ('riverlb-authority', 'riverlb-cluster', 'riverlb-traffic', 'riverlb-ha.service'):
        files['deploy/ha/' + helper] = (root / 'deploy/ha' / helper).read_bytes()
    for file in ('sbom.cdx.json', 'licenses.json', 'notices.tar.gz'):
        files['software/' + file] = (software / file).read_bytes()
    archive_manifest = {**manifest, 'format_version': 2, 'platform': platform,
                        'binary_sha256': sha256(binary), 'signed': False, 'purpose': 'build-candidate',
                        'compiler_sha256': hashlib.sha256(compiler.encode()).hexdigest(),
                        'sbom_sha256': sha256(software / 'sbom.cdx.json')}
    files['manifest.json'] = canonical(archive_manifest)
    files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ./' + path + '\n' for path, data in sorted(files.items())).encode()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / (name + '.tar.gz')
    partial = destination.with_suffix('.gz.partial')
    try:
        with partial.open('wb') as target, gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|') as archive:
                for path, data in sorted(files.items()):
                    entry = tarfile.TarInfo(name + '/' + path)
                    entry.size = len(data); entry.mtime = manifest.get('source_date_epoch', 0)
                    entry.mode = 0o755 if path == 'riverlb' or path in ('deploy/ha/riverlb-authority', 'deploy/ha/riverlb-cluster', 'deploy/ha/riverlb-traffic') else 0o644
                    archive.addfile(entry, io.BytesIO(data))
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    (destination.parent / (destination.name + '.sha256')).write_text(sha256(destination) + '  ' + destination.name + '\n')
    return destination


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--software', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(package(a.root, a.binary, a.software, json.loads(a.manifest.read_text()), a.compiler.read_text(), a.output))
