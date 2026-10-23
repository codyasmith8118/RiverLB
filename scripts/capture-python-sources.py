#!/usr/bin/env python3
"""Capture immutable PyPI source references, including SDK-vendored distributions."""
import argparse
import email
import hashlib
import json
import re
from pathlib import Path
import urllib.parse
import urllib.request
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheels', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--downloads', type=Path, required=True)
    args = parser.parse_args()
    args.downloads.mkdir(parents=True, exist_ok=True)
    entries = {}
    for wheel in sorted(args.wheels.glob('*.whl')):
        wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            for path in archive.namelist():
                if not path.endswith('.dist-info/METADATA'):
                    continue
                metadata = email.message_from_bytes(archive.read(path))
                key = re.sub('[-_.]+', '-', metadata['Name']).lower() + '==' + metadata['Version']
                if key not in entries:
                    url = 'https://pypi.org/pypi/' + urllib.parse.quote(metadata['Name']) + '/' + urllib.parse.quote(metadata['Version']) + '/json'
                    with urllib.request.urlopen(url, timeout=30) as response:
                        release = json.load(response)
                    sources = [f for f in release['urls'] if f['packagetype'] == 'sdist']
                    if len(sources) != 1:
                        raise ValueError('Expected one source archive: ' + key)
                    source = sources[0]
                    address = urllib.parse.urlsplit(source['url'])
                    if address.scheme != 'https' or address.hostname != 'files.pythonhosted.org':
                        raise ValueError('Unexpected source host')
                    destination = args.downloads / source['filename']
                    h = hashlib.sha256()
                    with urllib.request.urlopen(source['url'], timeout=60) as response, destination.open('wb') as stream:
                        size = 0
                        while block := response.read(1024 * 1024):
                            size += len(block)
                            if size > 128 * 1024 * 1024:
                                raise ValueError('Oversized source archive')
                            h.update(block); stream.write(block)
                    if h.hexdigest() != source['digests']['sha256']:
                        raise ValueError('Source digest mismatch')
                    entries[key] = dict(name=metadata['Name'], version=metadata['Version'],
                                        source_url=source['url'], source_sha256=h.hexdigest(),
                                        source_size=size, origins=[])
                    print('Verified source archive:', key, flush=True)
                entries[key]['origins'].append(dict(wheel=wheel.name, wheel_sha256=wheel_hash, metadata_path=path))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(schema=1, packages=entries), sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
