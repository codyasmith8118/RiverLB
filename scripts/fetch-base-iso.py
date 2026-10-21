#!/usr/bin/env python3
"""Download media pinned by the reviewed repository lock manifest."""
import hashlib
import json
import os
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parent.parent
lock = json.loads((root / 'appliance/base-media.json').read_text())
folder = root / 'dist/base'
folder.mkdir(parents=True, exist_ok=True)
path = folder / lock['filename']
if not path.exists():
    partial = path.with_suffix('.iso.partial')
    try:
        with urllib.request.urlopen(lock['url'], timeout=30) as response, partial.open('wb') as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.replace(partial, path)
    finally:
        partial.unlink(missing_ok=True)
digest = hashlib.sha256()
with path.open('rb') as stream:
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
if digest.hexdigest() != lock['sha256']:
    raise SystemExit('Base media checksum mismatch; refusing to build')
print(path)
