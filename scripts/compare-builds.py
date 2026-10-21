#!/usr/bin/env python3
"""Compare unsigned RPM candidate sets, including all retained dependency bytes."""
import argparse
import hashlib
import json
from pathlib import Path


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Unexpected symlink: ' + str(path))
        if path.is_file():
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    h.update(chunk)
            result[str(path.relative_to(root))] = h.hexdigest()
    return result


def compare(left, right):
    a, b = files(left), files(right)
    changed = sorted(name for name in a.keys() | b.keys() if a.get(name) != b.get(name))
    # JSON formatting is not semantic; all manifest fields remain significant.
    manifests = ['build-manifest.json', 'build-inputs.json']
    normalized_equal = all(json.loads((left / name).read_text()) == json.loads((right / name).read_text()) for name in manifests)
    return dict(schema=1, comparison='unsigned-rpm-candidates-v1',
                normalized_manifests_equal=normalized_equal, byte_identical=not changed,
                changed_files=changed, left=a, right=b)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.left, args.right)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    if not report['normalized_manifests_equal'] or not report['byte_identical']:
        raise SystemExit('FAIL: ' + ', '.join(report['changed_files']))
    print('PASS: normalized manifests and all unsigned candidate/dependency hashes match')


if __name__ == '__main__':
    main()
