#!/usr/bin/env python3
"""Generate or independently reconstruct a retained-input software inventory."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from software_inventory import source_inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['source', 'verify-source', 'appliance', 'verify-appliance'])
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    for name in ('packages', 'media', 'disks', 'installed', 'report'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--firmware', choices=['bios', 'uefi'])
    args = parser.parse_args()
    if args.command in ('appliance', 'verify-appliance'):
        from appliance_inventory import build
        if any(getattr(args, key) is None for key in ('packages', 'media', 'disks', 'installed', 'report', 'firmware')):
            parser.error('appliance inventory requires packages, media, disks, installed, report and firmware')
        if args.command == 'appliance':
            build(args.root, args.inputs, args.packages, args.media, args.disks, args.installed, args.report, args.output, args.firmware)
        else:
            with tempfile.TemporaryDirectory() as folder:
                expected = Path(folder)
                build(args.root, args.inputs, args.packages, args.media, args.disks, args.installed, args.report, expected, args.firmware)
                if {p.name for p in args.output.iterdir()} != {p.name for p in expected.iterdir()}:
                    raise ValueError('Unexpected inventory files')
                for path in expected.iterdir():
                    from software_inventory import sha256
                    if (args.output / path.name).is_symlink() or sha256(args.output / path.name) != sha256(path):
                        raise ValueError('Appliance inventory differs: ' + path.name)
        return
    if args.manifest is None or args.binary is None:
        parser.error('source inventory requires manifest and binary')
    metadata = json.loads(args.metadata.read_text()) if args.metadata else json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1', '--filter-platform', 'x86_64-unknown-linux-gnu'], cwd=args.root))
    inv, document = source_inventory(args.root, args.inputs, metadata, args.binary, json.loads(args.manifest.read_text()), args.agent)
    if args.command == 'source':
        inv.write(args.output, document)
    else:
        with tempfile.TemporaryDirectory() as folder:
            inv.write(Path(folder), document)
            for name in ('sbom.cdx.json', 'licenses.json', 'notices.tar.gz'):
                path = args.output / name
                if path.is_symlink() or path.read_bytes() != (Path(folder) / name).read_bytes():
                    raise ValueError('Inventory coverage/content mismatch: ' + name)
    print('Verified inventory:', len(inv.components), 'components;', len(inv.notices), 'retained notice/metadata files')


if __name__ == '__main__':
    main()
