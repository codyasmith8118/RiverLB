#!/usr/bin/env python3
"""Build Anaconda product.img and verify the media's offline GUI components.

The base distribution, packages, EFI vendor path, licenses and signatures are
preserved. The product image changes only the installer's presentation.
"""
import argparse
import gzip
import html
from pathlib import Path
import re
import stat
import subprocess

GUI_COMPONENTS = (
    'usr/lib64/python3.12/site-packages/pyanaconda/ui/gui/__init__.py',
    'usr/lib64/girepository-1.0/Gtk-3.0.typelib',
    'usr/bin/mutter',
)


def check_runtime(image):
    listing = subprocess.run(['unsquashfs', '-l', str(image)], check=True,
                             capture_output=True, text=True).stdout
    paths = set(line.removeprefix('squashfs-root/') for line in listing.splitlines())
    missing = [name for name in GUI_COMPONENTS if name not in paths]
    if missing:
        raise SystemExit('This base media lacks the offline graphical installer: '
                         + ', '.join(missing) + '. Use reviewed AlmaLinux 10.2 DVD/minimal media.')
    print('Verified offline Anaconda GUI, GTK and Mutter components.')


def cpio_entry(name, content, inode, directory=False):
    """Deterministic newc archive records, no external mounts or root required."""
    encoded = name.encode('utf-8') + b'\0'
    mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)
    fields = (inode, mode, 0, 0, 1, 0, len(content),
              0, 0, 0, 0, len(encoded), 0)
    header = b'070701' + b''.join(f'{field:08x}'.encode('ascii') for field in fields)
    result = header + encoded
    result += b'\0' * (-len(result) % 4)
    result += content
    result += b'\0' * (-len(content) % 4)
    return result


def make_product(source, output, version, stage=None):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+.][A-Za-z0-9.-]+)?', version):
        raise SystemExit('Invalid RiverLB version for installer branding.')
    source, output = Path(source), Path(output)
    if stage is None:
        stage = (source / 'release-stage').read_text().strip()
    if stage not in ('In development', 'Pre-production', 'Production'):
        raise SystemExit('Invalid RiverLB release stage.')
    logo = (source / 'installer-logo.svg').read_text().replace('@VERSION@', html.escape(version)).replace('@RELEASE_STAGE@', html.escape(stage))
    files = {
        '.buildstamp': (f'[Main]\nProduct=RiverLB\nVersion={version} ({stage})\n'
                        f'BugURL=Contact your RiverLB administrator\nIsFinal={stage == "Production"}\n'
                        'Variant=Appliance\n').encode(),
        # AlmaLinux 10's dracut loader overlays product.img at the runtime root.
        # A top-level CSS file becomes /anaconda-gtk.css, which Anaconda never
        # loads. Put it at the actual high-priority product override path.
        'run/install/product/anaconda-gtk.css': (source / 'anaconda-gtk.css').read_bytes(),
        'usr/share/anaconda/pixmaps/riverlb-installer.svg': logo.encode(),
    }
    directories = {str(parent) for name in files for parent in Path(name).parents}
    archive = b''
    inode = 1
    for directory in sorted(directories, key=lambda name: (len(Path(name).parts), name)):
        archive += cpio_entry(directory, b'', inode, directory=True)
        inode += 1
    for name, data in sorted(files.items()):
        archive += cpio_entry(name, data, inode)
        inode += 1
    archive += cpio_entry('TRAILER!!!', b'', inode)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(gzip.compress(archive, compresslevel=9, mtime=0))


def brand_grub(text, mode):
    """Brand known AlmaLinux GRUB layouts; preserve kernel, labels and EFI paths."""
    if mode not in ('installer', 'image'):
        raise ValueError('Unsupported installer mode')
    if 'RiverLB appliance' in text:
        return text
    if not re.search(r"menuentry ['\"]Install AlmaLinux [^'\"]+['\"]", text):
        raise RuntimeError('Unknown boot menu layout; review before remastering')
    result, block, depth = [], [], 0
    for line in text.splitlines(keepends=True):
        if not block and re.match(r'\s*menuentry\s', line):
            block = [line]
            depth = line.count('{') - line.count('}')
        elif block:
            block.append(line)
            depth += line.count('{') - line.count('}')
        else:
            result.append(line)
        if block and depth == 0:
            entry = ''.join(block)
            title = re.search(r"menuentry (['\"])(.*?)\1", entry).group(2)
            if 'FIPS mode' in title:
                # RiverLB makes no FIPS certification claim.
                block = []
                continue
            if 'basic graphics mode' in title:
                new_title = 'Install RiverLB appliance (text console)'
                entry = re.sub(r'\bnomodeset\b', 'inst.text', entry)
            elif title.startswith('Test this media'):
                new_title = 'Test this media & install RiverLB appliance'
            elif title.startswith('Rescue '):
                new_title = 'Rescue a RiverLB appliance'
            else:
                new_title = 'Install RiverLB appliance'
            if mode == 'image' and 'inst.rescue' not in entry:
                new_title = 'Build RiverLB disposable appliance image'
            entry = entry.replace(title, new_title, 1)
            result.append(entry)
            block = []
    if block:
        raise RuntimeError('Unclosed boot menu entry')
    output = ''.join(result)
    if mode == 'installer' and 'inst.text' not in output:
        raise RuntimeError('The graphical installer must retain a text fallback entry')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, help='Check extracted images/install.img')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--release-stage')
    args = parser.parse_args()
    if args.runtime:
        check_runtime(args.runtime)
    if any((args.source, args.output, args.version, args.release_stage)):
        if not all((args.source, args.output, args.version)):
            parser.error('--source, --output and --version must be supplied together')
        make_product(args.source, args.output, args.version, args.release_stage)
    if not args.runtime and not args.output:
        parser.error('Select --runtime or --source/--output/--version')


if __name__ == '__main__':
    main()
