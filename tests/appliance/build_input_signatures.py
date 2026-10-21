"""Real offline RPM trust-boundary tests against retained vendor packages."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_inputs', ROOT / 'scripts/build-inputs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def rejected(tree, runtime, description):
    try:
        m.verify_signatures(tree, runtime)
    except (ValueError, subprocess.CalledProcessError):
        print('PASS ' + description)
    else:
        raise AssertionError('Accepted ' + description)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unsigned_rpm', type=Path)
    args = parser.parse_args()
    lock = m.read_lock(ROOT / 'packaging/build-inputs.lock.json')
    cache = Path(os.environ.get('RIVERLB_BUILD_INPUTS_CACHE', str(ROOT / 'dist/build-inputs'))).resolve()
    inputs = m.prepare(lock, cache)
    runtime = m.load_image(inputs, lock, 'runtime')
    builder = m.load_image(inputs, lock, 'builder')
    # Catch private SELinux relabels revoking another container's shared cache.
    reader = subprocess.Popen(['podman', 'run', '--rm', '--pull=never', '--network=none',
        '--security-opt=no-new-privileges', '--entrypoint', 'python3',
        '-v', f'{inputs}:/inputs:ro,z', builder, '-c',
        "import time; from pathlib import Path; "
        "[(Path('/inputs/almalinux-10.asc').read_bytes(), time.sleep(0.1)) for _ in range(30)]"])
    try:
        m.verify_signatures(inputs, runtime)
    finally:
        result = reader.wait(timeout=30)
    if result:
        raise AssertionError('Concurrent verification revoked shared input access')
    print('PASS concurrent verification preserves shared input access')
    package = min((inputs / 'rpm-repository').glob('*.rpm'), key=lambda p: p.stat().st_size)
    with tempfile.TemporaryDirectory(prefix='riverlb-signature-negative-') as folder:
        tree = Path(folder)
        (tree / 'rpm-repository').mkdir()
        dest = tree / 'rpm-repository/package.rpm'
        key = tree / 'almalinux-10.asc'
        shutil.copyfile(package, dest)
        shutil.copyfile(inputs / 'almalinux-10.asc', key)
        m.verify_signatures(tree, runtime)
        print('PASS trusted vendor-signed package: ' + package.name)
        key.write_bytes((inputs / 'toolchain-provenance/hashicorp.asc').read_bytes())
        rejected(tree, runtime, 'package with no trusted signing key rejected')
        shutil.copyfile(inputs / 'almalinux-10.asc', key)
        shutil.copyfile(args.unsigned_rpm, dest)
        rejected(tree, runtime, 'unsigned package with valid digests rejected')
        shutil.copyfile(package, dest)
        with dest.open('r+b') as stream:
            stream.seek(-8, 2)
            stream.write(b'TAMPERED')
        rejected(tree, runtime, 'corrupted package rejected')


if __name__ == '__main__':
    main()
