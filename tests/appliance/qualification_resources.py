"""Real cgroup OOM and interrupted-container cleanup probes; no KVM or host disks."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qualification', ROOT / 'scripts/qualify-appliance.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    env = dict(os.environ)
    m.identity(env)
    lock = json.loads((ROOT / 'packaging/build-inputs.lock.json').read_text())
    image = lock['images']['builder']['id']
    subprocess.run(['python3', str(ROOT / 'scripts/build-inputs.py'), 'image', 'builder'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
    created = []
    with tempfile.TemporaryDirectory(prefix='riverlb-resource-probe-') as private:
        root = Path(private)
        owner = m.fresh_workspace(root, env)
        def start(label):
            result = subprocess.check_output(['podman', 'run', '-d', '--pull=never', '--network=none',
                '--security-opt=no-new-privileges', '--label', f'{m.LABEL}={label}',
                '--memory=64m', '--memory-swap=64m', '--cpus=1', '--pids-limit=32',
                '--entrypoint', '/bin/bash', image, '-c', 'sleep 120'], text=True).strip()
            if not re.fullmatch('[a-f0-9]{64}', result):
                raise AssertionError('Invalid probe container identity')
            created.append(result)
            return result
        try:
            owned = start(owner['job'])
            control = start('control-' + owner['job'])
            result = subprocess.run(['podman', 'run', '--rm', '--pull=never', '--network=none',
                '--security-opt=no-new-privileges', '--label', f'{m.LABEL}={owner["job"]}',
                '--memory=64m', '--memory-swap=64m', '--cpus=1', '--pids-limit=32',
                '--entrypoint', 'python3', image, '-c', 'bytearray(512 * 1024 * 1024)'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            if result.returncode != 137:
                raise AssertionError('Kernel memory limit did not terminate the OOM probe')
            m.cleanup(root, env)
            if subprocess.run(['podman', 'container', 'exists', owned], check=False).returncode == 0:
                raise AssertionError('Interrupted owned container survived cleanup')
            info = json.loads(subprocess.check_output(['podman', 'inspect', control]))[0]
            if not info['State']['Running']:
                raise AssertionError('Cleanup interfered with the separately owned control')
            print('PASS kernel-enforced memory cap, interrupted container removal and control preservation')
        finally:
            # These IDs were created by this probe, including its control sentinel.
            for container in created:
                subprocess.run(['podman', 'rm', '--force', '--time', '5', container], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
