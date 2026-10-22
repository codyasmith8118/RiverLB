#!/usr/bin/env python3
"""Admit and bound disposable hosted KVM jobs; publish only fixed-schema evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'codyasmith8118/RiverLB'
TRUSTED_REFS = {'refs/heads/release-2.0'}
OWNER = '.qualification-owner.json'
EVIDENCE = 'qualification-evidence'
LABEL = 'io.riverlb.qualification'
BOOT_TESTS = {'console setup', 'verified HTTPS login', 'real firewalld VIP TCP forwarding',
    'clean shutdown', 'reboot configuration/account/certificate persistence',
    'persisted traffic statistics', 'independent clone certificates and machine IDs',
    'SELinux enforcing', 'SSH disabled', 'console recovery login', 'private database permissions'}
INSTALLER_TESTS = {'RiverLB graphical summary and accessible installation destination',
    'text-console storage selection', 'native text Quit requested before installation',
    'blank disks unchanged before storage confirmation'}


class Rejected(Exception):
    pass


def identity(env):
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise Rejected('manual-dispatch-required')
    if env.get('GITHUB_REPOSITORY') != REPOSITORY or env.get('GITHUB_REF') not in TRUSTED_REFS:
        raise Rejected('untrusted-repository-or-ref')
    if env.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise Rejected('disposable-hosted-runner-required')
    if not re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', '')):
        raise Rejected('invalid-source-identity')
    if any(not re.fullmatch(r'[0-9]+', env.get(key, '')) for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')):
        raise Rejected('invalid-run-identity')
    firmware = env.get('RIVERLB_IMAGE_FIRMWARE', '')
    if firmware not in ('bios', 'uefi'):
        raise Rejected('invalid-firmware')
    return firmware


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save_report(root, report):
    folder = root / 'dist' / EVIDENCE
    if (root / 'dist').is_symlink() or folder.is_symlink():
        raise Rejected('unsafe-evidence-directory')
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / 'report.json'
    if path.is_symlink():
        raise Rejected('unsafe-evidence-file')
    temporary = folder / 'report.partial'
    with temporary.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    os.replace(temporary, path)
    (folder / 'SHA256SUMS').write_text(sha256(path) + '  report.json\n')


def fresh_workspace(root, env):
    firmware = identity(env)
    dist = root / 'dist'
    # Never adopt an existing developer output directory or follow a symlink.
    if dist.exists() or dist.is_symlink():
        raise Rejected('workspace-not-fresh')
    dist.mkdir(mode=0o700)
    job = f"{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}-{firmware}-{secrets.token_hex(8)}"
    marker = dict(schema=1, job=job, source=env['GITHUB_SHA'])
    (dist / OWNER).write_text(json.dumps(marker))
    return marker


def owned_workspace(root, env):
    identity(env)
    dist = root / 'dist'
    marker = dist / OWNER
    if dist.is_symlink() or marker.is_symlink() or not marker.is_file():
        raise Rejected('workspace-ownership-missing')
    data = json.loads(marker.read_text())
    prefix = f"{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}-{env['RIVERLB_IMAGE_FIRMWARE']}-"
    if (data.get('schema') != 1 or data.get('source') != env['GITHUB_SHA']
            or not re.fullmatch(re.escape(prefix) + '[a-f0-9]{16}', data.get('job', ''))):
        raise Rejected('workspace-ownership-mismatch')
    return data


def resources(root, minimum_gib=40, measured=None):
    free = shutil.disk_usage(root).free
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:'))) * 1024
    result = dict(free_disk_bytes=free, available_memory_bytes=memory,
                  required_disk_bytes=minimum_gib * 1024 ** 3, required_memory_bytes=6 * 1024 ** 3,
                  logical_cpus=os.cpu_count() or 0, required_logical_cpus=2)
    if measured is not None:
        measured.update(result)
    if free < result['required_disk_bytes']:
        raise Rejected('insufficient-disk')
    if memory < result['required_memory_bytes']:
        raise Rejected('insufficient-memory')
    if result['logical_cpus'] < result['required_logical_cpus']:
        raise Rejected('insufficient-cpu')
    if not Path('/dev/kvm').is_char_device() or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise Rejected('kvm-unavailable')
    return result


def stop_process(process):
    # Descendants may outlive the stage leader and retain its output pipe.
    # Always stop the owned group, even after the leader has already exited.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def bounded_command(argv, log, env, timeout):
    # Private bounded logs are never uploaded or echoed into Actions output.
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=env, start_new_session=True, bufsize=0)
    def drain():
        remaining = 1024 * 1024
        with log.open('xb') as output:
            while chunk := process.stdout.read(65536):
                output.write(chunk[:remaining])
                remaining = max(0, remaining - len(chunk))
    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=timeout)
        if code:
            raise Rejected('command-failed')
    except subprocess.TimeoutExpired:
        raise Rejected('stage-timeout') from None
    finally:
        stop_process(process)
        reader.join(timeout=15)
        process.stdout.close()


def fixture_report(path, firmware, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise Rejected('fixture-report-missing-or-unsafe')
    data = json.loads(path.read_text())
    if (set(data) != {'status', 'firmware', 'tests'} or data['status'] != 'passed'
            or data['firmware'] != firmware or not isinstance(data['tests'], list)
            or any(not isinstance(item, str) for item in data['tests'])
            or set(data['tests']) != expected or len(data['tests']) != len(expected)):
        raise Rejected('fixture-report-invalid')
    # Rebuild the public object from constants, never forward arbitrary guest text.
    return dict(status='passed', firmware=firmware, tests=sorted(expected))


def cleanup(root, env, run=subprocess.run):
    marker = owned_workspace(root, env)
    found = run(['podman', 'ps', '-a', '--no-trunc', '--filter', f'label={LABEL}={marker["job"]}',
                 '--format', '{{.ID}}'], check=True, capture_output=True, text=True)
    for container in found.stdout.splitlines():
        if not re.fullmatch('[a-f0-9]{64}', container):
            raise Rejected('invalid-container-identity')
        info = json.loads(run(['podman', 'inspect', container], check=True,
                             capture_output=True, text=True).stdout)[0]
        if info.get('Config', {}).get('Labels', {}).get(LABEL) != marker['job']:
            raise Rejected('container-ownership-mismatch')
        run(['podman', 'rm', '--force', '--time', '15', container], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in (root / 'dist').iterdir():
        if path.name in (EVIDENCE, OWNER):
            continue
        if path.is_symlink() or not path.is_dir():
            path.unlink()
        else:
            shutil.rmtree(path)
    (root / 'dist' / OWNER).unlink()


def qualify(root, env, report):
    firmware = identity(env)
    marker = owned_workspace(root, env)
    if report.get('status') != 'ready' or report.get('source') != env['GITHUB_SHA'] or report.get('firmware') != firmware:
        raise Rejected('preflight-not-ready')
    report['stage'] = 'candidate-identity'
    manifest_path = root / 'dist/rpm/build-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    lock_path = root / 'packaging/build-inputs.lock.json'
    lock = json.loads(lock_path.read_text())
    if (manifest['commit'] != env['GITHUB_SHA'] or manifest['dirty']
            or manifest.get('build_inputs') != lock):
        raise Rejected('candidate-source-or-input-mismatch')
    report['inputs'] = dict(lock_sha256=sha256(lock_path), snapshot_sha256=lock['sha256'],
                            rpm_manifest_sha256=sha256(manifest_path), tools_image=lock['images']['tools']['id'])
    child_env = dict(env, RIVERLB_QUALIFICATION_ID=marker['job'], RIVERLB_IMAGE_ACCELERATOR='kvm')
    stages = [
        ('resource-controls', ['python3', 'tests/appliance/qualification_resources.py'], 900),
        ('base-media', ['python3', 'scripts/fetch-base-iso.py'], 900),
        ('image-media', ['bash', 'scripts/build-iso.sh', 'BASE', 'HASH', 'image'], 900),
        ('image-structure', ['bash', 'scripts/test-iso.sh', 'image'], 300),
        ('disk-build', ['bash', 'scripts/build-image.sh'], 5400),
        ('boot-suite', ['bash', 'scripts/test-image.sh'], 1800),
        ('installer-media', ['bash', 'scripts/build-iso.sh', 'BASE', 'HASH', 'installer'], 900),
        ('installer-structure', ['bash', 'scripts/test-iso.sh', 'installer'], 300),
        ('installer-suite', ['bash', 'scripts/test-installer.sh'], 1800)]
    with tempfile.TemporaryDirectory(prefix='riverlb-qualification-private-') as private:
        child_env['TMPDIR'] = private
        base = json.loads((root / 'appliance/base-media.json').read_text())
        for name, args, timeout in stages:
            report['stage'] = name
            args = [str(root / 'dist/base' / base['filename']) if a == 'BASE' else base['sha256'] if a == 'HASH' else a for a in args]
            report.setdefault('commands', {})[name] = dict(argv=args, timeout_seconds=timeout)
            save_report(root, report)
            print('Qualification stage: ' + name, flush=True)
            bounded_command(args, Path(private) / (name + '.log'), child_env, timeout)
            if name in ('image-media', 'installer-media'):
                mode = 'image' if name == 'image-media' else 'installer'
                artifact = f'riverlb-{mode}.iso'
                report.setdefault('artifacts', {})[artifact] = sha256(root / 'dist/iso' / artifact)
            elif name == 'disk-build':
                image = 'image-uefi' if firmware == 'uefi' else 'image'
                report.setdefault('artifacts', {}).update({artifact: sha256(root / 'dist' / image / artifact)
                    for artifact in ('riverlb.qcow2', 'riverlb.raw')})
            elif name == 'boot-suite':
                boot = 'test-vm-uefi' if firmware == 'uefi' else 'test-vm'
                report['boot'] = fixture_report(root / 'dist' / boot / 'report.json', firmware, BOOT_TESTS)
            elif name == 'installer-suite':
                report['installer'] = fixture_report(root / 'dist/test-installer-vm/report.json', firmware, INSTALLER_TESTS)
            report['stages'][name] = 'passed'
            save_report(root, report)
    report.update(status='passed', stage='complete')


def main():
    os.umask(0o077)
    os.chdir(ROOT)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['admit', 'preflight', 'run', 'cleanup'])
    parser.add_argument('--negative', action='store_true', help='Exercise real disk preflight rejection; never qualify a guest')
    args = parser.parse_args()
    env = dict(os.environ)
    report = dict(schema=1, status='not-run', stage=args.command, stages={}, cleanup='pending')
    path = ROOT / 'dist' / EVIDENCE / 'report.json'
    if args.command in ('run', 'cleanup') and path.is_file() and not path.is_symlink():
        report = json.loads(path.read_text())
    def interrupted(_signum, _frame):
        raise Rejected('job-interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    result = 0
    may_save = False
    try:
        firmware = identity(env)
        report.update(firmware=firmware, source=env['GITHUB_SHA'], run_id=env['GITHUB_RUN_ID'],
                      run_attempt=env['GITHUB_RUN_ATTEMPT'])
        if args.command == 'admit':
            print('Trusted manual qualification ref admitted')
            return
        if args.command in ('run', 'cleanup'):
            if (ROOT / 'dist' / OWNER).exists():
                owned_workspace(ROOT, env)
                may_save = True
        if args.command == 'preflight':
            actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            if actual != env['GITHUB_SHA'] or subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no']):
                raise Rejected('checkout-source-mismatch')
            fresh_workspace(ROOT, env)
            may_save = True
            report['platform'] = dict(kernel=os.uname().release, runner_image=os.environ.get('ImageVersion', 'unknown'))
            resources(ROOT, 1000000 if args.negative else 40, report.setdefault('resources', {}))
            report['status'] = 'ready'
        elif args.command == 'run':
            qualify(ROOT, env, report)
        elif args.command == 'cleanup':
            if not (ROOT / 'dist' / OWNER).exists():
                report['cleanup'] = 'not-initialized'
            else:
                cleanup(ROOT, env)
                report['cleanup'] = 'passed'
    except Rejected as error:
        report.update(status='rejected' if args.command in ('admit', 'preflight') else 'failed', reason=str(error))
        print('Qualification rejected/failed: ' + str(error), flush=True)
        result = 1
        if args.negative and args.command == 'preflight' and str(error) == 'insufficient-disk':
            report['expected_negative'] = True
            result = 0
    except Exception:
        # Exception text, command output, guest serial and environment are private.
        report.update(status='failed', reason='internal-stage-error')
        print('Qualification failed; inspect stage and documented recovery instructions', flush=True)
        result = 1
    finally:
        if args.command != 'admit' and may_save:
            report['finished_at_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            save_report(ROOT, report)
    raise SystemExit(result)


if __name__ == '__main__':
    main()
