"""Qualify interactive media on blank disposable disks; never begin installation."""
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import zlib
import shutil
import subprocess
import sys
import time
from vnc import Console

OUTPUT = Path('/output')
MEDIA = '/media/riverlb-installer.iso'
FIRMWARE = os.environ.get('RIVERLB_IMAGE_FIRMWARE', 'bios')
if FIRMWARE not in ('bios', 'uefi'):
    raise SystemExit('Invalid installer firmware')


def command(*args):
    subprocess.run(args, check=True)


class InstallerFailure(Exception):
    pass


CURRENT_CASE = 'initialization'
CHECKPOINT = 'initialization'
GUI_REASONS = {'anaconda-not-found', 'gui-session-bus-missing', 'accessibility-unavailable',
    'accessibility-query-failed', 'branding-assets-missing', 'branding-stylesheet-invalid', 'gui-probe-error'}


def checkpoint(name):
    global CHECKPOINT
    CHECKPOINT = name


def probe_command(script, marker, serial_device='/dev/ttyS0'):
    if not re.fullmatch(r'RIVERLB_PROBE_DONE_[a-f0-9]{16}', marker):
        raise ValueError('Invalid probe marker')
    # Lowercase hex follows the passing boot fixture: avoid sustained shifted
    # key sequences through firmware/installer keyboard state.
    encoded = zlib.compress(script.encode()).hex()
    code = "import zlib;exec(zlib.decompress(bytes.fromhex('" + encoded + "')))"
    sink = shlex.quote(str(serial_device))
    return 'timeout -k 5 30 python3 -c ' + shlex.quote(code) + ' > ' + sink + " 2>&1; printf '\\n" + marker + "\\n' >> " + sink + '\n'


def shell(serial, script, return_tty=1, ready_seconds=180):
    """Wait for completion; never discard a slow probe's late serial response."""
    before = serial.stat().st_size if serial.exists() else 0
    marker = 'RIVERLB_PROBE_DONE_' + secrets.token_hex(8)
    console = Console(5920)
    try:
        # Verify a responsive shell before typing a long script. A fixed boot
        # delay alone cannot establish that the installer has started TTY2.
        ready = 'riverlb_shell_ready_' + secrets.token_hex(8)
        end = time.monotonic() + ready_seconds
        while True:
            # Starting the graphical session can switch away from TTY2.
            console.chord('ctrl', 'alt', 'f2')
            time.sleep(1)
            console.type('printf ' + ready + ' > /dev/ttyS0\n')
            deadline = min(end, time.monotonic() + 5)
            data = ''
            while time.monotonic() < deadline:
                data = serial.read_bytes()[before:].decode('utf-8', errors='replace') if serial.exists() else ''
                if ready in data:
                    break
                time.sleep(0.2)
            if ready in data:
                break
            if time.monotonic() >= end:
                raise InstallerFailure('shell-not-ready')
        before = serial.stat().st_size
        console.type(probe_command(script, marker))
        end = time.monotonic() + 45
        while time.monotonic() < end:
            output = serial.read_bytes()[before:].decode('utf-8', errors='replace') if serial.exists() else ''
            if marker in output:
                return output.split(marker, 1)[0]
            time.sleep(0.2)
        raise InstallerFailure('probe-timeout')
    finally:
        try:
            console.chord('ctrl', 'alt', f'f{return_tty}')
        finally:
            console.close()


def console_text(serial):
    return shell(serial, "import pathlib; print(pathlib.Path('/dev/vcs1').read_bytes().decode('ascii', errors='replace'))")


def wait_text(serial, phrase, seconds=180):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        text = console_text(serial)
        if phrase.lower() in text.lower():
            return text
        time.sleep(5)
    raise InstallerFailure('text-screen-not-ready')


GUI_PROBE = Path(__file__).with_name('installer_probe.py').read_text()


def wait_gui(serial, seconds=180):
    end = time.monotonic() + seconds
    reason = 'gui-probe-no-result'
    while time.monotonic() < end:
        output = shell(serial, GUI_PROBE, return_tty=6)
        stages = re.findall(r'RIVERLB_GUI_STAGE=([a-z-]+)', output)
        if stages and stages[-1] in ('environment', 'accessibility-import', 'accessibility-query', 'product'):
            reason = 'gui-timeout-' + stages[-1]
        failure = re.search(r'RIVERLB_GUI_FAILURE=([a-z-]+)', output)
        if failure and failure.group(1) in GUI_REASONS:
            reason = failure.group(1)
        match = re.search(r'RIVERLB_GUI_PROBE=(\{[^\n]+\})', output)
        if match:
            result = json.loads(match.group(1))
            labels = ' '.join(result['names']).lower()
            reason = 'product-name-mismatch' if result['product'] != 'RiverLB' else 'installation-destination-unavailable'
            if result['product'] == 'RiverLB' and 'installation destination' in labels:
                assert 'riverlb' in labels, result
                return result
        time.sleep(5)
    raise InstallerFailure(reason)


def boot_text(console):
    # Enter GRUB's command line on this ISO, using its preserved volume label.
    report = subprocess.run(['xorriso', '-indev', MEDIA, '-pvd_info'], check=True,
                            capture_output=True, text=True)
    match = re.search(r"Volume Id\s*:\s*'?([A-Za-z0-9_.-]+)'?", report.stdout + report.stderr)
    assert match, report.stdout + report.stderr
    label = match.group(1)
    console.key('c')
    console.type(f'linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL={label} inst.ks=hd:LABEL={label}:/installer.ks inst.text\n')
    console.type('initrd /images/pxeboot/initrd.img\nboot\n')


def case(name):
    global CURRENT_CASE
    CURRENT_CASE = name
    checkpoint('guest-start')
    disk = OUTPUT / (name + '.qcow2')
    serial = OUTPUT / (name + '.serial.log')
    command('qemu-img', 'create', '-f', 'qcow2', str(disk), '16G')
    log = (OUTPUT / (name + '.qemu.log')).open('w')
    firmware_args = []
    if FIRMWARE == 'uefi':
        nvram = OUTPUT / (name + '.efivars.fd')
        shutil.copyfile('/usr/share/edk2/ovmf/OVMF_VARS.fd', nvram)
        firmware_args = ['-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
                         '-drive', f'if=pflash,format=raw,unit=1,file={nvram}']
    guest = subprocess.Popen(['/usr/libexec/qemu-kvm', '-machine', 'accel=kvm', '-cpu', 'host',
        '-m', '4096', '-smp', '2', '-display', 'none', '-vga', 'std', '-vnc', '127.0.0.1:20',
        '-drive', f'file={disk},format=qcow2,if=virtio', '-cdrom', MEDIA,
        '-boot', 'd', '-serial', f'file:{serial}', '-netdev', 'user,id=net0',
        '-device', 'virtio-net-pci,netdev=net0'] + firmware_args, stdout=log, stderr=log)
    log.close()
    try:
        time.sleep(10)
        if guest.poll() is not None:
            raise InstallerFailure('guest-exited')
        checkpoint('boot-menu')
        console = Console(5920)
        console.screenshot(OUTPUT / (name + '-boot-menu.png'))
        if name == 'graphical':
            console.key('enter')
        else:
            boot_text(console)
        console.close()
        time.sleep(40)
        if name == 'graphical':
            checkpoint('graphical-summary')
            evidence = wait_gui(serial)
            (OUTPUT / 'graphical-accessibility.json').write_text(json.dumps(evidence, indent=2) + '\n')
            console = Console(5920)
            console.screenshot(OUTPUT / 'graphical-summary.png')
            console.close()
        else:
            checkpoint('storage-selection')
            text = wait_text(serial, 'Installation Destination')
            (OUTPUT / (name + '-storage-selection.txt')).write_text(text)
            assert 'riverlb' in text.lower(), text
            console = Console(5920)
            console.screenshot(OUTPUT / (name + '-storage-selection.png'))
            if name == 'cancel':
                console.type('q\n')
            console.close()
            if name == 'cancel':
                checkpoint('cancel-confirmation')
                wait_text(serial, 'Do you really want to quit?')
                console = Console(5920)
                console.type('yes\n')
                console.close()
                # Native Quit may reboot into the medium. Stop this disposable
                # VM after allowing Quit to run; disk comparison is the safety gate.
                time.sleep(15)
                (OUTPUT / 'cancel-quit-requested.txt').write_text('Native Anaconda Quit confirmed before any installation was begun.\n')
        if guest.poll() is None:
            guest.terminate()
            guest.wait(timeout=10)
        checkpoint('blank-disk-comparison')
        try:
            command('qemu-img', 'compare', '-f', 'qcow2', '-F', 'raw', str(disk), '/output/blank.raw')
        except subprocess.CalledProcessError:
            raise InstallerFailure('disk-comparison-failed') from None
    finally:
        if guest.poll() is None:
            try:
                console = Console(5920)
                console.screenshot(OUTPUT / (name + '-failure.png'))
                console.close()
            except Exception:
                pass
            guest.terminate()
            try:
                guest.wait(timeout=10)
            except subprocess.TimeoutExpired:
                guest.kill()
                guest.wait(timeout=10)


def main():
    if os.environ.get('RIVERLB_VM_TEST') != 'disposable-container':
        raise SystemExit('Use scripts/test-installer.sh')
    os.umask(0o077)
    try:
        command('qemu-img', 'create', '-f', 'raw', '/output/blank.raw', '16G')
        selected = sys.argv[1:]
        if selected and selected not in (['graphical'], ['cancel'], ['select']):
            raise SystemExit('Use graphical, cancel, select, or no argument for all cases')
        for name in selected or ['graphical', 'select', 'cancel']:
            case(name)
            print(f'Interactive installer {name} case passed', flush=True)
        if not selected:
            (OUTPUT / 'report.json').write_text(json.dumps(dict(status='passed', firmware=FIRMWARE, tests=[
                'RiverLB graphical summary and accessible installation destination',
                'text-console storage selection', 'native text Quit requested before installation',
                'blank disks unchanged before storage confirmation']), indent=2) + '\n')
        print('Interactive installer startup, storage and untouched-disk checks passed', flush=True)
    except Exception as error:
        reason = str(error) if isinstance(error, InstallerFailure) else 'fixture-error'
        (OUTPUT / 'failure.json').write_text(json.dumps(dict(schema=1, firmware=FIRMWARE,
            case=CURRENT_CASE, checkpoint=CHECKPOINT, reason=reason)) + '\n')
        raise


if __name__ == '__main__':
    main()
