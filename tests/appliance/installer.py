"""Qualify interactive media on blank disposable disks; never begin installation."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from vnc import Console

if os.environ.get('RIVERLB_VM_TEST') != 'disposable-container':
    raise SystemExit('Use scripts/test-installer.sh')
os.umask(0o077)
OUTPUT = Path('/output')
MEDIA = '/media/riverlb-installer.iso'
FIRMWARE = os.environ.get('RIVERLB_IMAGE_FIRMWARE', 'bios')
if FIRMWARE not in ('bios', 'uefi'):
    raise SystemExit('Invalid installer firmware')


def command(*args):
    subprocess.run(args, check=True)


def shell(serial, script, return_tty=1):
    """Export a guest-only probe through this guest's private serial log."""
    before = serial.stat().st_size if serial.exists() else 0
    console = Console(5920)
    console.chord('ctrl', 'alt', 'f2')
    time.sleep(1)
    encoded = base64.b64encode(script.encode()).decode()
    console.type("python3 -c \"import base64;exec(base64.b64decode('" + encoded + "'))\" > /dev/ttyS0 2>&1\n")
    time.sleep(3)
    console.chord('ctrl', 'alt', f'f{return_tty}')
    console.close()
    return serial.read_bytes()[before:].decode('utf-8', errors='replace')


def console_text(serial):
    return shell(serial, "import pathlib; print(pathlib.Path('/dev/vcs1').read_bytes().decode('ascii', errors='replace'))")


def wait_text(serial, phrase, seconds=180):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        text = console_text(serial)
        if phrase.lower() in text.lower():
            return text
        time.sleep(5)
    raise AssertionError(f'Installer did not display {phrase!r}')


GUI_PROBE = r'''
import configparser, json, os, pathlib
found = False
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        args = entry.joinpath('cmdline').read_bytes().split(b'\0')
        if b'/usr/sbin/anaconda' not in args:
            continue
        env = dict(item.split(b'=', 1) for item in entry.joinpath('environ').read_bytes().split(b'\0') if b'=' in item)
        for key in ('DBUS_SESSION_BUS_ADDRESS', 'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR',
                    'PRODBUILDPATH', 'ANACONDA_PRODUCTNAME', 'ANACONDA_PRODUCTVERSION'):
            if key.encode() in env:
                os.environ[key] = env[key.encode()].decode()
        found = True
        break
    except (OSError, ValueError):
        pass
assert found, 'Anaconda process not found'
import pyatspi
names = []
def visit(item, depth=0):
    if depth > 12 or len(names) > 1000:
        return
    try:
        if item.name:
            names.append(item.name)
        for number in range(item.childCount):
            visit(item.getChildAtIndex(number), depth + 1)
    except Exception:
        pass
visit(pyatspi.Registry.getDesktop(0))
from pyanaconda.core.product import get_product_name
stylesheet = pathlib.Path('/run/install/product/anaconda-gtk.css')
logo = pathlib.Path('/usr/share/anaconda/pixmaps/riverlb-installer.svg')
assert stylesheet.is_file() and logo.is_file(), 'RiverLB runtime stylesheet/logo missing'
assert str(logo) in stylesheet.read_text(), 'Sidebar logo must resolve in product.img'
print('RIVERLB_GUI_PROBE=' + json.dumps(dict(product=get_product_name(), names=names)))
'''


def wait_gui(serial, seconds=180):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        output = shell(serial, GUI_PROBE, return_tty=6)
        match = re.search(r'RIVERLB_GUI_PROBE=(\{[^\n]+\})', output)
        if match:
            result = json.loads(match.group(1))
            labels = ' '.join(result['names']).lower()
            if result['product'] == 'RiverLB' and 'installation destination' in labels:
                assert 'riverlb' in labels, result
                return result
        time.sleep(5)
    raise AssertionError('Branded graphical installation summary was not accessible; inspect screenshots/logs')


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
        '-m', '4096', '-smp', '2', '-display', 'none', '-vga', 'virtio', '-vnc', '127.0.0.1:20',
        '-drive', f'file={disk},format=qcow2,if=virtio', '-cdrom', MEDIA,
        '-boot', 'd', '-serial', f'file:{serial}', '-netdev', 'user,id=net0',
        '-device', 'virtio-net-pci,netdev=net0'] + firmware_args, stdout=log, stderr=log)
    log.close()
    try:
        time.sleep(10)
        console = Console(5920)
        console.screenshot(OUTPUT / (name + '-boot-menu.png'))
        if name == 'graphical':
            console.key('enter')
        else:
            boot_text(console)
        console.close()
        time.sleep(40)
        if name == 'graphical':
            evidence = wait_gui(serial)
            (OUTPUT / 'graphical-accessibility.json').write_text(json.dumps(evidence, indent=2) + '\n')
            console = Console(5920)
            console.screenshot(OUTPUT / 'graphical-summary.png')
            console.close()
        else:
            text = wait_text(serial, 'Installation Destination')
            (OUTPUT / (name + '-storage-selection.txt')).write_text(text)
            assert 'riverlb' in text.lower(), text
            console = Console(5920)
            console.screenshot(OUTPUT / (name + '-storage-selection.png'))
            if name == 'cancel':
                console.type('q\n')
            console.close()
            if name == 'cancel':
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
        command('qemu-img', 'compare', '-f', 'qcow2', '-F', 'raw', str(disk), '/output/blank.raw')
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
