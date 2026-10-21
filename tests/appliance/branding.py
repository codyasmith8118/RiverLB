"""Exercise installer product image, boot configuration and offline runtime gates."""
import gzip
import importlib.util
from pathlib import Path
import stat
import subprocess
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('branding', ROOT / 'appliance/tools/installer-branding.py')
branding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(branding)


def records(data):
    result = {}
    cursor = 0
    while cursor < len(data):
        assert data[cursor:cursor + 6] == b'070701'
        fields = [int(data[cursor + 6 + number * 8:cursor + 14 + number * 8], 16)
                  for number in range(13)]
        size, namesize = fields[6], fields[11]
        start = cursor + 110
        name = data[start:start + namesize - 1].decode()
        start = (start + namesize + 3) // 4 * 4
        if name == 'TRAILER!!!':
            assert size == 0
            return result
        result[name] = (fields[1], data[start:start + size])
        cursor = (start + size + 3) // 4 * 4
    raise AssertionError('Missing cpio trailer')


fixture = '''set default="1"
search --no-floppy --set=root -l 'AlmaLinux-10-2-x86_64-dvd'
menuentry 'Install AlmaLinux 10.2' --class fedora {
 linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=AlmaLinux-10-2-x86_64-dvd inst.ks=hd:LABEL=AlmaLinux-10-2-x86_64-dvd:/installer.ks quiet
 initrdefi /images/pxeboot/initrd.img
}
menuentry 'Test this media & install AlmaLinux 10.2' --class fedora {
 linuxefi /images/pxeboot/vmlinuz rd.live.check inst.ks=hd:LABEL=AlmaLinux-10-2-x86_64-dvd:/installer.ks
 initrdefi /images/pxeboot/initrd.img
}
menuentry 'Install AlmaLinux 10.2 in FIPS mode' {
 linuxefi /images/pxeboot/vmlinuz fips=1
}
submenu 'Troubleshooting -->' {
 menuentry 'Install AlmaLinux 10.2 in basic graphics mode' {
  linuxefi /images/pxeboot/vmlinuz nomodeset inst.ks=hd:LABEL=AlmaLinux-10-2-x86_64-dvd:/installer.ks
  initrdefi /images/pxeboot/initrd.img
 }
 menuentry 'Rescue an AlmaLinux system' {
  linuxefi /images/pxeboot/vmlinuz inst.rescue
 }
}
'''
menu = branding.brand_grub(fixture, 'installer')
assert 'Install RiverLB appliance' in menu and 'Test this media & install RiverLB appliance' in menu
assert 'Install AlmaLinux' not in menu and 'fips=1' not in menu
assert 'inst.text' in menu and 'nomodeset' not in menu and 'rd.live.check' in menu
assert 'inst.rescue' in menu and 'Rescue a RiverLB appliance' in menu
assert 'AlmaLinux' not in '\n'.join(line for line in menu.splitlines() if 'menuentry' in line)
assert menu.count('/installer.ks') == fixture.count('/installer.ks')
assert menu.count('AlmaLinux-10-2-x86_64-dvd') == fixture.count('AlmaLinux-10-2-x86_64-dvd')
assert branding.brand_grub(menu, 'installer') == menu, 'Menu customization must be idempotent'
assert 'Build RiverLB disposable appliance image' in branding.brand_grub(fixture, 'image')
try:
    branding.brand_grub('menuentry "Unknown media" {}\n', 'installer')
except RuntimeError:
    pass
else:
    raise AssertionError('Unsupported menu layout must fail closed')

with tempfile.TemporaryDirectory() as folder:
    stage = (ROOT / 'appliance/branding/release-stage').read_text().strip()
    first, second = Path(folder) / 'first.img', Path(folder) / 'second.img'
    branding.make_product(ROOT / 'appliance/branding', first, '0.1.0')
    branding.make_product(ROOT / 'appliance/branding', second, '0.1.0')
    assert first.read_bytes() == second.read_bytes(), 'Product image must be deterministic'
    image = records(gzip.decompress(first.read_bytes()))
    assert b'Product=RiverLB\n' in image['.buildstamp'][1]
    assert f'IsFinal={stage == "Production"}'.encode() in image['.buildstamp'][1]
    logo = image['usr/share/anaconda/pixmaps/riverlb-installer.svg'][1]
    assert b'AlmaLinux' not in logo and b'0.1.0' in logo and stage.encode() in logo
    assert f'Version=0.1.0 ({stage})'.encode() in image['.buildstamp'][1]
    branding.make_product(ROOT / 'appliance/branding', second, '1.1.9', 'Production')
    production = records(gzip.decompress(second.read_bytes()))
    assert b'IsFinal=True' in production['.buildstamp'][1]
    assert b'1.1.9 (Production)' in production['.buildstamp'][1]
    try:
        branding.make_product(ROOT / 'appliance/branding', second, '1.1.9', 'Invalid\nProduct=Other')
    except SystemExit:
        pass
    else:
        raise AssertionError('Release stage must reject metadata injection')
    assert stat.S_ISDIR(image['usr/share/anaconda/pixmaps'][0])
    assert 'anaconda-gtk.css' not in image, 'A root-level stylesheet is not loaded by this runtime'
    css = image['run/install/product/anaconda-gtk.css'][1].decode()
    assert "url('/usr/share/anaconda/pixmaps/riverlb-installer.svg')" in css
    assert not any(name.endswith(('os-release', 'almalinux-release', '.key')) for name in image)
    try:
        branding.make_product(ROOT / 'appliance/branding', first, '0.1\nProduct=other')
    except SystemExit:
        pass
    else:
        raise AssertionError('Installer metadata cannot accept injected version fields')

# Exercise the actual remaster hooks: EFI branding must occur before FAT
# rebuilding, and ISO config copies must receive the identical customization.
spec = importlib.util.spec_from_file_location('remaster', ROOT / 'appliance/tools/remaster-iso.py')
remaster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remaster)
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    efi = root / 'EFI/BOOT'
    efi.mkdir(parents=True)
    (efi / 'grub.cfg').write_text(fixture)
    bios = root / 'boot/grub2/grub.cfg'
    bios.parent.mkdir(parents=True)
    bios.write_text(fixture)
    with patch.object(remaster, 'original', return_value=subprocess.CompletedProcess([], 0)) as invoke:
        remaster.run(['mkefiboot', '--label=ANACONDA', str(efi), str(root / 'efiboot.img')])
        assert (efi / 'grub.cfg').read_text() == menu
        remaster.run(['xorriso', '-indev', 'fixture.iso', '-outdev', 'result.iso',
                      '-boot_image', 'any', 'replay', '-append_partition', '2', 'GUID',
                      str(root / 'efiboot.img'), '-update', str(bios), '/boot/grub2/grub.cfg'])
        command = invoke.call_args.args[0]
        assert 'partition_table=on' in command and 'grub2_boot_info=on' in command
        assert 'efi_path=--interval:appended_partition_2:all::' in command
        assert (bios.read_text()) == menu

success = subprocess.CompletedProcess([], 0, stdout='\n'.join('squashfs-root/' + name for name in branding.GUI_COMPONENTS))
with patch.object(branding.subprocess, 'run', return_value=success):
    branding.check_runtime('fixture.img')
with patch.object(branding.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='squashfs-root/usr/bin/mutter\n')):
    try:
        branding.check_runtime('fixture.img')
    except SystemExit as error:
        assert 'lacks the offline graphical installer' in str(error)
    else:
        raise AssertionError('Do not ship GUI advertising when runtime components are missing')
common = (ROOT / 'appliance/kickstart/common.ks').read_text()
installer = (ROOT / 'appliance/kickstart/installer.ks').read_text()
commands = [line for line in installer.splitlines() if line.strip() and not line.lstrip().startswith('#')]
assert not any(line.startswith(('clearpart', 'autopart', 'ignoredisk')) for line in commands)
assert '\ntext\n' not in common and '\ntext\n' not in installer
assert '\ntext\n' in (ROOT / 'appliance/kickstart/image.ks').read_text()
assert 'rootpw --lock' in common and 'services --enabled=' in common
assert 'ShowStatus=no' in common and 'system.conf.d/riverlb-console.conf' in common
image_recipe = (ROOT / 'appliance/kickstart/image.ks').read_text()
assert '/etc/NetworkManager/system-connections/' not in common, 'Interactive installs must retain operator network profiles'
assert 'riverlb-bootstrap.nmconnection' not in installer
assert 'rm -f /mnt/sysroot/etc/NetworkManager/system-connections/*' in image_recipe
assert 'method=auto' in image_recipe and 'riverlb-bootstrap.nmconnection' in image_recipe
print('PASS installer branding: deterministic product.img, safe menu edits, offline GUI gate and interactive storage guard')
