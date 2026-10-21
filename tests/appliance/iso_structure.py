"""Structural ISO checks. Does not substitute for firmware boot/install tests."""
import base64
import hashlib
import json
import configparser
import gzip
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

iso, mode = Path(sys.argv[1]), sys.argv[2]
assert mode in ('installer', 'image')

def run(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

report = run('xorriso', '-indev', str(iso), '-report_el_torito', 'plain')
assert re.search(r'El Torito boot img :\s+1\s+BIOS\s+y', report), report
assert re.search(r'El Torito boot img :\s+2\s+UEFI\s+y', report), report
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    for source, target in [(f'/{mode}.ks', 'mode.ks'), ('/riverlb-common.ks', 'common.ks'),
                           ('/riverlb-packages.tar', 'packages.tar'), ('/EFI/BOOT/grub.cfg', 'efi.cfg'),
                           ('/boot/grub2/grub.cfg', 'bios.cfg'),
                           ('/images/product.img', 'product.img'), ('/update-trust.json', 'update-trust.json')]:
        run('xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract', source, str(root / target))
    trust_bytes = (root / 'update-trust.json').read_bytes()
    trust = json.loads(trust_bytes)
    assert trust['format'] == 1 and len(trust['keys']) == 1
    public = base64.b64decode(trust['keys'][0]['public_key'], validate=True)
    assert len(public) == 32 and trust['keys'][0]['id'] == hashlib.sha256(public).hexdigest()
    for config in ('efi.cfg', 'bios.cfg'):
        menu = (root / config).read_text()
        assert f':/{mode}.ks' in menu
        assert 'RiverLB appliance' in menu
        assert 'Install AlmaLinux' not in menu and 'fips=1' not in menu
        if mode == 'installer':
            assert 'Install RiverLB appliance (text console)' in menu and 'inst.text' in menu
    ks = (root / 'mode.ks').read_text()
    common = (root / 'common.ks').read_text()
    assert '/etc/NetworkManager/system-connections/' not in common, 'Shared recipe must preserve installed networking'
    if mode == 'installer':
        commands = [line for line in ks.splitlines() if not line.lstrip().startswith('#')]
        assert not any(line.startswith(('clearpart', 'autopart', 'ignoredisk')) for line in commands)
        assert '\ntext\n' not in ks and '\ntext\n' not in common
        assert 'riverlb-bootstrap.nmconnection' not in ks
    else:
        assert 'clearpart --all --initlabel --drives=vda' in ks
        assert 'shutdown' in ks
        assert 'rm -f /mnt/sysroot/etc/NetworkManager/system-connections/*' in ks
        assert 'riverlb-bootstrap.nmconnection' in ks
    assert 'rootpw --lock' in common
    assert 'systemctl enable riverlb-firstboot.service' in common
    assert 'ssh_host_*' in common
    # Read archive members to stdout; never extract an arbitrary archive to host paths.
    archive = gzip.decompress((root / 'product.img').read_bytes())
    def product_file(name):
        return subprocess.run(['cpio', '-i', '--quiet', '--to-stdout', name], input=archive,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    product = configparser.ConfigParser()
    product.read_string(product_file('.buildstamp').decode())
    assert product['Main']['Product'] == 'RiverLB'
    assert product['Main']['Version'] and product['Main']['Variant'] == 'Appliance'
    logo = product_file('usr/share/anaconda/pixmaps/riverlb-installer.svg')
    assert b'RiverLB' in logo and b'AlmaLinux' not in logo
    assert b'#102432' in product_file('run/install/product/anaconda-gtk.css')
    expanded = root / 'expanded.ks'
    expanded.write_text(ks.replace('%include /run/install/repo/riverlb-common.ks', common))
    run('ksvalidator', '-v', 'RHEL10', str(expanded))
    with tarfile.open(root / 'packages.tar') as archive:
        members = archive.getmembers()
        assert len(members) > 3, 'ISO must include the HA dependency closure'
        assert all((m.isfile() or m.isdir()) and m.name.startswith('./') and '..' not in Path(m.name).parts and not m.issym() and not m.islnk() for m in members)
        assert any(m.name=='./ha-dependencies/repodata/repomd.xml' for m in members)
        main = [m for m in members if re.fullmatch(r'./riverlb-[0-9].*\.rpm', m.name)]
        assert len(main) == 1, 'Expected exactly one main RiverLB RPM'
        package = root / 'riverlb.rpm'
        package.write_bytes(archive.extractfile(main[0]).read())
        payload = subprocess.check_output(['rpm2cpio', str(package)])
        embedded = subprocess.run(['cpio', '-i', '--quiet', '--to-stdout',
                                  './etc/riverlb-updater/update-trust.json'], input=payload,
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        assert embedded == trust_bytes, 'Installed RPM trust must match the ISO public key'
        listing = run('rpm', '-qpl', str(package))
        assert 'publisher.pem' not in listing and 'private.key' not in listing
        names=[Path(m.name).name for m in members if m.isfile()]
        for package in ('riverlb-ha-','pacemaker-','corosync-','pcs-','resource-agents-',
                        'fence-agents-all-','fence-agents-aws-','fence-agents-azure-arm-',
                        'fence-agents-gce-','fence-agents-openstack-',
                        'fence-agents-nutanix-ahv-','fence-agents-virsh-',
                        'ha-cloud-support-','python3-setuptools-','openssh-server-'):
            assert any(name.startswith(package) for name in names),package
    # Inspect the FAT filesystem actually referenced by the EFI boot record.
    run('xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract_boot_images', str(root / 'boot'))
    candidates = list((root / 'boot').glob('*uefi*'))
    assert len(candidates) == 1, list((root / 'boot').iterdir())
    firmware_config = run('mtype', '-i', str(candidates[0]), '::/EFI/BOOT/grub.cfg')
    assert f':/{mode}.ks' in firmware_config
    assert 'RiverLB appliance' in firmware_config and 'Install AlmaLinux' not in firmware_config
    if mode == 'installer':
        assert 'inst.text' in firmware_config
    run('mdir', '-i', str(candidates[0]), '::/EFI/BOOT/BOOTX64.EFI')
print(f'{mode} ISO: BIOS/UEFI records, RiverLB menus/product identity, payload and Kickstart checks passed')
