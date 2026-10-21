"""Exercise installed presentation using a temporary filesystem, never the host."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('installed_branding', str(ROOT / 'appliance/firstboot/riverlb-brand-appliance'))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for folder in ('etc/default', 'usr/lib', 'boot/loader/entries'):
        (root / folder).mkdir(parents=True)
    original = 'NAME="AlmaLinux"\nPRETTY_NAME="AlmaLinux 10.2"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.2"\n'
    (root / 'usr/lib/os-release').write_text(original)
    (root / 'etc/os-release').symlink_to('../usr/lib/os-release')
    (root / 'etc/default/grub').write_text('GRUB_DISTRIBUTOR="AlmaLinux"\nGRUB_TIMEOUT=5\n')
    entry = root / 'boot/loader/entries/kernel.conf'
    entry.write_text('title AlmaLinux 10.2\nversion 6.12.0-test\nlinux /vmlinuz-test\noptions root=UUID=test ro\n')
    module.brand(root, '1.1.9', 'Pre-production')
    release = (root / 'etc/os-release').read_text()
    assert 'PRETTY_NAME="RiverLB 1.1.9 · Pre-production"' in release
    assert 'ID="almalinux"' in release and 'VERSION_ID="10.2"' in release
    assert (root / 'usr/lib/os-release').read_text() == original
    assert 'AlmaLinux' not in (root / 'etc/issue').read_text()
    assert (root / 'etc/issue').read_text() == (root / 'etc/issue.net').read_text()
    assert 'GRUB_DISTRIBUTOR="RiverLB"' in (root / 'etc/default/grub').read_text()
    assert 'GRUB_TIMEOUT=5' in (root / 'etc/default/grub').read_text()
    assert 'title RiverLB 1.1.9 · Pre-production (6.12.0-test)' in entry.read_text()
    assert 'options root=UUID=test ro' in entry.read_text()
    module.brand(root, '1.2.0', 'Production')
    assert (root / 'etc/os-release').read_text().count('PRETTY_NAME=') == 1
    assert 'RiverLB 1.2.0 · Production' in entry.read_text()
print('PASS installed branding: version/stage, console and boot titles; vendor identity and kernel arguments preserved')
