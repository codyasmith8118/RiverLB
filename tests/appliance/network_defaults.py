"""Test first-boot NIC selection and hot-added NIC isolation without host changes."""
import configparser
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile

ROOT=Path(__file__).resolve().parents[2]
loader=importlib.machinery.SourceFileLoader('bootstrap_network',str(ROOT/'appliance/firstboot/riverlb-bootstrap-network'))
spec=importlib.util.spec_from_loader(loader.name,loader)
module=importlib.util.module_from_spec(spec)
loader.exec_module(module)
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)
    profile=root/'etc/NetworkManager/system-connections/riverlb-bootstrap.nmconnection'
    profile.parent.mkdir(parents=True)
    recipe=(ROOT/'appliance/kickstart/image.ks').read_text()
    template=recipe.split("<<'PROFILE'\n",1)[1].split('\nPROFILE',1)[0]
    assert 'autoconnect=false' in template
    profile.write_text(template)
    def nic(name,mac,physical=True):
        path=root/'sys/class/net'/name
        path.mkdir(parents=True)
        if physical:(path/'device').mkdir()
        (path/'type').write_text('1')
        (path/'address').write_text(mac)
    nic('eth0','52:54:00:01:02:03')
    nic('eth1','52:54:00:01:02:04')
    nic('aaa-vlan','52:54:00:01:02:05',False)
    module.bind(root)
    config=configparser.ConfigParser()
    config.read(profile)
    assert config['connection']['interface-name']=='eth0'
    assert config['connection']['autoconnect']=='true'
    assert config['ethernet']['mac-address']=='52:54:00:01:02:03'
    assert config['ipv4']['method']=='auto'
    assert profile.stat().st_mode & 0o777==0o600
    bound=profile.read_bytes()
    nic('aaa-new-nic','52:54:00:01:02:06')
    module.bind(root)
    assert profile.read_bytes()==bound,'Adding a NIC must not move bootstrap DHCP'
    profile.unlink()
    module.bind(root)
    assert not profile.exists(),'Interactive static network profiles must not be replaced'
assert 'no-auto-default=*' in (ROOT/'appliance/firstboot/riverlb-network-defaults.conf').read_text()
service=(ROOT/'appliance/firstboot/riverlb-bootstrap-network.service').read_text()
assert 'Before=NetworkManager.service' in service
assert 'systemctl enable riverlb-bootstrap-network.service' in (ROOT/'appliance/kickstart/common.ks').read_text()
print('PASS network defaults: one bound bootstrap NIC, hot-add isolation, private profile, interactive settings preserved')
