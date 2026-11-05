"""Fixed public platform identity; unexpected tool/profile data is never forwarded."""
import json
from pathlib import Path
import re
import subprocess


def reference(path):
    value=json.loads(Path(path).read_text())
    fields={'schema','architecture','accelerator','cpu_model','machine_default','qemu_package',
            'firmware_package','firmware','cpus','memory_mib','disk_gib','disk_interface',
            'nic_model','boot_nics','installer_nics'}
    if (set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or value['architecture']!='x86_64' or value['accelerator']!='kvm'
            or value['cpu_model']!='host' or value['firmware']!=['bios','uefi']
            or any(type(value[k]) is not int or value[k]!=v for k,v in
                   {'cpus':2,'memory_mib':4096,'disk_gib':16,'boot_nics':2,'installer_nics':1}.items())
            or value['disk_interface']!='virtio' or value['nic_model']!='virtio-net-pci'
            or any(not isinstance(value[k],str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',value[k])
                   for k in ['machine_default','qemu_package','firmware_package'])):
        raise ValueError('Invalid declared KVM reference profile')
    return value


def validate(actual, expected):
    if (type(actual) is not dict or set(actual)!=set(expected)
            or any(type(actual[k]) is not type(v) or actual[k]!=v for k,v in expected.items())):
        raise ValueError('Measured KVM tools/profile differs from declared reference')
    # Reconstruct from the checked-in declaration; never publish arbitrary output.
    return dict(expected)


def measure(expected):
    packages=subprocess.check_output(['rpm','-q','qemu-kvm-core','edk2-ovmf'],text=True,timeout=10).splitlines()
    machines=subprocess.check_output(['/usr/libexec/qemu-kvm','-machine','help'],text=True,timeout=10)
    defaults=[line.split()[0] for line in machines.splitlines() if '(default)' in line]
    if packages!=[expected['qemu_package'],expected['firmware_package']] or defaults!=[expected['machine_default']]:
        raise ValueError('Pinned virtualization packages/default machine differ from declared reference')
    return dict(expected)
