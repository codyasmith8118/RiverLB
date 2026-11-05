"""Actual synthetic packet/PCAP worker check; run only in a fresh network namespace.

No installed helper or application endpoint is enabled. Both veth interfaces and
every packet belong to this disposable namespace; no host/LAN traffic is read.
"""
import importlib.util
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock
from capture_policy import capture, NETWORKS, packet, request


def run():
    parent=os.environ.get('RIVERLB_CAPTURE_TEST_PARENT_NETNS')
    assert parent and parent.startswith('net:[')
    assert os.readlink('/proc/self/ns/net')!=parent
    assert os.geteuid()==0
    if len(sys.argv)==1:
        assert {name for _,name in socket.if_nameindex()}=={'lo'}, 'Fresh network namespace required'
        subprocess.run(['ip','link','add','cap0','type','veth','peer','name','cap1'],check=True)
        for name in ['cap0','cap1']:
            subprocess.run(['sysctl','-q','-w',f'net.ipv6.conf.{name}.accept_dad=0'],check=True)
            subprocess.run(['ip','link','set',name,'up'],check=True)
        # Initial IPv6 link-local creation is a real network change; let setup
        # settle before measuring the worker's normal deadline behavior.
        time.sleep(2)
        # GitHub's checkout ancestors belong to the runner and may be 0700.
        # With only NET_RAW, root must not need DAC override to read fixtures.
        with tempfile.TemporaryDirectory(prefix='riverlb-capture-fixture-',dir='/tmp') as folder:
            root=Path(folder);(root/'tests').mkdir();(root/'deploy/privileged').mkdir(parents=True)
            source=Path(__file__).resolve().parents[1]
            for name in ['tests/capture_worker_network.py','tests/capture_policy.py',
                         'deploy/privileged/capture_policy.py','deploy/privileged/capture_file.py',
                         'deploy/privileged/capture_worker.py']:
                shutil.copyfile(source/name,root/name)
            for family in ['4','6']:
                for protocol in ['tcp','udp']:
                    subprocess.run(['setpriv','--bounding-set=-all,+net_raw',sys.executable,
                                    str(root/'tests/capture_worker_network.py'),'--case',family,protocol],check=True)
        return
    assert len(sys.argv)==4 and sys.argv[1]=='--case' and sys.argv[2] in {'4','6'} and sys.argv[3] in {'tcp','udp'}
    assert {name for _,name in socket.if_nameindex()}=={'lo','cap0','cap1'}
    family,protocol=int(sys.argv[2]),sys.argv[3]
    cap_fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert int(cap_fields['CapEff'].strip(),16)==1<<13, 'Worker setup must need only CAP_NET_RAW'
    modules={}
    for name in ['capture_worker','capture_file']:
        spec=importlib.util.spec_from_file_location('fixture_'+name,Path(__file__).resolve().parents[1]/'deploy/privileged'/f'{name}.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);modules[name]=module
    worker,files=modules['capture_worker'],modules['capture_file']
    # Supply the selected index and independent fixture exclusions; raw socket
    # binding, kernel delivery, capability drop and PCAP writes remain real.
    index=socket.if_nametoindex('cap0')
    config={'request':{**request(),'interface':'cap0','duration_seconds':1,'protocol':protocol,'host':'10.88.10.100' if family==4 else 'fd88:16::100'},'interface_index':index,'management_interfaces':['cap1'],'protected_ports':[18090]}
    with tempfile.TemporaryDirectory(prefix='riverlb-capture-worker-') as directory, socket.socket(socket.AF_PACKET,socket.SOCK_RAW,0) as injector:
        Path(directory).chmod(0o700)
        injector.bind(('cap1',3))
        raw=packet(family,protocol,options=protocol=='tcp')
        def send():
            for _ in range(5):time.sleep(.1);injector.send(raw)
        sender=threading.Thread(target=send);sender.start()
        with mock.patch.object(worker,'inventory',return_value=([{'ifname':'cap0','ifindex':index}],NETWORKS)):
            result=worker.run(directory,config,capture,files,threading.Event())
        sender.join(timeout=2);assert not sender.is_alive()
        assert result['reason']=='time_limit' and result['packets']>0,result
        assert result['kernel_received']>=result['observed'] and result['kernel_dropped']==0,result
        data=(Path(directory)/'capture.pcap').read_bytes()
        assert data.startswith(files.PCAP_HEADER) and len(data)==result['bytes']
        assert b'private-synthetic' not in data and b'opts' not in data
        status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        assert all(int(status[name].strip(),16)==0 for name in ['CapEff','CapPrm','CapInh','CapAmb'])
        assert status['NoNewPrivs'].strip()=='1'
    print(f'PASS isolated capture worker: IPv{family}/{protocol}, bound headers, actual PCAP, deadline and zero remaining capabilities')


if __name__=='__main__':run()
