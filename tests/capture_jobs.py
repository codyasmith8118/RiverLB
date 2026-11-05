"""Private job lifecycle tests: systemd/inventory calls are closed fixtures."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from capture_policy import request


ROOT=Path(__file__).resolve().parents[1]/'deploy/privileged'
def load(name):
    spec=importlib.util.spec_from_file_location('fixture_'+name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
jobs=load('capture_jobs');policy=load('policy')
OWNER='a'*64;OTHER='b'*64


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name);self.root.chmod(0o700)
        self.now=0;self.state='inactive';self.result='success';self.calls=[]
        broker=SimpleNamespace(configuration=dict(uid=4242,traffic_interfaces=['ens4'],management_interfaces=['ens3']),device=self.device)
        self.manager=jobs.Capture(broker,policy,self.process,self.success,self.root,os.getuid(),clock=lambda:self.now,janitor=False)
        self.assertTrue(self.manager.available)

    def tearDown(self):self.temporary.cleanup()

    def device(self,name):
        if name!='ens4':raise ValueError('Unapproved interface')
        return dict(ifname=name,ifindex=4)

    def process(self,program,args,**kwargs):
        self.calls.append((program,args))
        if program=='/usr/sbin/ip':
            self.assertEqual(args,['-j','address','show'])
            return dict(code=0,stdout=json.dumps([dict(ifname='ens3',addr_info=[dict(local='10.88.0.11',prefixlen=24)])]))
        self.assertEqual(program,'/usr/bin/systemctl')
        if args[1] in {'riverlb.service','riverlb-ha.service'}:
            return dict(code=0,stdout=f'MainPID={os.getpid()}\nUser=riverlb\nPrivateNetwork=no\nNetworkNamespacePath=\nRestrictNamespaces=yes\n')
        self.assertRegex(args[-1] if args[0]=='kill' else args[1],r'^riverlb-capture@[0-9a-f]{32}\.service$')
        if args[0]=='start':self.state='active'
        if args[0] in {'stop','kill'}:self.state='inactive'
        return dict(code=0,stdout='ActiveState='+self.state+'\nExecMainStatus=0\nResult='+self.result+'\nLoadState=loaded\nMainPID=0\nControlPID=0\n')

    def success(self,value):
        policy.require(value['code']==0);return value

    def call(self,operation,**fields):
        if operation=='start' and 'protected_ports' not in fields:fields['protected_ports']=[18090]
        return self.manager.dispatch(dict(operation=operation,**fields),(os.getpid(),4242,os.getgid()))

    def start(self):return self.call('start',owner=OWNER,request=request())['id']

    def finish(self,identifier):
        path=self.root/identifier
        (path/'capture.pcap').write_bytes(jobs.pcap.PCAP_HEADER);(path/'capture.pcap').chmod(0o600)
        (path/'status.json').write_text(json.dumps(dict(state='complete',reason='time_limit',bytes=24,packets=0,observed=0,kernel_received=0,kernel_dropped=0)));(path/'status.json').chmod(0o600)
        self.state='inactive'

    def test_start_private_configuration_and_one_job_bound(self):
        identifier=self.start();path=self.root/identifier
        value=json.loads((path/'request.json').read_text())
        self.assertEqual(value['interface_index'],4);self.assertEqual(value['management_interfaces'],['ens3'])
        self.assertEqual((path/'request.json').stat().st_mode&0o777,0o600)
        self.assertEqual(path.stat().st_mode&0o777,0o700)
        with self.assertRaises(ValueError):self.start()
        self.assertEqual(self.call('status',owner=OTHER),{'state':'busy'})

    def test_same_session_export_only_after_completion_and_bounded_offsets(self):
        identifier=self.start()
        with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=0)
        self.finish(identifier)
        with self.assertRaises(ValueError):self.call('export',owner=OTHER,id=identifier,offset=0)
        value=self.call('export',owner=OWNER,id=identifier,offset=0)
        self.assertEqual(base64.b64decode(value['data']),jobs.pcap.PCAP_HEADER)
        self.assertEqual(value['total'],24);self.assertEqual(len(value['sha256']),64)
        for offset in [True,-1,25,'0']:
            with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=offset)
        self.assertEqual(self.call('export',owner=OWNER,id=identifier,offset=24)['data'],'')

    def test_foreign_peer_namespace_unknown_fields_and_injection_rejected(self):
        for fields in [dict(owner=OWNER,request={**request(),'interface':'ens3'}),dict(owner=OWNER,request={**request(),'host':'10.88.0.11'}),dict(owner=OWNER,request={**request(),'port':22}),dict(owner=OWNER,request=request(),protected_ports=[18080]),dict(owner=OWNER,request=request(),protected_ports=[True]),dict(owner='../bad',request=request()),dict(owner=OWNER,request=request(),command='id')]:
            with self.assertRaises(ValueError):self.call('start',**fields)
        with self.assertRaises(ValueError):self.manager.dispatch({'operation':'interfaces'},(os.getpid(),4243,0))
        with mock.patch.object(self.manager,'process',return_value=dict(code=0,stdout=f'MainPID={os.getpid()}\nUser=riverlb\nPrivateNetwork=yes\nNetworkNamespacePath=/foreign/netns\nRestrictNamespaces=yes\n')):
            with self.assertRaises(ValueError):self.call('interfaces')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_expiry_cancel_delete_and_orphan_cleanup(self):
        identifier=self.start();self.finish(identifier)
        self.assertEqual(self.call('status',owner=OWNER)['state'],'complete')
        self.now=599;self.assertEqual(self.call('status',owner=OWNER)['state'],'complete')
        self.now=600;self.assertEqual(self.call('status',owner=OWNER)['state'],'idle')
        self.assertFalse((self.root/identifier).exists())
        identifier=self.start();self.call('cancel',owner=OWNER,id=identifier)
        self.assertEqual(self.state,'inactive')
        self.call('delete',owner=OWNER,id=identifier);self.assertEqual(list(self.root.iterdir()),[])
        self.start()
        broker=self.manager.broker
        other=jobs.Capture(broker,policy,self.process,self.success,self.root,os.getuid(),janitor=False)
        self.assertTrue(other.available);self.assertEqual(list(self.root.iterdir()),[])

    def test_export_refuses_symlink_hardlink_replaced_and_incomplete_files(self):
        identifier=self.start();self.finish(identifier);path=self.root/identifier/'capture.pcap'
        self.call('status',owner=OWNER)
        original=self.root/'outside';path.rename(original);path.symlink_to(original)
        with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=0)
        path.unlink();os.link(original,path)
        with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=0)
        path.unlink();original.rename(path)
        path.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=0)

    def test_worker_failure_cannot_export_and_expires(self):
        identifier=self.start();self.state='failed';self.result='signal'
        self.assertEqual(self.call('status',owner=OWNER)['state'],'failed')
        with self.assertRaises(ValueError):self.call('export',owner=OWNER,id=identifier,offset=0)
        self.now=600;self.assertEqual(self.call('status',owner=OWNER)['state'],'idle')

    def test_late_status_does_not_kill_completed_retained_capture(self):
        identifier=self.start();self.finish(identifier);self.state='active'
        stamp=(self.root/identifier/'status.json').stat().st_mtime
        self.now=100;self.manager.wall=lambda:stamp+self.now
        value=self.call('status',owner=OWNER)
        self.assertEqual(value['state'],'complete');self.assertEqual(value['retention_seconds'],500)
        self.assertFalse(any(args[0]=='stop' for _,args in self.calls))

    def test_runtime_directory_removal_expires_completed_capture(self):
        identifier=self.start();self.finish(identifier);self.call('status',owner=OWNER)
        for path in (self.root/identifier).iterdir():path.unlink()
        (self.root/identifier).rmdir()
        self.assertEqual(self.call('status',owner=OWNER)['state'],'idle')

    def test_unsafe_optional_storage_is_preserved_and_disabled(self):
        item=self.root/'foreign';item.write_bytes(b'preserve')
        other=jobs.Capture(self.manager.broker,policy,self.process,self.success,self.root,os.getuid(),janitor=False)
        self.assertFalse(other.available);self.assertEqual(item.read_bytes(),b'preserve')


if __name__=='__main__':unittest.main()
