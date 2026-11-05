"""Worker orchestration fixtures; all packet sockets and inventory are replaced."""
import importlib.util
import json
import os
import tempfile
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
from capture_policy import capture, NETWORKS, packet, request

spec=importlib.util.spec_from_file_location('riverlb_capture_worker',Path(__file__).resolve().parents[1]/'deploy/privileged/capture_worker.py')
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class Socket:
    def __init__(self,frames=()):self.frames=iter(frames);self.bound=None;self.blocking=None;self.closed=False
    def __enter__(self):return self
    def __exit__(self,*_):self.closed=True
    def bind(self,address):self.bound=address
    def setblocking(self,blocking):self.blocking=blocking
    def recvfrom(self,size):
        frame,address=next(self.frames)
        assert size==capture.MAX_FRAME
        return frame,address


class WorkerTests(unittest.TestCase):
    def configuration(self):return {'request':request(),'interface_index':4,'management_interfaces':['ens3'],'protected_ports':[18090]}

    def run_worker(self,write,ready='packets',frames=()):
        events,packets=Socket(),Socket(frames)
        with mock.patch.object(worker.socket,'socket',side_effect=[events,packets]) as factory, \
                mock.patch.object(worker,'inventory',return_value=([{'ifname':'ens4','ifindex':4}],NETWORKS)), \
                mock.patch.object(worker,'drop_capabilities') as drop, \
                mock.patch.object(worker.select,'select',return_value=([events,packets] if ready=='events' else [packets],[],[])):
            result=worker.run('/unused-private-directory',self.configuration(),capture,SimpleNamespace(write=write),threading.Event())
            self.assertEqual(factory.call_args_list[1].args,(worker.socket.AF_PACKET,worker.socket.SOCK_RAW,0))
            self.assertEqual(packets.bound,('ens4',3))
            self.assertFalse(packets.blocking)
            drop.assert_called_once()
        self.assertTrue(events.closed and packets.closed)
        return result

    def test_only_selected_interface_is_received_and_payload_is_stripped(self):
        raw=packet(options=True)
        def write(directory,request,receive,headers,stopped):
            self.assertFalse(stopped())
            self.assertIsNone(receive(worker.time.monotonic()+1))
            selected=receive(worker.time.monotonic()+1)
            self.assertEqual(selected,raw)
            self.assertEqual(len(headers(selected)),54)
            return {'reason':'time_limit','packets':1}
        result=self.run_worker(write,frames=[(raw,('ens3',3,0,0,b'')),(raw,('ens4',3,0,0,b''))])
        self.assertEqual(result['packets'],1)

    def test_network_event_takes_priority_and_cancels_before_packet(self):
        def write(directory,request,receive,headers,stopped):
            self.assertIsNone(receive(worker.time.monotonic()+1))
            self.assertTrue(stopped())
            return {'reason':'canceled','packets':0}
        self.assertEqual(self.run_worker(write,ready='events')['reason'],'network_changed')

    def test_interface_replacement_and_bad_config_fail_before_packet_socket(self):
        for config in [{}, {**self.configuration(),'interface_index':True}, {**self.configuration(),'request':'bad'},self.configuration()]:
            with self.subTest(config=config),mock.patch.object(worker.socket,'socket',return_value=Socket()) as factory, \
                    mock.patch.object(worker,'inventory',return_value=([{'ifname':'ens4','ifindex':99}],NETWORKS)):
                with self.assertRaises(ValueError):worker.run('/unused',config,capture,None,threading.Event())
                self.assertLessEqual(factory.call_count,1)

    def test_private_request_rejects_permissions_links_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);directory.chmod(0o700);path=directory/'request.json'
            path.write_text(json.dumps(self.configuration()));path.chmod(0o600)
            real_stat=os.fstat
            def root_stat(fd):
                info=real_stat(fd)
                return SimpleNamespace(st_uid=0,st_mode=info.st_mode,st_nlink=info.st_nlink,st_size=info.st_size)
            with mock.patch.object(worker.os,'fstat',side_effect=root_stat):
                self.assertEqual(worker.read_configuration(directory),self.configuration())
                for mode in [0o644,0o666]:
                    path.chmod(mode)
                    with self.assertRaises(ValueError):worker.read_configuration(directory)
                path.chmod(0o600);os.link(path,directory/'second-link')
                with self.assertRaises(ValueError):worker.read_configuration(directory)
                (directory/'second-link').unlink();path.write_bytes(b'x'*32769)
                with self.assertRaises(ValueError):worker.read_configuration(directory)
                path.unlink();path.symlink_to(directory/'other')
                with self.assertRaises(OSError):worker.read_configuration(directory)
                path.unlink();os.mkfifo(path,0o600)
                with self.assertRaises(ValueError):worker.read_configuration(directory)

    def test_fixed_resource_limits(self):
        with mock.patch.object(worker.resource,'getrlimit',return_value=(worker.resource.RLIM_INFINITY,worker.resource.RLIM_INFINITY)), \
                mock.patch.object(worker.resource,'setrlimit') as limits, \
                mock.patch.object(worker.os,'nice'):
            worker.limits()
            self.assertEqual([c.args[1] for c in limits.call_args_list],[(5,5),(128*1024*1024,)*2,(16*1024*1024,)*2,(32,32),(0,0)])

    def test_main_retention_is_fixed_and_cleanup_runs_on_success_and_failure(self):
        class Event:
            def __init__(self):self.set_value=False;self.waited=[]
            def set(self):self.set_value=True
            def is_set(self):return self.set_value
            def wait(self,seconds):self.waited.append(seconds);return False
        for failed in [False,True]:
            events=[];handlers={};statuses=[]
            def event():value=Event();events.append(value);return value
            def signal(kind,handler):handlers[kind]=handler
            def run(*args):
                if failed:raise OSError('secret-synthetic-packet-error')
                handlers[worker.signal.SIGUSR1]()
                self.assertTrue(events[0].is_set());self.assertFalse(events[1].is_set())
                return dict(reason='canceled',bytes=24,packets=0,observed=0)
            with self.subTest(failed=failed),mock.patch.object(worker.os,'geteuid',return_value=0), \
                    mock.patch.object(worker.sys,'argv',['worker','a'*32]), \
                    mock.patch.object(worker,'read_configuration',return_value=self.configuration()), \
                    mock.patch.object(worker,'load_module',return_value=object()), \
                    mock.patch.object(worker,'limits'),mock.patch.object(worker.threading,'Event',side_effect=event), \
                    mock.patch.object(worker.signal,'signal',side_effect=signal), \
                    mock.patch.object(worker,'run',side_effect=run), \
                    mock.patch.object(worker,'status',side_effect=lambda _,value:statuses.append(value)), \
                    mock.patch.object(worker,'cleanup') as cleanup:
                self.assertEqual(worker.main(),1 if failed else 0)
                cleanup.assert_called_once()
                self.assertNotIn('secret',json.dumps(statuses))
                if not failed:self.assertEqual(events[1].waited,[600])

    def test_resource_limits_are_lowered_never_raised(self):
        with mock.patch.object(worker.resource,'getrlimit',return_value=(10,10)), \
                mock.patch.object(worker.resource,'setrlimit') as limits, \
                mock.patch.object(worker.os,'nice') as nice:
            worker.limits()
            self.assertEqual(len(limits.call_args_list),5)
            self.assertTrue(all(soft==hard and soft<=10 for _,(soft,hard) in (c.args for c in limits.call_args_list)))
            nice.assert_called_once_with(10)


if __name__=='__main__':unittest.main()
