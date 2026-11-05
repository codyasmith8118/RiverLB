"""Synthetic private PCAP persistence; never opens a capture socket."""
import errno
import importlib.util
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
from capture_policy import capture, packet, request, NETWORKS

spec = importlib.util.spec_from_file_location('capture_file', Path(__file__).resolve().parents[1] / 'deploy/privileged/capture_file.py')
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.request = capture.validate(request(), {'ens4'}, NETWORKS)

    def tearDown(self):self.temporary.cleanup()

    def write(self, frames=None, **kwargs):
        source=iter(frames if frames is not None else [packet()])
        return storage.write(self.directory, self.request,
                             kwargs.pop('receive',lambda _:next(source)),
                             lambda frame:capture.headers(frame,self.request,NETWORKS),
                             kwargs.pop('stopped',lambda:False), owner_uid=os.getuid(),
                             wall=lambda:1700000000.25, **kwargs)

    def records(self):
        data=(self.directory/'capture.pcap').read_bytes()
        self.assertEqual(data[:24],storage.PCAP_HEADER)
        records=[];offset=24
        while offset<len(data):
            seconds,micros,caplen,wirelen=struct.unpack_from('<IIII',data,offset)
            offset+=16;self.assertLessEqual(offset+caplen,len(data))
            records.append((seconds,micros,caplen,wirelen,data[offset:offset+caplen]));offset+=caplen
        self.assertEqual(offset,len(data))
        return data,records

    def test_valid_private_pcap_retains_wire_length_but_no_payload(self):
        raw=packet(options=True)
        result=self.write([raw])
        data,records=self.records()
        self.assertEqual(result['reason'],'source_closed')
        self.assertEqual(result['bytes'],len(data))
        self.assertEqual(result['packets'],1)
        self.assertEqual(records[0][:4],(1700000000,250000,54,len(raw)))
        self.assertNotIn(b'private-synthetic',data)
        self.assertNotIn(b'opts',data)
        info=(self.directory/'capture.pcap').stat()
        self.assertEqual(stat.S_IMODE(info.st_mode),0o600)
        self.assertEqual(info.st_uid,os.getuid())
        self.assertEqual(info.st_nlink,1)

    def test_size_limit_precedes_complete_record_write(self):
        self.request=capture.validate({**request(),'max_bytes':4096},{'ens4'},NETWORKS)
        result=self.write(receive=lambda _:packet())
        data,records=self.records()
        self.assertEqual(result['reason'],'byte_limit')
        self.assertLessEqual(len(data),4096)
        self.assertGreater(len(data)+16+54,4096)
        self.assertEqual(len(records),result['packets'])

    def test_deadline_and_cancellation_discard_late_receive(self):
        for canceled in [False,True]:
            with self.subTest(canceled=canceled):
                now=[0];stop=[False]
                def receive(_):
                    now[0]=61;stop[0]=canceled
                    return packet()
                result=self.write(receive=receive,clock=lambda:now[0],stopped=lambda:stop[0])
                self.assertEqual(result['reason'],'canceled' if canceled else 'time_limit')
                self.assertEqual(self.records()[1],[])
                (self.directory/'capture.pcap').unlink()

    def test_unmatched_flood_is_bounded(self):
        with mock.patch.object(storage,'MAX_PACKETS',100):
            result=self.write(receive=lambda _:packet(destination_port=18081))
        self.assertEqual(result['reason'],'packet_limit')
        self.assertEqual(result['observed'],100)
        self.assertEqual(self.records()[1],[])

    def test_disk_full_partial_write_and_sync_failure_remove_output(self):
        real_write=os.write
        for mode in ['disk_full','short_then_full','zero_write','sync_failure']:
            calls=[0]
            def write(fd,data):
                calls[0]+=1
                if mode=='zero_write':return 0
                if mode=='disk_full' or (mode=='short_then_full' and calls[0]>1):
                    raise OSError(errno.ENOSPC,'synthetic disk full')
                return real_write(fd,data[:3] if mode=='short_then_full' else data)
            with self.subTest(mode=mode), mock.patch.object(storage.os,'write',side_effect=write):
                if mode=='sync_failure':
                    with mock.patch.object(storage.os,'fsync',side_effect=OSError(errno.EIO,'synthetic sync failure')):
                        with self.assertRaises(OSError):self.write()
                else:
                    with self.assertRaises(OSError):self.write()
                self.assertFalse((self.directory/'capture.pcap').exists())

    def test_close_failure_removes_output_and_closes_directory(self):
        real_close=os.close;calls=[0]
        def close(fd):
            calls[0]+=1;real_close(fd)
            if calls[0]==1:raise OSError(errno.EIO,'synthetic close failure')
        with mock.patch.object(storage.os,'close',side_effect=close):
            with self.assertRaises(OSError):self.write()
        self.assertEqual(calls[0],2)
        self.assertFalse((self.directory/'capture.pcap').exists())

    def test_symlinks_existing_files_and_unsafe_directory_are_rejected(self):
        target=self.directory/'existing';target.write_bytes(b'preserve')
        (self.directory/'capture.pcap').symlink_to(target)
        with self.assertRaises(FileExistsError):self.write()
        self.assertEqual(target.read_bytes(),b'preserve')
        (self.directory/'capture.pcap').unlink()
        (self.directory/'capture.pcap').write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):self.write()
        self.assertEqual((self.directory/'capture.pcap').read_bytes(),b'preserve')
        (self.directory/'capture.pcap').unlink();self.directory.chmod(0o755)
        with self.assertRaises(ValueError):self.write()
        self.assertFalse((self.directory/'capture.pcap').exists())


if __name__=='__main__':unittest.main()
