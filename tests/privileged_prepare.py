#!/usr/bin/env python3
"""Exercise descriptor-based migration using private disposable files only."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare', ROOT / 'deploy/privileged/prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class Migration(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='riverlb-identity-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.uid, self.gid = os.geteuid(), os.getegid()

    def test_private_regular_state_preserves_contents(self):
        child = self.root / 'nested'
        child.mkdir(mode=0o700)
        data = child / 'database'
        data.write_bytes(b'private fixture')
        data.chmod(0o640)
        prepare.transfer_tree(self.root, self.uid, self.gid)
        self.assertEqual(data.read_bytes(), b'private fixture')
        self.assertEqual(stat.S_IMODE(data.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)

    def test_service_identity_rejects_supplementary_privileges_and_aliases(self):
        account = SimpleNamespace(pw_name='riverlb', pw_uid=1001, pw_gid=1002,
                                  pw_shell='/sbin/nologin', pw_dir='/var/lib/riverlb')
        group = SimpleNamespace(gr_name='riverlb', gr_gid=1002)
        with patch.object(prepare.pwd, 'getpwnam', return_value=account), \
             patch.object(prepare.pwd, 'getpwall', return_value=[account]), \
             patch.object(prepare.grp, 'getgrnam', return_value=group), \
             patch.object(prepare.grp, 'getgrall', return_value=[group]), \
             patch.object(prepare.os, 'getgrouplist', return_value=[1002]):
            self.assertIs(prepare.account_identity(), account)
            with patch.object(prepare.os, 'getgrouplist', return_value=[1002, 999]):
                with self.assertRaises(prepare.broker.policy.Rejected):
                    prepare.account_identity()
            alias = SimpleNamespace(gr_name='docker', gr_gid=1002)
            with patch.object(prepare.grp, 'getgrall', return_value=[group, alias]):
                with self.assertRaises(prepare.broker.policy.Rejected):
                    prepare.account_identity()
            alias = SimpleNamespace(pw_name='another-user', pw_uid=1001)
            with patch.object(prepare.pwd, 'getpwall', return_value=[account, alias]):
                with self.assertRaises(prepare.broker.policy.Rejected):
                    prepare.account_identity()

    def test_symlink_hardlink_fifo_and_writable_directory_rejected(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'unchanged')
        outside.chmod(0o600)
        for kind in ['symlink', 'hardlink', 'fifo', 'directory']:
            with self.subTest(kind=kind):
                target = self.root / 'application'
                target.mkdir(mode=0o700)
                leaf = target / 'unexpected'
                if kind == 'symlink':
                    leaf.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, leaf)
                elif kind == 'fifo':
                    os.mkfifo(leaf)
                else:
                    leaf.mkdir(mode=0o700)
                    leaf.chmod(0o777)
                with self.assertRaises((OSError, prepare.broker.policy.Rejected)):
                    prepare.transfer_tree(target, self.uid, self.gid)
                self.assertEqual(outside.read_bytes(), b'unchanged')
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o600)
                leaf.rmdir() if kind == 'directory' else leaf.unlink()
                target.rmdir()

    def test_initial_scope_uses_saved_config_and_protects_other_addressed_nics(self):
        config = self.root / 'config'
        data = self.root / 'state'
        sys_net = self.root / 'sys'
        for path in [config, data, sys_net]:
            path.mkdir(mode=0o700)
        (config / 'riverlb.toml').write_text('management="127.0.0.1:18090"\n')
        saved = dict(management='192.0.2.10:18090', network=dict(vlans=[dict(interface='eth1')]))
        with sqlite3.connect(data / 'riverlb.db') as connection:
            connection.execute('CREATE TABLE configurations (revision INTEGER PRIMARY KEY, json TEXT)')
            connection.execute('INSERT INTO configurations VALUES (1, ?)', [json.dumps(saved)])
        links = []
        for index in range(4):
            name = f'eth{index}'
            (sys_net / name / 'device').mkdir(parents=True)
            links.append(dict(ifname=name, link_type='ether', addr_info=[] if index == 2 else
                              [dict(scope='global', local='192.0.2.10' if index == 0 else f'198.51.100.{index}')]))
        with patch.object(prepare, 'CONFIG', config), patch.object(prepare, 'DATA', data), \
             patch.object(prepare, 'SYS_NET', sys_net), \
             patch.object(prepare.broker, 'private'), \
             patch.object(prepare.broker, 'process', return_value=dict(code=0, stdout=json.dumps(links))):
            policy = prepare.initial_policy(self.uid, self.gid)
        self.assertEqual(policy['traffic_interfaces'], ['eth1', 'eth2'])
        self.assertEqual(policy['management_interfaces'], ['eth0', 'eth3'])


if __name__ == '__main__':
    unittest.main()
