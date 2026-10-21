"""Standalone updater state-machine fixtures with no host services or databases.

All paths map into temporary directories. Commands that would execute a binary,
control systemd, read a database or contact management are replaced with fixed
fixture operations. Signature interoperability is tested separately by Rust/CLI.
"""
import base64
from contextlib import ExitStack
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path as RealPath
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = RealPath(__file__).resolve().parents[1]


class Fixture:
    def __init__(self):
        self.stack = ExitStack()
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='riverlb-update-helper-'))
        self.root = RealPath(directory)
        loader = importlib.machinery.SourceFileLoader('update_fixture', str(ROOT / 'packaging/update/riverlb-update'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.helper = importlib.util.module_from_spec(spec)
        loader.exec_module(self.helper)
        # Only this disposable imported fixture uses the actual test UID. The
        # installed helper's immutable OWNER=0 policy is not changed.
        self.helper.OWNER = os.geteuid()
        original_umask = os.umask(0o077)
        self.stack.callback(os.umask, original_umask)
        self.commands = []
        self.running = True
        self.service_start_count = 0
        self.fail_restore = False
        self.original_database = b'old-compatible-database'
        self.original_wal = b'old-private-wal'
        self.payload = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\0' + bytes(44)
        self.manifest = dict(format=1, product='RiverLB', version='0.1.1', sequence=5,
                             payload_length=len(self.payload),
                             payload_sha256=hashlib.sha256(self.payload).hexdigest())
        self.versions = self.root / 'usr/lib/riverlb/versions'
        self.versions.mkdir(parents=True, mode=0o755)
        constants = dict(BASE=self.root / 'usr/lib/riverlb/base/riverlb',
                         CURRENT=self.root / 'usr/lib/riverlb/current',
                         DB=self.root / 'var/lib/riverlb/riverlb.db',
                         CONFIG=self.root / 'etc/riverlb/riverlb.toml',
                         UPDATER=self.root / 'var/lib/riverlb-updater',
                         TRUST=self.root / 'etc/riverlb-updater/update-trust.json',
                         HELPER=self.root / 'usr/libexec/riverlb/riverlb-update',
                         SOCKET=self.root / 'run/riverlb/operations.sock')
        constants.update(BUNDLE=constants['DB'].with_suffix('.update-bundle.json'),
                         STATE=constants['DB'].with_suffix('.updates.json'),
                         JOURNAL=constants['UPDATER'] / 'recovery.json',
                         CHECKPOINT=constants['UPDATER'] / 'checkpoint.json',
                         HIGHSTATE=constants['UPDATER'] / 'status.json',
                         RUNNING=constants['UPDATER'] / 'running.json')
        for name, value in constants.items():
            setattr(self.helper, name, value)
            value.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if hasattr(self.helper, 'VERSIONS'):
            self.helper.VERSIONS = self.versions
        self.helper.BASE.write_bytes(b'baseline-reader-fixture')
        self.helper.BASE.chmod(0o755)
        self.helper.DB.write_bytes(self.original_database)
        RealPath(str(self.helper.DB) + '-wal').write_bytes(self.original_wal)
        self.helper.CONFIG.write_text('fixture only\n')
        (self.root / 'etc/os-release').write_text('ID=almalinux\nVERSION_ID="10.2"\n')
        self.helper.write(self.helper.HIGHSTATE, dict(highest_sequence=4, history=[]))
        self.helper.write(self.helper.BUNDLE, dict(manifest='fixture verified separately', signature='fixture',
                                                  payload=base64.b64encode(self.payload).decode()))
        self.stack.enter_context(patch.object(self.helper, 'Path', self.safe_path))
        self.stack.enter_context(patch.object(self.helper, 'run', self.run))
        self.original_readiness = self.helper.readiness
        self.stack.enter_context(patch.object(self.helper, 'local_status', self.local_status))
        self.stack.enter_context(patch.object(self.helper, 'readiness', self.ready))

    def safe_path(self, value):
        path = RealPath(value)
        for original in ('/usr/lib/riverlb', '/var/lib/riverlb', '/var/lib/riverlb-updater',
                         '/etc/riverlb', '/etc/riverlb-updater', '/run/riverlb', '/proc'):
            if path == RealPath(original) or RealPath(original) in path.parents:
                return self.root / str(path).lstrip('/')
        if path == RealPath('/etc/os-release'):
            return self.root / 'etc/os-release'
        if path.is_absolute() and path != self.root and self.root not in path.parents:
            raise AssertionError(f'Fixture attempted a host path: {path}')
        return path

    def snapshot(self):
        config = dict(management='192.0.2.10:18090', virtual_servers=[])
        return dict(format=3, tables=dict(configurations=[[1, json.dumps(config), 0, 'fixture']],
                                          administrators=[['admin', 'fixture-password-hash']],
                                          device_certificates=[]),
                    fixture_database=self.original_database.decode(), fixture_wal=self.original_wal.decode())

    def run(self, args):
        args = [str(value) for value in args]
        self.commands.append(args)
        executable = RealPath(args[0]).name
        if executable == 'systemctl':
            operation = args[1]
            if operation == 'stop':
                self.running = False
                return ''
            if operation == 'start':
                self.running = True
                self.service_start_count += 1
                if self.helper.CURRENT.is_symlink() and self.helper.CURRENT.resolve().name == '5':
                    self.helper.DB.write_bytes(b'candidate-migrated-database')
                    RealPath(str(self.helper.DB) + '-wal').write_bytes(b'candidate-wal')
                return ''
            raise AssertionError('Unexpected fixture systemctl operation')
        if args[1:] == ['--version']:
            assert self.versions in RealPath(args[0]).parents
            return 'riverlb 0.1.1\n'
        assert RealPath(args[0]) == self.helper.BASE or self.versions in RealPath(args[0]).parents, 'Execute only a validated application reader in this fixture'
        operation = args[1]
        if operation == 'update-verify':
            sequence = int(args[args.index('--sequence') + 1])
            if self.manifest['sequence'] <= sequence:
                raise subprocess.CalledProcessError(1, args)
            return json.dumps(self.manifest)
        if operation == 'backup':
            assert not self.running, 'Stop the daemon before offline checkpoint'
            output = RealPath(args[args.index('--output') + 1])
            self.helper.write(output, self.snapshot())
            return 'Private backup saved\n'
        if operation == 'update-readiness-token':
            assert not self.running
            return json.dumps(dict(token='fixture-secret-readiness-token'))
        if operation == 'restore':
            assert not self.running, 'Never replace database or WAL while the service is running'
            if self.fail_restore:
                raise subprocess.CalledProcessError(1, args)
            snapshot = self.helper.load(RealPath(args[args.index('--input') + 1]))
            target = RealPath(args[args.index('--database') + 1])
            target.write_bytes(snapshot['fixture_database'].encode())
            RealPath(str(target) + '-wal').write_bytes(snapshot['fixture_wal'].encode())
            return 'Backup restored\n'
        raise AssertionError('Unexpected fixture operation: ' + operation)

    def local_status(self):
        return dict(version='0.1.1' if self.helper.CURRENT.is_symlink() and self.helper.CURRENT.resolve().name == '5' else '0.1.0',
                    revision=1, management='192.0.2.10:18090', management_secure=False,
                    ha_role='standalone', confirmation_pending=False, virtual_servers=[])

    def ready(self, snapshot, baseline, manifest):
        assert self.running
        assert manifest['version'] == '0.1.1'
        assert not baseline['confirmation_pending']

    def previous_version(self, sequence=4):
        previous = self.versions / str(sequence)
        previous.mkdir(mode=0o755)
        previous.chmod(0o755)
        reader = previous / 'riverlb'
        reader.write_bytes(b'previous-signed-reader-fixture')
        reader.chmod(0o755)
        self.helper.CURRENT.symlink_to(previous, target_is_directory=True)
        return previous, reader

    def interrupted(self, sequence=5, previous=None, reader=None):
        self.running = False
        self.helper.write(self.helper.CHECKPOINT, self.snapshot())
        journal = dict(format=1, previous=str(previous) if previous else None,
                       version='0.1.1', sequence=sequence)
        if reader:
            journal['reader'] = str(reader)
        self.helper.write(self.helper.JOURNAL, journal)
        self.helper.DB.write_bytes(b'incomplete-candidate-database')

    def updater_process(self, pid=4321, args=None):
        process = self.root / 'proc' / str(pid)
        process.mkdir(parents=True, mode=0o700, exist_ok=True)
        command = args if args is not None else [b'/usr/bin/python3', str(self.helper.HELPER).encode(), b'activate']
        (process / 'cmdline').write_bytes(b'\0'.join(command) + b'\0')
        self.helper.write(self.helper.RUNNING, {'pid': pid})
        return process

    def close(self):
        self.stack.close()


class UpdateHelperTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)
        self.helper = self.fixture.helper

    def test_successful_activation_consumes_sequence_and_clears_recovery(self):
        self.helper.activate()
        self.assertEqual(self.helper.CURRENT.resolve(), self.fixture.versions / '5')
        self.assertEqual(self.helper.DB.read_bytes(), b'candidate-migrated-database')
        state = self.helper.load(self.helper.HIGHSTATE)
        self.assertEqual(state['highest_sequence'], 5)
        self.assertEqual(state['history'][-1]['result'], 'applied')
        self.assertFalse(self.helper.JOURNAL.exists())
        self.assertFalse(self.helper.BUNDLE.exists())
        self.assertTrue(self.fixture.running)
        self.assertNotIn('fixture-secret', json.dumps(self.fixture.commands))
        self.assertNotIn('fixture-password-hash', json.dumps(state))
        self.assertEqual(stat.S_IMODE(self.helper.CURRENT.resolve().stat().st_mode), 0o755,
                         'A non-root CLI must traverse the selected version despite updater umask 077')
        self.assertEqual(stat.S_IMODE((self.helper.CURRENT.resolve() / 'riverlb').stat().st_mode), 0o755)

    def test_failed_readiness_restores_database_wal_selector_and_monotonic_highwater(self):
        with patch.object(self.helper, 'readiness', side_effect=RuntimeError('fixture not ready')):
            with self.assertRaisesRegex(RuntimeError, 'fixture not ready'):
                self.helper.activate()
        self.assertFalse(self.helper.CURRENT.exists())
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        self.assertEqual(RealPath(str(self.helper.DB) + '-wal').read_bytes(), self.fixture.original_wal)
        state = self.helper.load(self.helper.HIGHSTATE)
        self.assertEqual(state['highest_sequence'], 5)
        self.assertEqual(state['history'][-1]['result'], 'rolled_back')
        self.assertFalse(self.helper.JOURNAL.exists())
        self.assertTrue(self.fixture.running)

    def test_interruption_between_journal_and_highwater_preserves_consumed_sequence(self):
        self.fixture.running = False
        self.helper.write(self.helper.CHECKPOINT, self.fixture.snapshot())
        self.helper.write(self.helper.JOURNAL, dict(format=1, previous=None, version='0.1.1', sequence=5))
        self.helper.DB.write_bytes(b'incomplete-candidate-database')
        self.helper.recover()
        state = self.helper.load(self.helper.HIGHSTATE)
        self.assertEqual(state['highest_sequence'], 5, 'Recovery must consume the signed journal sequence even if status write was interrupted')
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        command_count = len(self.fixture.commands)
        self.helper.recover()
        self.assertEqual(len(self.fixture.commands), command_count, 'Completed recovery must be idempotent')

    def test_failed_restore_keeps_recovery_journal_and_traffic_stopped(self):
        self.fixture.fail_restore = True
        with patch.object(self.helper, 'readiness', side_effect=RuntimeError('fixture not ready')):
            with self.assertRaises(subprocess.CalledProcessError):
                self.helper.activate()
        self.assertTrue(self.helper.JOURNAL.exists())
        self.assertFalse(self.fixture.running)
        self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 5)

    def test_final_symlink_bundle_and_traversal_targets_are_rejected(self):
        other = self.fixture.root / 'outside-bundle.json'
        other.write_text(self.helper.BUNDLE.read_text())
        self.helper.BUNDLE.unlink()
        self.helper.BUNDLE.symlink_to(other)
        with self.assertRaises(OSError):
            self.helper.activate()
        self.assertFalse(self.fixture.commands)
        for target in (self.fixture.versions / '../outside', self.fixture.root / 'outside/5', RealPath('relative/5')):
            with self.assertRaises(RuntimeError):
                self.helper.point(target)

    def test_existing_sequence_directory_symlink_is_rejected_before_payload_execution(self):
        outside = self.fixture.root / 'outside-version'
        outside.mkdir()
        (self.fixture.versions / '5').symlink_to(outside, target_is_directory=True)
        with self.assertRaises((RuntimeError, OSError)):
            self.helper.activate()
        self.assertFalse((outside / 'riverlb').exists(), 'Never write through a symlinked version directory')
        self.assertFalse(any('--version' in call for call in self.fixture.commands))
        self.assertFalse(any(RealPath(call[0]).name == 'systemctl' for call in self.fixture.commands))

    def test_invalid_previous_selector_is_rejected_before_stopping_service(self):
        outside = self.fixture.root / 'outside-current'
        outside.mkdir()
        self.helper.CURRENT.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((RuntimeError, OSError)):
            self.helper.activate()
        self.assertTrue(self.fixture.running)
        self.assertFalse(any(RealPath(call[0]).name == 'systemctl' for call in self.fixture.commands))

    def test_restored_database_directory_is_synced_before_recovery_marker_removed(self):
        self.fixture.running = False
        self.helper.write(self.helper.CHECKPOINT, self.fixture.snapshot())
        self.helper.write(self.helper.JOURNAL, dict(format=1, previous=None, version='0.1.1', sequence=5))
        directories = []
        original = os.fsync
        def sync(fd):
            info = os.fstat(fd)
            for path in (self.helper.DB.parent, self.helper.UPDATER, self.helper.CURRENT.parent):
                if path.stat().st_ino == info.st_ino and path.stat().st_dev == info.st_dev:
                    directories.append((path, self.helper.JOURNAL.exists()))
            return original(fd)
        with patch.object(self.helper.os, 'fsync', sync):
            self.helper.recover()
        self.assertIn((self.helper.DB.parent, True), directories, 'Restored DB/WAL directory must be durable before clearing recovery')
        self.assertIn((self.helper.UPDATER, False), directories, 'Recovery marker deletion must be durable')

    def test_previous_signed_reader_verifies_checkpoints_and_restores_its_own_schema(self):
        previous, reader = self.fixture.previous_version()
        with patch.object(self.helper, 'readiness', side_effect=RuntimeError('fixture not ready')):
            with self.assertRaisesRegex(RuntimeError, 'fixture not ready'):
                self.helper.activate()
        self.assertEqual(self.helper.CURRENT.resolve(), previous)
        operations = [call for call in self.fixture.commands if len(call) > 1 and call[1] in ('update-verify', 'backup', 'restore')]
        self.assertEqual([call[1] for call in operations], ['update-verify', 'backup', 'restore'])
        self.assertTrue(all(call[0] == str(reader) for call in operations),
                        'The baseline binary may not understand a newer installed version checkpoint')
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)

    def test_live_database_lock_refuses_recovery_and_retains_checkpoint(self):
        self.fixture.interrupted()
        original = self.helper.DB.read_bytes()
        with self.helper.exclusive_lock(RealPath(str(self.helper.DB) + '.lock')):
            with self.assertRaises(BlockingIOError):
                self.helper.recover()
        self.assertEqual(self.helper.DB.read_bytes(), original)
        self.assertTrue(self.helper.JOURNAL.exists())
        self.assertTrue(self.helper.CHECKPOINT.exists())
        self.assertFalse(any(call[1] == 'restore' for call in self.fixture.commands))
        self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 5)

    def test_preflight_allows_only_an_existing_root_fixture_updater_while_lock_is_held(self):
        self.fixture.updater_process()
        self.fixture.interrupted()
        with self.helper.exclusive_lock(self.helper.UPDATER / 'update.lock'):
            self.assertTrue(self.helper.active_updater())
            self.helper.main('preflight')
            self.assertTrue(self.helper.JOURNAL.exists(), 'Candidate start must not roll back an update still holding its lock')
            for action in ('recover', 'activate'):
                with self.assertRaisesRegex(RuntimeError, 'already in progress'):
                    self.helper.main(action)
        self.assertFalse(self.fixture.commands)

    def test_preflight_refuses_unrelated_missing_or_unsafe_process_markers(self):
        with self.helper.exclusive_lock(self.helper.UPDATER / 'update.lock'):
            for args in ([b'/usr/bin/python3', b'/tmp/unrelated-helper', b'activate'],
                         [b'/usr/bin/python3', str(self.helper.HELPER).encode(), b'recover']):
                self.fixture.updater_process(args=args)
                self.assertFalse(self.helper.active_updater())
                with self.assertRaisesRegex(RuntimeError, 'already in progress'):
                    self.helper.main('preflight')
            self.helper.write(self.helper.RUNNING, {'pid': 9999})
            self.assertFalse(self.helper.active_updater())
            with self.assertRaisesRegex(RuntimeError, 'already in progress'):
                self.helper.main('preflight')
            self.fixture.updater_process()
            self.helper.RUNNING.chmod(0o666)
            self.assertFalse(self.helper.active_updater())
            with self.assertRaisesRegex(RuntimeError, 'already in progress'):
                self.helper.main('preflight')

    def test_every_start_preflight_recovers_journal_and_removes_stale_marker(self):
        self.fixture.interrupted()
        self.helper.write(self.helper.RUNNING, {'pid': 9999})
        self.helper.main('preflight')
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        self.assertFalse(self.helper.JOURNAL.exists())
        self.assertFalse(self.helper.RUNNING.exists())
        self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 5)

    def test_readiness_preserves_previously_up_virtual_servers_and_allows_existing_failures(self):
        baseline = self.fixture.local_status()
        baseline['virtual_servers'] = [dict(name='healthy', enabled=True, state='up'),
                                       dict(name='already-down', enabled=True, state='down'),
                                       dict(name='disabled', enabled=False, state='up')]
        status = dict(baseline, version=self.fixture.manifest['version'], virtual_servers=[
            dict(name='healthy', enabled=True, state='up'),
            dict(name='already-down', enabled=True, state='down')])
        with patch.object(self.helper, 'local_status', return_value=status), patch.object(self.helper.time, 'sleep') as sleep:
            self.fixture.original_readiness(self.fixture.snapshot(), baseline, self.fixture.manifest)
        sleep.assert_not_called()

    def test_readiness_refuses_version_revision_management_pending_ha_and_healthy_server_regressions(self):
        baseline = self.fixture.local_status()
        baseline['virtual_servers'] = [dict(name='healthy', enabled=True, state='up')]
        valid = dict(baseline, version=self.fixture.manifest['version'])
        changes = [dict(version='0.1.0'), dict(revision=2), dict(management='192.0.2.99:18090'),
                   dict(management_secure=True), dict(confirmation_pending=True), dict(ha_role='active'),
                   dict(virtual_servers=[]), dict(virtual_servers=[dict(name='healthy', enabled=True, state='down')])]
        for change in changes:
            with self.subTest(change=change):
                status = dict(valid, **change)
                with patch.object(self.helper, 'local_status', return_value=status), patch.object(self.helper.time, 'sleep') as sleep:
                    with self.assertRaisesRegex(RuntimeError, 'readiness failed'):
                        self.fixture.original_readiness(self.fixture.snapshot(), baseline, self.fixture.manifest)
                    self.assertEqual(sleep.call_count, 30)

    def test_readiness_retries_temporary_socket_errors_without_logging_private_state(self):
        baseline = self.fixture.local_status()
        valid = dict(baseline, version=self.fixture.manifest['version'])
        with patch.object(self.helper, 'local_status', side_effect=[OSError('private fixture error'), valid]), \
                patch.object(self.helper.time, 'sleep') as sleep:
            self.fixture.original_readiness(self.fixture.snapshot(), baseline, self.fixture.manifest)
        sleep.assert_called_once_with(1)

    def test_group_writable_hardlinked_wrong_owner_and_symlink_state_are_rejected(self):
        state = self.helper.BUNDLE
        state.chmod(0o660)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            self.helper.load(state)
        state.chmod(0o600)
        link = state.with_name('hardlink.json')
        os.link(state, link)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            self.helper.load(state)
        link.unlink()
        with patch.object(self.helper, 'OWNER', os.geteuid() + 1):
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                self.helper.load(state)
        state.unlink()
        state.symlink_to(self.helper.HIGHSTATE)
        with self.assertRaises(OSError):
            self.helper.load(state)

    def test_unsafe_or_linked_state_directory_is_rejected_before_loading(self):
        self.helper.DB.parent.chmod(0o770)
        with self.assertRaisesRegex(RuntimeError, 'directory'):
            self.helper.load(self.helper.BUNDLE)
        self.helper.DB.parent.chmod(0o700)
        alias = self.fixture.root / 'linked-db-directory'
        alias.symlink_to(self.helper.DB.parent, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'directory'):
            self.helper.load(alias / self.helper.BUNDLE.name)

    def test_recovery_cannot_decrease_existing_highwater_or_use_unmatched_reader(self):
        self.fixture.interrupted()
        self.helper.write(self.helper.HIGHSTATE, dict(highest_sequence=9, history=[]))
        journal = self.helper.load(self.helper.JOURNAL)
        journal['reader'] = str(self.fixture.root / 'untrusted-reader')
        self.helper.write(self.helper.JOURNAL, journal)
        with self.assertRaisesRegex(RuntimeError, 'reader'):
            self.helper.recover()
        self.assertFalse(self.fixture.commands)
        journal['reader'] = str(self.helper.BASE)
        self.helper.write(self.helper.JOURNAL, journal)
        self.helper.recover()
        self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 9)

    def test_initial_stop_error_restarts_previous_service_without_database_changes(self):
        original_run = self.fixture.run
        def fail_first_stop(args):
            if RealPath(str(args[0])).name == 'systemctl' and str(args[1]) == 'stop':
                original_run(args)
                raise subprocess.TimeoutExpired([str(value) for value in args], 90)
            return original_run(args)
        with patch.object(self.helper, 'run', fail_first_stop):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.helper.activate()
        self.assertTrue(self.fixture.running, 'A stop timeout may have stopped the old service; start it before returning failure')
        self.assertFalse(self.helper.CURRENT.exists())
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        self.assertEqual(RealPath(str(self.helper.DB) + '-wal').read_bytes(), self.fixture.original_wal)
        self.assertFalse(self.helper.JOURNAL.exists())
        self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 4)

    def test_unsafe_stale_checkpoint_restarts_previous_service_without_replacing_it(self):
        checkpoint = self.fixture.root / 'unmanaged-checkpoint.json'
        checkpoint.write_text('fixture private checkpoint')
        self.helper.CHECKPOINT.symlink_to(checkpoint)
        with self.assertRaises(OSError):
            self.helper.activate()
        self.assertTrue(self.fixture.running)
        self.assertFalse(self.helper.CURRENT.exists())
        self.assertFalse(self.helper.JOURNAL.exists())
        self.assertEqual(checkpoint.read_text(), 'fixture private checkpoint')
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        self.assertFalse(any(call[1] == 'backup' for call in self.fixture.commands))

    def test_checkpoint_failure_restarts_old_service_before_a_recovery_journal_exists(self):
        previous, _ = self.fixture.previous_version()
        original_run = self.fixture.run
        def fail_checkpoint(args):
            if str(args[1]) == 'backup':
                raise subprocess.CalledProcessError(1, [str(value) for value in args],
                                                    output='fixture-password-hash', stderr='fixture-secret')
            return original_run(args)
        with patch.object(self.helper, 'run', fail_checkpoint):
            with self.assertRaises(subprocess.CalledProcessError):
                self.helper.activate()
        self.assertTrue(self.fixture.running)
        self.assertEqual(self.helper.CURRENT.resolve(), previous)
        self.assertEqual(self.helper.DB.read_bytes(), self.fixture.original_database)
        self.assertFalse(self.helper.JOURNAL.exists())
        state = self.helper.load(self.helper.HIGHSTATE)
        self.assertEqual(state['highest_sequence'], 4)
        self.assertNotIn('fixture-password-hash', json.dumps(state))

    def test_fifo_state_refused_before_a_blocking_open(self):
        fifo = self.helper.UPDATER / 'fixture-state-fifo'
        os.mkfifo(fifo, 0o600)
        original_open = os.open
        def checked_open(path, flags, *args, **kwargs):
            if RealPath(path) == fifo:
                self.assertTrue(flags & os.O_NONBLOCK, 'Validation must not block on a FIFO before fstat can reject it')
            return original_open(path, flags, *args, **kwargs)
        with patch.object(self.helper.os, 'open', checked_open):
            for operation in (self.helper.secure_file, self.helper.load, self.helper.remove):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                        operation(fifo)
        self.assertTrue(fifo.exists(), 'Invalid privileged state must remain for diagnosis, without following it')

    def test_verified_bundle_copy_is_outside_daemon_writable_database_directory(self):
        self.helper.activate()
        verified = next(call for call in self.fixture.commands if call[1] == 'update-verify')
        copy = RealPath(verified[verified.index('--bundle') + 1])
        self.assertIn(self.helper.UPDATER, copy.parents,
                      'A 0700 directory does not isolate processes that share UID0; use privileged filesystem scope')
        self.assertNotIn(self.helper.DB.parent, copy.parents)

    def test_payload_swap_after_verification_is_refused_before_execution_or_service_stop(self):
        original_run = self.fixture.run
        changed = bytes([self.fixture.payload[0] ^ 1]) + self.fixture.payload[1:]
        for payload in (changed, self.fixture.payload + b'length-change'):
            with self.subTest(length=len(payload)):
                def swap_verified_copy(args):
                    result = original_run(args)
                    if str(args[1]) == 'update-verify':
                        copy = RealPath(args[args.index('--bundle') + 1])
                        bundle = self.helper.load(copy)
                        bundle['payload'] = base64.b64encode(payload).decode()
                        self.helper.write(copy, bundle)
                    return result
                with patch.object(self.helper, 'run', swap_verified_copy):
                    with self.assertRaisesRegex(RuntimeError, 'Verified update payload changed'):
                        self.helper.activate()
                self.assertFalse((self.fixture.versions / '5').exists())
                self.assertFalse(any('--version' in call for call in self.fixture.commands))
                self.assertFalse(any(RealPath(call[0]).name == 'systemctl' for call in self.fixture.commands))
                self.assertTrue(self.fixture.running)
                self.assertFalse(self.helper.JOURNAL.exists())
                self.assertEqual(self.helper.load(self.helper.HIGHSTATE)['highest_sequence'], 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
