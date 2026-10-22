"""Qualification admission, ownership, report redaction and interruption regressions."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qualify', ROOT / 'scripts/qualify-appliance.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def context():
    return dict(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY=m.REPOSITORY,
                GITHUB_REF='refs/heads/release-2.0', RUNNER_ENVIRONMENT='github-hosted',
                GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                RIVERLB_IMAGE_FIRMWARE='bios')


class Qualification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = context()

    def test_admission_rejects_prs_forks_other_refs_persistent_hosts(self):
        self.assertEqual(m.identity(self.env), 'bios')
        cases = dict(GITHUB_EVENT_NAME=['pull_request', 'pull_request_target', 'push', 'workflow_run'],
                     GITHUB_REPOSITORY=['attacker/RiverLB'], GITHUB_REF=['refs/pull/75/merge', 'refs/heads/feature', 'refs/tags/v2.0.0'],
                     RUNNER_ENVIRONMENT=['self-hosted', ''], GITHUB_SHA=['bad', 'a'*39],
                     GITHUB_RUN_ID=['../other'], RIVERLB_IMAGE_FIRMWARE=['../bios'])
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(m.Rejected):
                    m.identity({**self.env, key: value})

    def test_actual_negative_disk_preflight_is_actionable(self):
        measured = {}
        with self.assertRaisesRegex(m.Rejected, 'insufficient-disk'):
            m.resources(self.root, 1000000, measured)
        self.assertGreater(measured['required_disk_bytes'], measured['free_disk_bytes'])
        self.assertGreater(measured['free_disk_bytes'], 0)

    def test_memory_pressure_rejected_before_vm_start(self):
        with patch.object(Path, 'read_text', return_value='MemAvailable: 1024 kB\n'):
            with self.assertRaisesRegex(m.Rejected, 'insufficient-memory'):
                m.resources(self.root, 0)

    def test_never_adopt_existing_workspace_or_symlink(self):
        dist = self.root / 'dist'
        dist.mkdir()
        (dist / 'precious').write_text('preserve')
        with self.assertRaisesRegex(m.Rejected, 'workspace-not-fresh'):
            m.fresh_workspace(self.root, self.env)
        self.assertEqual((dist / 'precious').read_text(), 'preserve')
        other = self.root / 'other'
        other.mkdir()
        (dist / 'precious').unlink()
        dist.rmdir()
        dist.symlink_to(other, target_is_directory=True)
        with self.assertRaises(m.Rejected):
            m.fresh_workspace(self.root, self.env)

    def test_cleanup_exact_ownership_and_symlink_boundaries(self):
        marker = m.fresh_workspace(self.root, self.env)
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'preserve').write_text('private')
        (self.root / 'dist/linked').symlink_to(outside, target_is_directory=True)
        evidence = self.root / 'dist' / m.EVIDENCE
        evidence.mkdir()
        (evidence / 'report.json').write_text('{}')
        calls = []
        def execute(args, **kwargs):
            calls.append(args)
            if args[1] == 'ps':
                self.assertIn('label=' + m.LABEL + '=' + marker['job'], args)
                return subprocess.CompletedProcess(args, 0, stdout='b'*64+'\n')
            if args[1] == 'inspect':
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{'Config': {'Labels': {m.LABEL: marker['job']}}}]))
            return subprocess.CompletedProcess(args, 0)
        m.cleanup(self.root, self.env, run=execute)
        self.assertEqual((outside / 'preserve').read_text(), 'private')
        self.assertTrue((evidence / 'report.json').exists())
        self.assertEqual(calls[-1][-1], 'b'*64)
        self.assertFalse((self.root / 'dist/linked').exists())
        self.assertFalse((self.root / 'dist' / m.OWNER).exists())

    def test_cleanup_refuses_foreign_run_and_container(self):
        m.fresh_workspace(self.root, self.env)
        with self.assertRaises(m.Rejected):
            m.cleanup(self.root, {**self.env, 'GITHUB_RUN_ID':'999'}, run=lambda *_a, **_k: self.fail('must not invoke Podman'))
        commands = []
        def execute(args, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, stdout='b'*64+'\n' if args[1]=='ps' else json.dumps([{'Config': {'Labels': {m.LABEL:'foreign'}}}]))
        with self.assertRaisesRegex(m.Rejected, 'container-ownership-mismatch'):
            m.cleanup(self.root, self.env, run=execute)
        self.assertFalse(any(args[1]=='rm' for args in commands))

    def test_public_reports_accept_only_known_fixture_labels(self):
        path = self.root / 'report.json'
        valid = dict(status='passed',firmware='bios',tests=sorted(m.BOOT_TESTS))
        path.write_text(json.dumps(valid))
        self.assertEqual(m.fixture_report(path,'bios',m.BOOT_TESTS),valid)
        for change in ({'password':'do-not-publish'}, {'tests':['do-not-publish']}, {'firmware':'uefi'}, {'status':'failed'}):
            path.write_text(json.dumps({**valid,**change}))
            with self.assertRaises(m.Rejected):
                m.fixture_report(path,'bios',m.BOOT_TESTS)
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(m.Rejected):
            m.fixture_report(path,'bios',m.BOOT_TESTS)

    def test_later_failure_preserves_validated_identity_and_boot_evidence(self):
        # Controller regression only: synthetic files are not guest qualification.
        m.fresh_workspace(self.root, self.env)
        lock = json.loads((ROOT / 'packaging/build-inputs.lock.json').read_text())
        for folder in ('packaging', 'appliance', 'dist/rpm', 'dist/iso', 'dist/image', 'dist/test-vm'):
            (self.root / folder).mkdir(parents=True, exist_ok=True)
        (self.root / 'packaging/build-inputs.lock.json').write_text(json.dumps(lock))
        (self.root / 'appliance/base-media.json').write_text((ROOT / 'appliance/base-media.json').read_text())
        (self.root / 'dist/rpm/build-manifest.json').write_text(json.dumps(dict(commit=self.env['GITHUB_SHA'], dirty=False, build_inputs=lock)))
        for name in ('riverlb-image.iso', 'riverlb-installer.iso'):
            (self.root / 'dist/iso' / name).write_bytes(b'synthetic media')
        for name in ('riverlb.qcow2', 'riverlb.raw'):
            (self.root / 'dist/image' / name).write_bytes(b'synthetic disk')
        (self.root / 'dist/test-vm/report.json').write_text(json.dumps(dict(status='passed',firmware='bios',tests=sorted(m.BOOT_TESTS))))
        report = dict(status='ready',source=self.env['GITHUB_SHA'],firmware='bios',stages={})
        def execute(args, *_):
            if args[-1] == 'scripts/test-installer.sh':
                folder = self.root / 'dist/test-installer-vm'
                folder.mkdir()
                (folder / 'failure.json').write_text(json.dumps(dict(schema=1, firmware='bios', case='graphical', checkpoint='graphical-summary', reason='gui-session-bus-missing')))
                raise m.Rejected('command-failed')
        with patch.object(m, 'bounded_command', side_effect=execute):
            with self.assertRaisesRegex(m.Rejected, 'command-failed'):
                m.qualify(self.root, self.env, report)
        saved = json.loads((self.root / 'dist' / m.EVIDENCE / 'report.json').read_text())
        self.assertEqual(saved['stage'], 'installer-suite')
        self.assertEqual(set(saved['artifacts']), {'riverlb-image.iso','riverlb-installer.iso','riverlb.qcow2','riverlb.raw'})
        self.assertEqual(saved['boot']['tests'], sorted(m.BOOT_TESTS))
        self.assertEqual(saved['installer_failure']['reason'], 'gui-session-bus-missing')
        self.assertNotIn('installer-suite', saved['stages'])
        self.assertNotEqual(saved['status'], 'passed')

    def test_guest_probe_uses_actual_user_bus_not_initial_proc_bus(self):
        import installer_probe as probe
        proc = self.root / 'proc'
        entry = proc / '123'
        entry.mkdir(parents=True)
        runtime = self.root / 'runtime'
        runtime.mkdir()
        (entry / 'cmdline').write_bytes(b'/usr/bin/python3\0/sbin/anaconda\0')
        (entry / 'environ').write_bytes(b'DBUS_SESSION_BUS_ADDRESS=unix:path=/wrong\0PASSWORD=do-not-copy\0XDG_RUNTIME_DIR=' + os.fsencode(runtime) + b'\0')
        with socket.socket(socket.AF_UNIX) as bus:
            bus.bind(str(runtime / 'bus'))
            env = probe.discover_environment(proc)
            self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=' + str(runtime / 'bus'))
            self.assertNotIn('PASSWORD', env)
        (runtime / 'bus').unlink()
        with self.assertRaisesRegex(probe.ProbeFailure, 'gui-session-bus-missing'):
            probe.discover_environment(proc)

    def test_serial_probe_waits_for_late_completion(self):
        # Actual local shell transport only; this does not boot or qualify a guest.
        import installer as fixture
        serial = self.root / 'serial.log'
        original_command = fixture.probe_command
        processes = []
        class Console:
            def __init__(self, _port): pass
            def chord(self, *_keys): pass
            def close(self): pass
            def type(self, command):
                processes.append(subprocess.Popen(['bash', '-c', command.replace('/dev/ttyS0', shlex.quote(str(serial))).replace(' > ', ' >> ')]))
        def command(script, marker):
            return original_command(script, marker, serial)
        try:
            with patch.object(fixture, 'Console', Console), patch.object(fixture, 'probe_command', command):
                output = fixture.shell(serial, "import time;time.sleep(3.2);print('late-completion')")
            self.assertIn('late-completion', output)
            self.assertNotIn('RIVERLB_PROBE_DONE_', output)
            self.assertTrue(all(process.wait(timeout=5) == 0 for process in processes))
            self.assertGreaterEqual(len(processes), 2)
            with self.assertRaises(ValueError):
                original_command('print(1)', 'invalid-marker')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait()

    def test_unready_console_never_receives_probe_payload(self):
        import installer as fixture
        serial = self.root / 'unready.serial'
        typed = []
        class Console:
            def __init__(self, _port): pass
            def chord(self, *_keys): pass
            def close(self): pass
            def type(self, command): typed.append(command)
        with patch.object(fixture, 'Console', Console):
            with self.assertRaisesRegex(fixture.InstallerFailure, 'shell-not-ready'):
                fixture.shell(serial, 'sensitive-probe-payload', ready_seconds=0.1)
        self.assertTrue(typed)
        self.assertTrue(all(command.startswith('printf riverlb_shell_ready_') for command in typed))

    def test_probe_transport_payload_uses_lowercase_hex_and_guest_deadline(self):
        import installer as fixture
        import zlib
        command = fixture.probe_command(fixture.GUI_PROBE, 'RIVERLB_PROBE_DONE_' + 'a'*16)
        self.assertIn('signal.alarm(30)', command)
        payload = zlib.compress(fixture.GUI_PROBE.encode()).hex()
        self.assertIn(payload, command)
        self.assertEqual(payload, payload.lower())
        self.assertLess(len(command), 4096)  # Linux canonical console input limit.

    def test_hung_probe_returns_completion_after_guest_deadline(self):
        import installer as fixture
        serial = self.root / 'hung-probe.serial'
        marker = 'RIVERLB_PROBE_DONE_' + 'b'*16
        script = "import time;print('RIVERLB_GUI_STAGE=accessibility-query',flush=True);time.sleep(120)"
        command = fixture.probe_command(script, marker, serial)
        started = time.monotonic()
        subprocess.run(['bash', '-c', command], check=True, timeout=35)
        self.assertLess(time.monotonic() - started, 35)
        output = serial.read_text()
        self.assertIn('RIVERLB_GUI_STAGE=accessibility-query', output)
        self.assertIn(marker, output)

    def test_installer_diagnostics_allow_only_known_codes(self):
        path = self.root / 'failure.json'
        valid = dict(schema=1, firmware='bios', case='graphical', checkpoint='graphical-summary', reason='gui-session-bus-missing')
        path.write_text(json.dumps(valid))
        self.assertEqual(m.installer_failure(path, 'bios'), valid)
        for extra in ({'password':'do-not-copy'}, {'reason':'do-not-copy'}, {'case':'do-not-copy'}, {'checkpoint':'do-not-copy'}, {'firmware':'uefi'}):
            path.write_text(json.dumps({**valid, **extra}))
            with self.assertRaises(m.Rejected):
                m.installer_failure(path, 'bios')

    def test_timeout_kills_owned_process_group_and_bounds_logs(self):
        log = self.root / 'private.log'
        start = time.monotonic()
        with self.assertRaisesRegex(m.Rejected,'stage-timeout'):
            m.bounded_command([sys.executable,'-c',"import time; print('x'*2000000,flush=True); time.sleep(60)"],log,dict(os.environ),0.5)
        self.assertLess(time.monotonic()-start,15)
        self.assertLessEqual(log.stat().st_size,1024*1024)

    def test_exited_leader_does_not_leave_a_running_descendant(self):
        pidfile = self.root / 'descendant.pid'
        child = "import time; time.sleep(60)"
        leader = ("import subprocess;from pathlib import Path;"
                  f"p=subprocess.Popen([{sys.executable!r},'-c',{child!r}]);"
                  f"Path({str(pidfile)!r}).write_text(str(p.pid))")
        start = time.monotonic()
        m.bounded_command([sys.executable, '-c', leader], self.root / 'orphan.log', dict(os.environ), 5)
        self.assertLess(time.monotonic() - start, 5)
        status = Path('/proc') / pidfile.read_text() / 'status'
        deadline = time.monotonic() + 2
        while True:
            try:
                state = next(line.split()[1] for line in status.read_text().splitlines() if line.startswith('State:'))
            except (FileNotFoundError, ProcessLookupError):
                break
            if state in ('Z', 'X'):  # Exited; the host may still be reaping it.
                break
            self.assertLess(time.monotonic(), deadline, 'descendant remained alive')
            time.sleep(0.01)

    def test_real_term_interrupt_has_private_evidence(self):
        ready = self.root / 'ready'
        driver = self.root / 'driver.py'
        driver.write_text(f'''import importlib.util,os,signal
from pathlib import Path
s=importlib.util.spec_from_file_location('m',{str(ROOT/'scripts/qualify-appliance.py')!r})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def stop(*_):raise m.Rejected('job-interrupted')
signal.signal(signal.SIGTERM,stop)
try:m.bounded_command([{sys.executable!r},'-c',"from pathlib import Path;import time;Path({str(ready)!r}).touch();time.sleep(60)"],Path({str(self.root/'term.log')!r}),dict(os.environ),120)
except m.Rejected as error:raise SystemExit(3 if str(error)=='job-interrupted' else 4)
''')
        process = subprocess.Popen([sys.executable,str(driver)])
        try:
            deadline = time.monotonic()+10
            while not ready.exists() and time.monotonic()<deadline:
                time.sleep(0.05)
            self.assertTrue(ready.exists())
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=15),3)
        finally:
            if process.poll() is None:
                process.kill();process.wait()


if __name__ == '__main__':
    unittest.main()
