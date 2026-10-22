"""Qualification admission, ownership, report redaction and interruption regressions."""
import importlib.util
import json
import os
from pathlib import Path
import signal
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

    def test_timeout_kills_owned_process_group_and_bounds_logs(self):
        log = self.root / 'private.log'
        start = time.monotonic()
        with self.assertRaisesRegex(m.Rejected,'stage-timeout'):
            m.bounded_command([sys.executable,'-c',"import time; print('x'*2000000,flush=True); time.sleep(60)"],log,dict(os.environ),0.5)
        self.assertLess(time.monotonic()-start,15)
        self.assertLessEqual(log.stat().st_size,1024*1024)

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
