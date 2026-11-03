#!/usr/bin/env python3
"""Development delivery must fail closed on CI and untrusted bundle contents."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location('lab_' + name, ROOT / 'scripts/lab' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prepare, apply = module('prepare'), module('apply')
SHA = 'a' * 40


def runs():
    return [dict(id=i, head_sha=SHA, head_branch='release-2.0',
                 path='.github/workflows/' + name, status='completed',
                 conclusion='success', html_url=f'https://github.com/example/runs/{i}')
            for i, name in enumerate(['ci.yml', 'security.yml', 'rpm.yml'], 1)]


class Gates(unittest.TestCase):
    def test_all_exact_commit_runs_pass(self):
        self.assertEqual(len(prepare.qualified_runs(runs(), SHA)), 3)

    def test_missing_pending_failed_and_cancelled_rejected(self):
        cases = [runs()[:-1]]
        for conclusion, status in [('failure', 'completed'), ('cancelled', 'completed'),
                                   (None, 'in_progress'), ('skipped', 'completed')]:
            changed = runs()
            changed[0].update(conclusion=conclusion, status=status)
            cases.append(changed)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                prepare.qualified_runs(candidate, SHA)

    def test_new_failed_attempt_cannot_hide_behind_old_success(self):
        candidate = runs()
        candidate.append(dict(candidate[0], id=99, conclusion='failure'))
        with self.assertRaises(ValueError):
            prepare.qualified_runs(candidate, SHA)

    def test_other_commit_or_branch_does_not_qualify(self):
        for key, value in [('head_sha', 'b' * 40), ('head_branch', 'feature')]:
            candidate = runs()
            candidate[0][key] = value
            with self.assertRaises(ValueError):
                prepare.qualified_runs(candidate, SHA)

    def test_failed_optional_triggered_workflow_blocks(self):
        candidate = runs()
        candidate.append(dict(candidate[0], id=99, path='.github/workflows/reproducible.yml',
                              conclusion='failure'))
        with self.assertRaises(ValueError):
            prepare.qualified_runs(candidate, SHA)


class Bundles(unittest.TestCase):
    def bundle(self, root, mutation=None, extra=None):
        rpm = b'fixture RPM bytes'
        receipt = dict(repository=prepare.REPO, branch=prepare.BRANCH, commit=SHA,
                       workflows=[dict(path=r['path'], conclusion='success') for r in runs()],
                       packages={'riverlb-1.x86_64.rpm': hashlib.sha256(rpm).hexdigest()})
        manifest = dict(commit=SHA, dirty=False)
        if mutation:
            mutation(receipt, manifest)
        files = [('riverlb-1.x86_64.rpm', rpm), ('deployment.json', json.dumps(receipt).encode()),
                 ('build-manifest.json', json.dumps(manifest).encode())]
        bundle = root / 'bundle.tar'
        with tarfile.open(bundle, 'w') as archive:
            for name, data in files + (extra or []):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        destination = root / 'unpacked'
        destination.mkdir()
        return bundle, hashlib.sha256(bundle.read_bytes()).hexdigest(), destination

    def test_valid_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(apply.unpack(*self.bundle(Path(directory)))['commit'], SHA)

    def test_transferred_corruption_rejected_before_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _, dest = self.bundle(Path(directory))
            with self.assertRaises(ValueError):
                apply.unpack(bundle, '0' * 64, dest)
            self.assertEqual(list(dest.iterdir()), [])

    def test_paths_and_duplicates_rejected(self):
        for name in ['../outside', '/absolute.rpm', 'nested/evil.rpm', 'deployment.json']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                args = self.bundle(Path(directory), extra=[(name, b'bad')])
                with self.assertRaises(ValueError):
                    apply.unpack(*args)
                self.assertFalse((Path(directory) / 'outside').exists())

    def test_wrong_source_dirty_missing_ci_and_changed_package_rejected(self):
        mutations = [lambda r, m: m.update(commit='b' * 40),
                     lambda r, m: m.update(dirty=True),
                     lambda r, m: r.update(workflows=[]),
                     lambda r, m: r['packages'].update({'riverlb-1.x86_64.rpm': '0' * 64})]
        for mutation in mutations:
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    apply.unpack(*self.bundle(Path(directory), mutation))


class HelperQuiesce(unittest.TestCase):
    def test_legacy_absent_units_are_allowed(self):
        with patch.object(apply, 'ssh', return_value='not-found\n') as remote:
            apply.stop_auxiliary('a')
        self.assertEqual(remote.call_count, 2)
        self.assertTrue(all('show' in call.args for call in remote.call_args_list))

    def test_loaded_helper_stop_failure_is_not_ignored(self):
        with patch.object(apply, 'ssh', side_effect=['loaded\n', RuntimeError('stop failed')]):
            with self.assertRaisesRegex(RuntimeError, 'stop failed'):
                apply.stop_auxiliary('a')

    def test_backup_and_rollback_scope_includes_private_state(self):
        self.assertIn('etc/riverlb-privileged', apply.STATE_PATHS)
        self.assertIn('var/lib/riverlb-privileged', apply.STATE_PATHS)
        self.assertIn('var/lib/riverlb-updater-work', apply.STATE_PATHS)

    def test_running_update_blocks_deployment(self):
        with patch.object(apply, 'ssh', return_value='activating\n'):
            with self.assertRaisesRegex(RuntimeError, 'active application update'):
                apply.no_active_update('a')


class Recovery(unittest.TestCase):
    def simulate(self, backup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / 'previous.rpm'
            old.write_bytes(b'previous')
            baseline = dict(packages=[str(old)],
                            package_sha256={str(old): hashlib.sha256(old.read_bytes()).hexdigest()},
                            nodes={n: {'binary_sha256': 'old'} for n in ['a', 'b']})
            (root / 'development-current.json').write_text(json.dumps(baseline))
            calls, installed, backups = [], set(), set()

            def unpack(bundle, digest, target):
                for name in ['riverlb-main.rpm', 'riverlb-appliance-test.rpm']:
                    (target / name).write_bytes(b'candidate')
                return dict(commit=SHA)

            def ssh(node, *args):
                calls.append((node, args))
                if args[:2] == ('systemctl', 'show'):
                    if '--property=ActiveState' in args:
                        return 'inactive\n'
                    return 'loaded\n'
                if args[0] == 'hostname':
                    return 'riverlb-' + node
                if args[0] == 'sha256sum':
                    return ('new' if node in installed else 'old') + ' file'
                if args[0] == 'python3':
                    return json.dumps(['etc/riverlb', 'var/lib/riverlb'])
                if args[0] == 'tar' and '-czf' in args:
                    if backup_failure and node == 'b':
                        raise RuntimeError('Backup failed')
                    backups.add(node)
                if args[0] == 'rpm' and '-Uvh' in args and '/new/' in args[-1]:
                    installed.add(node)
                if args[0] == 'cat':
                    return json.dumps(dict(commit=SHA))
                if args[0] == 'rm':
                    self.assertIn(node, backups, 'Never remove state without a stopped backup')
                return ''

            def health(node):
                if not backup_failure and node == 'b' and node in installed:
                    installed.remove(node)
                    raise RuntimeError('New B failed readiness')

            with patch.object(apply, 'ROOT', root), patch.object(apply, 'unpack', unpack), \
                    patch.object(apply, 'ssh', ssh), patch.object(apply, 'copy'), \
                    patch.object(apply, 'health', health), patch.object(apply.os, 'geteuid', return_value=0), \
                    patch('sys.argv', ['apply', '/unused', '--sha256', 'unused']):
                with self.assertRaises(RuntimeError):
                    apply.main()
            self.assertEqual(json.loads((root / 'development-current.json').read_text()), baseline)
            return calls

    def test_second_node_failure_restores_both_stopped_states(self):
        calls = self.simulate()
        self.assertEqual({node for node, args in calls if args[0] == 'rm'}, {'a', 'b'})
        self.assertEqual({node for node, args in calls if args[0] == 'tar' and '-xzf' in args}, {'a', 'b'})

    def test_backup_failure_never_removes_unbacked_node(self):
        calls = self.simulate(backup_failure=True)
        self.assertEqual({node for node, args in calls if args[0] == 'rm'}, {'a'})
        self.assertIn(('b', ('systemctl', 'start', 'riverlb')), calls)


if __name__ == '__main__':
    unittest.main()
