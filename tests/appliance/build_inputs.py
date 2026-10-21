"""Adversarial tests for the retained-input trust boundary; no external services."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_inputs', ROOT / 'scripts/build-inputs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Inputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree = self.root / 'snapshot'
        self.tree.mkdir()
        (self.tree / 'almalinux-10.asc').write_text('fixture public key')
        (self.tree / 'rpm-repository').mkdir()
        (self.tree / 'rpm-repository/package.rpm').write_text('fixture package')
        self.inventory = dict(schema=1, snapshot_id='test', sources={}, files={})
        for path in self.tree.rglob('*'):
            if path.is_file():
                self.inventory['files'][str(path.relative_to(self.tree))] = dict(size=path.stat().st_size, sha256=m.digest(path))
        (self.tree / 'inventory.json').write_text(json.dumps(self.inventory))
        self.lock = dict(schema=1, snapshot_id='test', sources={}, inventory_sha256=m.digest(self.tree / 'inventory.json'),
                         rpm_signing_key={'sha256': m.digest(self.tree / 'almalinux-10.asc')})
        self.archive = self.root / 'inputs.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as tar:
            for path in sorted(self.tree.rglob('*')):
                tar.add(path, arcname=str(path.relative_to(self.tree)), recursive=False)
        self.lock.update(url='https://invalid.example/inputs.tar.gz', size=self.archive.stat().st_size,
                         sha256=m.digest(self.archive), unpacked_size=sum(p.stat().st_size for p in self.tree.rglob('*') if p.is_file()))

    def test_clean_extract_and_offline_cache(self):
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / (self.lock['sha256'] + '.tar.gz')).write_bytes(self.archive.read_bytes())
        with patch.object(m, 'download', side_effect=AssertionError('must not download')):
            tree = m.prepare(self.lock, cache, self.root)
            m.verify_tree(tree, self.lock)
            self.assertEqual(tree, m.prepare(self.lock, cache, self.root))

    def test_missing_altered_extra_files(self):
        package = self.tree / 'rpm-repository/package.rpm'
        for content in (None, 'tampered'):
            if content is None:
                package.unlink()
            else:
                package.write_text(content)
            with self.assertRaises(ValueError):
                m.verify_tree(self.tree, self.lock)
        package.write_text('fixture package')
        (self.tree / 'unexpected').touch()
        with self.assertRaises(ValueError):
            m.verify_tree(self.tree, self.lock)

    def test_changed_inventory_and_symlink(self):
        inventory = self.tree / 'inventory.json'
        inventory.write_text('{}')
        with self.assertRaises(ValueError):
            m.verify_tree(self.tree, self.lock)
        inventory.unlink()
        inventory.symlink_to(self.root / 'nonexistent')
        with self.assertRaises(ValueError):
            m.verify_tree(self.tree, self.lock)

    def test_archive_traversal_links_duplicates_and_size(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE), ('fifo', tarfile.FIFOTYPE),
                           ('duplicate', tarfile.REGTYPE), ('oversize', tarfile.REGTYPE)]:
            archive = self.root / 'bad.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '../escape'
                if name == 'oversize':
                    info.size = self.lock['unpacked_size'] + 1
                tar.addfile(info, io.BytesIO(b'x' * info.size) if info.isfile() else None)
                if name == 'duplicate':
                    tar.addfile(info, io.BytesIO())
            with tempfile.TemporaryDirectory(dir=self.root) as target:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    m.extract(archive, Path(target), self.lock)
        self.assertFalse((self.root / 'escape').exists())

    def test_unavailable_snapshot_no_fallback(self):
        with patch.object(m, 'download', side_effect=OSError('unavailable')) as download:
            with self.assertRaises(OSError):
                m.prepare(self.lock, self.root / 'cache', self.root)
            self.assertEqual(download.call_count, 1)

    def test_corrupt_cached_archive_no_fallback(self):
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / (self.lock['sha256'] + '.tar.gz')).write_bytes(b'bad')
        with patch.object(m, 'download', side_effect=AssertionError('no fallback')):
            with self.assertRaises(ValueError):
                m.prepare(self.lock, cache, self.root)

    def test_changed_source(self):
        (self.root / 'Cargo.lock').write_text('changed')
        self.lock['sources'] = {'Cargo.lock': '0' * 64}
        with self.assertRaises(ValueError):
            m.verify_sources(self.root, self.lock)

    def test_unsigned_and_untrusted_rpm_fail_closed(self):
        # rpmkeys returns zero for an unsigned package with valid digests.
        for output in ('package.rpm: digests OK\n', 'package.rpm: digests SIGNATURES NOT OK\n', ''):
            result = subprocess.CompletedProcess([], 0, stdout=output, stderr='')
            with patch.object(m.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                m.verify_signatures(self.tree, 'runtime')
        with patch.object(m.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['rpmkeys'])):
            with self.assertRaises(subprocess.CalledProcessError):
                m.verify_signatures(self.tree, 'runtime')
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='package.rpm: digests signatures OK\n', stderr='')):
            m.verify_signatures(self.tree, 'runtime')

    def test_oci_adapter_changes_only_transport_annotation(self):
        original = self.root / 'image.tar'
        target = self.root / 'normalized.tar'
        index = dict(schemaVersion=2, manifests=[dict(digest='sha256:' + 'a' * 64,
            annotations={'org.opencontainers.image.ref.name': 'registry/image@sha256:' + 'b' * 64,
                         'other': 'preserved'})])
        payloads = {'index.json': json.dumps(index).encode(), 'blobs/sha256/config': b'config',
                    'blobs/sha256/layer': b'layer'}
        with tarfile.open(original, 'w') as tar:
            for name, data in payloads.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        before = m.digest(original)
        m.normalize_oci_archive(original, target)
        self.assertEqual(before, m.digest(original))
        with tarfile.open(target) as tar:
            actual = json.load(tar.extractfile('index.json'))
            self.assertEqual(actual['manifests'][0]['digest'], index['manifests'][0]['digest'])
            self.assertEqual(actual['manifests'][0]['annotations'], {'other': 'preserved'})
            for name in ('blobs/sha256/config', 'blobs/sha256/layer'):
                self.assertEqual(tar.extractfile(name).read(), payloads[name])

    def test_invalid_lock_and_insecure_redirect(self):
        for change in ({'url': 'http://example.com/a'}, {'size': m.MAX_ARCHIVE + 1},
                       {'unpacked_size': m.MAX_UNPACKED + 1}, {'sha256': 'x' * 64}):
            lock = copy.deepcopy(self.lock)
            lock.update(change)
            path = self.root / 'lock.json'
            path.write_text(json.dumps(lock))
            with self.assertRaises(ValueError):
                m.read_lock(path)
        with self.assertRaises(ValueError):
            m.HTTPSRedirect().redirect_request(None, None, 302, '', {}, 'http://example.com/a')


if __name__ == '__main__':
    unittest.main()
