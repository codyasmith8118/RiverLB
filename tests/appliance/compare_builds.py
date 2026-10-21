"""Exercise build comparison against changed bytes and changed provenance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('compare', ROOT / 'scripts/compare-builds.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Compare(unittest.TestCase):
    def test_changed_artifact_and_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / 'a', Path(folder) / 'b'
            for root in (a, b):
                root.mkdir()
                (root / 'build-manifest.json').write_text('{"commit":"same"}')
                (root / 'build-inputs.json').write_text('{"snapshot":"same"}')
                (root / 'package.rpm').write_bytes(b'original')
            self.assertTrue(m.compare(a, b)['byte_identical'])
            (b / 'package.rpm').write_bytes(b'changed')
            result = m.compare(a, b)
            self.assertFalse(result['byte_identical'])
            self.assertEqual(result['changed_files'], ['package.rpm'])
            (b / 'build-manifest.json').write_text('{"commit":"different"}')
            self.assertFalse(m.compare(a, b)['normalized_manifests_equal'])
            (b / 'package.rpm').unlink()
            self.assertIn('package.rpm', m.compare(a, b)['changed_files'])


if __name__ == '__main__':
    unittest.main()
