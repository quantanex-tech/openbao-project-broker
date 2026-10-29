"""Install into isolated prefixes and reject overwrites/drift before mutation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prefix = Path(self.tmp.name).resolve() / 'new prefix'

    def test_preflight_is_read_only_and_install_launchers_work(self):
        installer.verify(self.prefix)
        self.assertFalse(self.prefix.exists())
        installer.install(self.prefix)
        for name in installer.FILES:
            self.assertEqual((self.prefix / 'lib/openbao-project-broker' / name).read_bytes(),
                             (ROOT / 'src' / name).read_bytes())
        for name in ('project-broker', 'project-access'):
            result = subprocess.run([str(self.prefix / 'bin' / name), '--help'],
                                    capture_output=True, text=True, check=True)
            self.assertIn('usage:', result.stdout)

    def test_existing_prefix_and_symlink_are_never_overwritten(self):
        self.prefix.mkdir()
        marker = self.prefix / 'unrelated'
        marker.write_text('preserve')
        with self.assertRaises(ValueError):
            installer.install(self.prefix)
        self.assertEqual(marker.read_text(), 'preserve')
        link = self.prefix.parent / 'alias'
        link.symlink_to(self.prefix, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(link)
        with self.assertRaises(ValueError):
            installer.install(link / 'new')
        self.assertFalse((self.prefix / 'new').exists())

    def test_manifest_and_source_drift_fail_without_creating_prefix(self):
        source = self.prefix.parent / 'source'
        (source / 'src').mkdir(parents=True)
        for name in installer.FILES:
            (source / 'src' / name).write_bytes((ROOT / 'src' / name).read_bytes())
        manifest = json.loads((ROOT / 'manifest.json').read_text())
        (source / 'manifest.json').write_text(json.dumps(manifest))
        (source / 'src/broker.py').write_text('DRIFT = True\n')
        with self.assertRaises(ValueError):
            installer.install(self.prefix, source)
        self.assertFalse(self.prefix.exists())
        del manifest['files']['broker.py']
        (source / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            installer.install(self.prefix, source)
        self.assertFalse(self.prefix.exists())

    def test_symlinked_source_is_rejected(self):
        source = self.prefix.parent / 'source'
        (source / 'src').mkdir(parents=True)
        (source / 'manifest.json').write_bytes((ROOT / 'manifest.json').read_bytes())
        for name in installer.FILES:
            (source / 'src' / name).symlink_to(ROOT / 'src' / name)
        with self.assertRaises(ValueError):
            installer.install(self.prefix, source)
        self.assertFalse(self.prefix.exists())

    def test_failed_write_removes_only_this_new_install(self):
        marker = self.prefix.parent / 'unrelated'
        marker.write_text('preserve')
        with patch.object(installer.os, 'fsync', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                installer.install(self.prefix)
        self.assertFalse(self.prefix.exists())
        self.assertEqual(marker.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
