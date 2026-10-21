#!/usr/bin/env python3
"""Exercise bounded extraction and rejection of corrupted ZIP payloads."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch', ROOT / 'tools/fetch-ipsw-component.py')
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class ExtractionTests(unittest.TestCase):
    def archive(self, method=zipfile.ZIP_DEFLATED):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', compression=method) as archive:
            archive.writestr('system.dmg', b'payload' * 10000)
        data.seek(0)
        return data

    def test_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp, zipfile.ZipFile(self.archive()) as archive:
            output = Path(temp) / 'system.dmg'
            report = fetch.extract(archive, 'system.dmg', output, 100000, 0)
            self.assertEqual(report['sha256'], hashlib.sha256(b'payload' * 10000).hexdigest())
            self.assertTrue(report['zip_crc_verified'])
            self.assertEqual(output.read_bytes(), b'payload' * 10000)
            with self.assertRaises(FileExistsError):
                fetch.extract(archive, 'system.dmg', output, 100000, 0)

    def test_size_and_reserve(self):
        with tempfile.TemporaryDirectory() as temp, zipfile.ZipFile(self.archive()) as archive:
            output = Path(temp) / 'system.dmg'
            with self.assertRaisesRegex(ValueError, 'Oversized'):
                fetch.extract(archive, 'system.dmg', output, 69999, 0)
            with patch.object(fetch.shutil, 'disk_usage') as usage:
                usage.return_value.free = 70000
                with self.assertRaisesRegex(ValueError, 'Insufficient'):
                    fetch.extract(archive, 'system.dmg', output, 100000, 1)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix('.dmg.partial').exists())

    def test_crc_failure_keeps_partial_not_final(self):
        data = bytearray(self.archive(zipfile.ZIP_STORED).getvalue())
        offset = data.index(b'payload')
        data[offset] ^= 1
        with tempfile.TemporaryDirectory() as temp, zipfile.ZipFile(io.BytesIO(data)) as archive:
            output = Path(temp) / 'system.dmg'
            with self.assertRaises(zipfile.BadZipFile):
                fetch.extract(archive, 'system.dmg', output, 100000, 0)
            self.assertFalse(output.exists())
            self.assertTrue(output.with_suffix('.dmg.partial').exists())


if __name__ == '__main__':
    unittest.main()
