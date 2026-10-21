#!/usr/bin/env python3
"""Offline HTTP failure tests; optional original Mach-O corruption probes."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import threading
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

ranges = module('ranges', 'serve-ipsw-member.py')
macho = module('macho', 'audit-ios-macho.py')
DATA = bytes(range(256)) * 4097

class Handler(BaseHTTPRequestHandler):
    mode = 'ok'
    def log_message(self, *args):
        pass
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(DATA)))
        self.send_header('ETag', '"fixed"')
        self.end_headers()
    def do_GET(self):
        start, end = map(int, self.headers['Range'][6:].split('-'))
        self.send_response(200 if self.mode == 'status' else 206)
        self.send_header('ETag', '"changed"' if self.mode == 'identity' else '"fixed"')
        self.send_header('Content-Range', 'invalid' if self.mode == 'range' else f'bytes {start}-{end}/{len(DATA)}')
        self.end_headers()
        body = DATA[start:end + 1]
        self.wfile.write(body[:-1] if self.mode == 'short' else body)

class InputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}/firmware'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
    def setUp(self):
        Handler.mode = 'ok'
    def test_ranges_and_eof(self):
        r = ranges.Ranges(self.url)
        self.assertEqual(r.read_at(262140, 20), DATA[262140:262160])
        self.assertEqual(r.requests, 2)
        self.assertEqual(r.read_at(262140, 20), DATA[262140:262160])
        self.assertEqual(r.requests, 2)
        self.assertEqual(r.read_at(len(DATA) - 3, 20), DATA[-3:])
        self.assertEqual(r.read_at(len(DATA) + 3, 20), b'')
        with self.assertRaises(ValueError):
            r.read_at(-1, 1)
    def test_server_failures(self):
        for mode in ('status', 'identity', 'range', 'short'):
            with self.subTest(mode=mode):
                Handler.mode = mode
                with self.assertRaises(OSError):
                    ranges.Ranges(self.url).read_at(0, 8)
    def test_original_macho_and_corruption(self):
        if not FILES:
            self.skipTest('Pass --macho paths for original file checks')
        for path in FILES:
            data = path.read_bytes()
            report = macho.audit(data)
            for cd in report['code_directories']:
                for offset in (4096, cd['code_limit'] - 1):
                    bad = bytearray(data)
                    bad[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, 'Code slot .* mismatch'):
                        macho.audit(bad)
            with self.assertRaises((ValueError, struct.error)):
                macho.audit(data[:100])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--macho', nargs='*', type=Path, default=[])
    args, rest = parser.parse_known_args()
    FILES = args.macho
    unittest.main(argv=[__file__] + rest)
else:
    FILES = []
