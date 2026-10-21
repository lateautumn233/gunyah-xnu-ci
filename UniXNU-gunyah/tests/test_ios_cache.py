#!/usr/bin/env python3
"""Verify an original cache and reject damage in each 4 KiB signing quarter."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cache', ROOT / 'tools/audit-ios-cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True, type=Path)
    args = parser.parse_args()
    report = cache.audit(args.cache)
    assert all(cd['signing_block_bytes'] == 16384 for cd in report['code_directories'])
    data = args.cache.read_bytes()
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'damaged-cache'
        # Second signing block avoids damaging the header/metadata parser.
        for quarter in range(4):
            bad = bytearray(data)
            bad[16384 + quarter * 4096] ^= 1
            path.write_bytes(bad)
            try:
                cache.audit(path)
            except ValueError as error:
                assert 'Code slot 1 mismatch' in str(error), error
            else:
                raise AssertionError(f'Accepted corruption in quarter {quarter}')
        path.write_bytes(data[:100])
        try:
            cache.audit(path)
        except ValueError:
            pass
        else:
            raise AssertionError('Accepted truncated cache')
    print('PASS: original cache; four 4 KiB corruption probes; truncation rejected')


if __name__ == '__main__':
    main()
