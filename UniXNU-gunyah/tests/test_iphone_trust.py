#!/usr/bin/env python3
"""Real-input corruption probes for special slots and trust-cache structure."""
import argparse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('trust', ROOT / 'tools/audit-iphone-trust.py')
trust = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trust)


def rejects(action, message=None):
    try:
        action()
    except ValueError as error:
        if message:
            assert message in str(error), error
    else:
        raise AssertionError('Corrupt input accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--launchd', required=True, type=Path)
    parser.add_argument('--trustcache', required=True, type=Path)
    args = parser.parse_args()
    data = args.launchd.read_bytes()
    report = trust.special_slots(data)
    assert report['verified_embedded_slots'] == [1, 2, 5, 7]
    assert not report['unavailable_external_slots']
    for magic, slot in [(bytes.fromhex('fade7171'), 5), (bytes.fromhex('fade7172'), 7)]:
        offset = data.index(magic)
        bad = bytearray(data)
        bad[offset + 9] ^= 1
        rejects(lambda: trust.special_slots(bad), f'Special slot {slot} mismatch')
    raw = args.trustcache.read_bytes()
    module, entries = trust.trust_cache(raw)
    assert module['version'] == 2 and entries
    rejects(lambda: trust.trust_cache(raw[:-1]))
    rejects(lambda: trust.trust_cache(raw + b'\0'))
    # Locate the parsed v2 header by its UUID, then invalidate its count.
    offset = raw.index(bytes.fromhex(module['uuid'])) - 4
    bad = bytearray(raw)
    bad[offset + 20] ^= 1
    rejects(lambda: trust.trust_cache(bad), 'size/version')
    print('PASS: original inputs; XML/DER corruption, truncated/extended IM4P and bad count rejected')


if __name__ == '__main__':
    main()
