#!/usr/bin/env python3
"""Classify the minimal original launchd exec attempt without claiming dyld ran."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    pin = json.loads((root / 'configs/iphone10-3-20H392.json').read_text())
    fixture = json.loads(args.fixture.read_text())
    for dest, source in [('apple-launchd', 'sbin/launchd'), ('usr/lib/dyld', 'usr/lib/dyld')]:
        assert fixture['files'][dest]['sha256'] == pin['files'][source]['sha256']
    with (args.run / 'test-disk.img').open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == fixture['sha256']
    log = (args.run / 'probe-serial.log').read_text()
    checks = json.loads((args.run / 'checks.json').read_text())
    assert checks['test_disk_unchanged']
    assert json.loads((args.run / 'host-pool-before.json').read_text())['verified']
    baseline = log.index('GUNYAH-USER: PASS pid=1')
    attempt = log.index('GUNYAH-APPLE-EXEC: exec /apple-launchd')
    refusal = log.index('GUNYAH-XNU: entitlement provider unavailable; refusing image')
    assert baseline < attempt < refusal
    assert 'check_signature[pid: 1]: error = 1' in log[refusal:]
    assert 'load code signature error 4 for file "apple-launchd"' in log[refusal:]
    assert 'unexpected SIGKILL of launchd' in log[refusal:]
    report = dict(run=str(args.run), own_pid1_baseline_passed=True,
                  pinned_apple_files_preserved=True, original_launchd_exec_attempted=True,
                  blocker='missing-entitlement-provider', dyld_entry_verified=False,
                  apple_launchd_executed=False, full_ios_booted=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('Confirmed: baseline passed; original exec refused for missing entitlement provider before dyld entry')


if __name__ == '__main__':
    main()
