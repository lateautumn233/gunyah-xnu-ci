#!/usr/bin/env python3
"""Check retained real-device evidence for the four-quarter signing fixture."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positive', required=True, type=Path)
    parser.add_argument('--negative', required=True, nargs=4, type=Path,
                        help='Evidence directories in quarter 0..3 order')
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    evidence = []
    for n, run in enumerate([args.positive] + args.negative):
        log = (run / 'probe-serial.log').read_text()
        checks = json.loads((run / 'checks.json').read_text())
        pool = json.loads((run / 'host-pool-before.json').read_text())
        expected = manifest['source_disk_sha256'] if n == 0 else manifest['negatives'][n - 1]['sha256']
        with (run / 'test-disk.img').open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, run
        assert pool['verified'], run
        assert checks['test_disk_unchanged'], run
        if n == 0:
            assert checks['hfs_root_verified'], run
            assert 'GUNYAH-USER-SIGNATURE: PASS executable_quarters=4 native_page=4096 signing_block=16384' in log, run
            assert 'GUNYAH-USER: PASS pid=1' in log, run
        else:
            assert not checks['hfs_root_verified'], run
            assert 'check_signature[pid: 1]: error = 85' in log, run
            assert 'load code signature error 4 for file "launchd"' in log, run
            assert 'unexpected SIGKILL of init' in log, run
            assert 'GUNYAH-USER-SIGNATURE: PASS' not in log, run
            assert 'GUNYAH-USER: entered EL0' not in log, run
        evidence.append(str(run))
    args.output.write_text(json.dumps(dict(evidence=evidence,
        positive_four_executable_quarters=True, corrupt_quarters_rejected_at_signature_load=4,
        post_load_mutation_tested=False, apple_userspace_tested=False), indent=2) + '\n')
    print('PASS: four executable quarters; four corrupt signatures rejected before EL0')


if __name__ == '__main__':
    main()
