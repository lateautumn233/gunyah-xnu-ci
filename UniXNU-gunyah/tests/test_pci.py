#!/usr/bin/env python3
"""PCI protocol bounds and host evidence rejection tests; no device required."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runner', DEVICE.parent / 'tools/run-xnu-boot.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

RESOURCES = dict(pci_ecam=[0x10000, 0x100000], pci_windows=[[0x02000000, 0x2000000, 0x2000000, 0x2000000]])
LOG = '''GUNYAH-PCI: start ecam=0x10000 bytes=0x100000 windows=1
GUNYAH-PCI: window=0 flags=0x2000000 bus=0x2000000 physical=0x2000000 bytes=0x2000000
GUNYAH-PCI: device=00:01.0 vendor=0x1af4 product=0x1042 command=0x0006
GUNYAH-PCI: block=00:01.0 type=1 bar=0 offset=0x0 bytes=0x38 physical=0x2000000
GUNYAH-PCI: block=00:01.0 type=2 bar=0 offset=0x1000 bytes=0x1000 physical=0x2001000
GUNYAH-PCI: block=00:01.0 type=3 bar=0 offset=0x2000 bytes=0x1 physical=0x2002000
GUNYAH-PCI: block=00:01.0 type=4 bar=0 offset=0x3000 bytes=0x8 physical=0x2003000
GUNYAH-PCI: block=00:01.0 notify_multiplier=4
GUNYAH-PCI: result=PASS devices=1 blocks=1 failures=0
'''


class PciTests(unittest.TestCase):
    def test_protocol_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'pci')
            subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(DEVICE / 'drivers/ArmDTPlatform'),
                            str(DEVICE / 'tests/test_pci.cpp'), '-o', binary], check=True)
            subprocess.run([binary], check=True)

    def test_complete_evidence(self):
        self.assertTrue(runner.pci_checks(LOG, RESOURCES)['pci_discovery_passed'])

    def test_reject_incomplete_or_invalid_evidence(self):
        cases = ['', LOG + LOG, LOG.replace('type=4', 'type=3'),
                 LOG.replace('bytes=0x38', 'bytes=0x1'), LOG.replace('bar=0', 'bar=7'),
                 LOG.replace('physical=0x2003000', 'physical=0x80000000'),
                 LOG.replace('product=0x1042', 'product=0x1041'),
                 LOG.replace('devices=1', 'devices=2'), LOG.replace('failures=0', 'failures=1'),
                 LOG + 'GUNYAH-PCI: result=FAIL reason=map\n',
                 LOG + 'GUNYAH-PCI: block=00:01.0 refused=5\n']
        cases += ['\n'.join(line for line in LOG.splitlines() if line != removed) for removed in LOG.splitlines()]
        for log in cases:
            with self.subTest(log=log):
                self.assertFalse(runner.pci_checks(log, RESOURCES)['pci_discovery_passed'])

    def test_reject_wrong_fdt_resources(self):
        r = copy.deepcopy(RESOURCES)
        r['pci_ecam'][0] += 4096
        self.assertFalse(runner.pci_checks(LOG, r)['pci_discovery_passed'])
        r = copy.deepcopy(RESOURCES)
        r['pci_windows'][0][2] += 4096
        self.assertFalse(runner.pci_checks(LOG, r)['pci_discovery_passed'])


class HostPoolTests(unittest.TestCase):
    def state(self, want=512, available=512, **extra):
        state = dict(active_vms=0, served=0, acquire_active=0, pool_avail=available,
                     pool_want=want, pool_want_with_cma=4096)
        state.update(extra)
        return ''.join(f'{key}={value}\n' for key, value in state.items())

    def test_resize_checks_readback_and_preserves_cma_target(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(runner.subprocess, 'check_output', side_effect=[self.state(), '4463', '1', self.state(256, 256)]), \
             mock.patch.object(runner.subprocess, 'run') as write:
            proof = Path(directory) / 'pool.json'
            runner.prepare_host_pool(['adb'], 384, 512, proof)
            self.assertIn('"verified": true', proof.read_text())
            self.assertEqual(write.call_count, 1)
            command = write.call_args.args[0][-1]
            self.assertIn('256 > ' + runner.POOL + '/pool_want', command)
            self.assertNotIn('pool_want_with_cma', command)

    def test_busy_owner_or_adjustment_is_never_modified(self):
        for busy in ({'active_vms': 1}, {'served': 1}, {'acquire_active': 1}):
            with self.subTest(busy=busy), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(runner.subprocess, 'check_output', return_value=self.state(**busy)), \
                 mock.patch.object(runner.subprocess, 'run') as write:
                with self.assertRaises(RuntimeError):
                    runner.prepare_host_pool(['adb'], 384, 512, Path(directory) / 'pool.json')
                write.assert_not_called()

    def test_target_without_available_pages_is_not_ready(self):
        states = [self.state(64, 64), '4463', '1', self.state(256, 64), self.state(256, 256)]
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(runner.subprocess, 'check_output', side_effect=states), \
             mock.patch.object(runner.subprocess, 'run') as write, \
             mock.patch.object(runner.time, 'sleep'):
            runner.prepare_host_pool(['adb'], 384, 512, Path(directory) / 'pool.json')
            self.assertEqual(write.call_count, 2)
            self.assertIn('1 > ' + runner.POOL + '/acquire', write.call_args.args[0][-1])

    def test_concurrent_resize_refused(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(runner.subprocess, 'check_output', side_effect=[self.state(), '4463', '1', self.state(128, 128)]), \
             mock.patch.object(runner.subprocess, 'run'):
            with self.assertRaises(RuntimeError):
                runner.prepare_host_pool(['adb'], 384, 512, Path(directory) / 'pool.json')


class BlockEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytes((i * 73 + (i >> 8) * 19 + (i >> 16) * 29 + 0x5a) & 255
                         for i in range(1024 * 1024))
        cls.resources = dict(RESOURCES, ram=[0x80000000, 0x18000000])
        cases = [(0, 512), (7, 8192), (113, 65536), (2047, 512), (2040, 4096),
                 (738, 4096), (875, 4096), (1012, 4096), (1149, 4096),
                 (1286, 4096), (1423, 4096), (1560, 4096), (1697, 4096),
                 (1834, 4096), (1971, 4096), (67, 4096)]
        cls.log = LOG.replace('00:01.0', '00:02.0') + '''GUNYAH-BLOCK: start device=00:02.0 mode=read-only
GUNYAH-BLOCK: bar=0 bus=0x2000000 bytes=0x8000 restored=1
GUNYAH-BLOCK: features_low=0x20001064 features_high=0x403
GUNYAH-BLOCK: ready=1 sectors=2048 queue_size=8 queue_gpa=0x86000000 data_gpa=0x86100000
'''
        for n, (sector, size) in enumerate(cases, 1):
            digest = hashlib.sha256(cls.data[sector * 512:sector * 512 + size]).hexdigest()
            cls.log += f'GUNYAH-BLOCK: sample={n} sector={sector} bytes={size} sha256={digest} used={n}\n'
        cls.log += ('GUNYAH-BLOCK: bounds=PASS rejected=6 submitted=16\n'
                    'GUNYAH-BLOCK: result=PASS reads=16 reset=1 bus_master=0\n')

    def check_log(self, log, resources=None, data=None):
        return runner.block_checks(log, self.data if data is None else data,
                                   self.resources if resources is None else resources)

    def test_complete_and_translated_evidence(self):
        result = self.check_log(self.log)
        self.assertTrue(result['block_transport_passed'])
        self.assertTrue(result['block_data_matches'])
        # BAR addresses are PCI bus addresses, not necessarily CPU addresses.
        resources = copy.deepcopy(self.resources)
        resources['pci_windows'][0][2] = 0x4000000
        log = self.log.replace('physical=0x200', 'physical=0x400')
        self.assertTrue(self.check_log(log, resources)['block_transport_passed'])
        self.assertFalse(self.check_log(self.log, resources)['block_transport_passed'])

    def test_reject_missing_duplicated_and_reordered_evidence(self):
        lines = self.log.splitlines(keepends=True)
        required = [line for line in lines if line.startswith('GUNYAH-BLOCK:') or ' type=' in line]
        for line in required:
            for log in (self.log.replace(line, ''), self.log + line):
                with self.subTest(line=line, log=log):
                    self.assertFalse(self.check_log(log)['block_transport_passed'])
        first = next(line for line in lines if 'sample=1 ' in line)
        self.assertFalse(self.check_log(self.log.replace(first, '') + first)['block_transport_passed'])
        self.assertFalse(self.check_log('')['block_transport_passed'])

    def test_reject_bad_resources_and_shutdown(self):
        mutations = [('queue_gpa=0x86000000', 'queue_gpa=0x70000000'),
                     ('data_gpa=0x86100000', 'data_gpa=0x97fff000'),
                     ('data_gpa=0x86100000', 'data_gpa=0x86000000'),
                     ('queue_gpa=0x86000000', 'queue_gpa=0x86000001'),
                     ('sectors=2048', 'sectors=2049'), ('queue_size=8', 'queue_size=2'),
                     ('features_low=0x20001064', 'features_low=0x20001044'),
                     ('features_high=0x403', 'features_high=0x402'),
                     ('bytes=0x8000', 'bytes=0x2000'), ('restored=1', 'restored=0'),
                     ('bus=0x2000000 bytes=0x8000', 'bus=0x2001000 bytes=0x8000'),
                     ('reset=1', 'reset=0'), ('bus_master=0', 'bus_master=1'),
                     ('used=16', 'used=15'), ('rejected=6', 'rejected=5'),
                     ('start device=00:02.0', 'start device=00:01.0')]
        for before, after in mutations:
            with self.subTest(after=after):
                self.assertFalse(self.check_log(self.log.replace(before, after))['block_transport_passed'])
        for failure in ('failure=requires-ro-version1', 'read-error=0xe00002d6', 'result=FAIL'):
            self.assertFalse(self.check_log(self.log + 'GUNYAH-BLOCK: ' + failure)['block_transport_passed'])

    def test_data_corruption_and_wrong_fixture(self):
        digest = hashlib.sha256(self.data[:512]).hexdigest()
        self.assertFalse(self.check_log(self.log.replace(digest, '0' * 64))['block_data_matches'])
        corrupt = bytes([self.data[0] ^ 1]) + self.data[1:]
        self.assertFalse(self.check_log(self.log, data=corrupt)['block_data_matches'])
        self.assertFalse(self.check_log(self.log, data=self.data[:-512])['block_transport_passed'])
        self.assertFalse(runner.block_checks(self.log, None, self.resources)['block_transport_passed'])

    def test_persistent_lifetime_requires_explicit_expectation(self):
        log = self.log.replace('reads=16 reset=1 bus_master=0', 'reads=16 persistent=1')
        self.assertFalse(self.check_log(log)['block_transport_passed'])
        self.assertTrue(runner.block_checks(log, self.data, self.resources, persistent=True)['block_transport_passed'])
        self.assertFalse(runner.block_checks(self.log, self.data, self.resources, persistent=True)['block_transport_passed'])
        self.assertFalse(runner.block_checks(log + 'GUNYAH-BLOCK: offline error=1 reset=1 bus_master=0',
                                            self.data, self.resources, persistent=True)['block_transport_passed'])

    def test_bsd_requires_ordered_kernel_and_user_evidence(self):
        log = '''GUNYAH-BLOCK: result=PASS reads=16 persistent=1
GUNYAH-BSD: published block=gvblk0 raw=rgvblk0 block_major=2 raw_major=14 sectors=2048 block_size=512 readonly=1
GUNYAH-USER-BLOCK: start fixture_bytes=1048576
GUNYAH-USER-BLOCK: geometry=PASS sectors=2048 block_size=512 readonly=1
GUNYAH-USER-BLOCK: raw read/pread/cross-page/64KiB/tail/EOF/alignment PASS
GUNYAH-USER-BLOCK: PASS raw=rgvblk0 block=gvblk0 bytes_verified=1 readonly=1
'''
        self.assertTrue(runner.bsd_block_checks(log)['bsd_block_user_passed'])
        cases = ['', log + log, log.replace('sectors=2048', 'sectors=2049'),
                 log.replace('block_major=2', 'block_major=0'), log.replace('readonly=1', 'readonly=0'),
                 log + 'GUNYAH-BSD: failure=devfs', log + 'GUNYAH-USER: FAIL disk-data',
                 log + 'GUNYAH-BLOCK: offline error=1 reset=1 bus_master=0',
                 '\n'.join(reversed(log.splitlines()))]
        cases += [log.replace(line, '') for line in log.splitlines(keepends=True)]
        for case in cases:
            with self.subTest(log=case):
                self.assertFalse(runner.bsd_block_checks(case)['bsd_block_user_passed'])

    def test_hfs_mount_evidence_rejects_incomplete_or_failed_runs(self):
        log = '''GUNYAH-HFS: registered version=650.140.2 content_protection=unsupported
GUNYAH-BSD: published block=gvblk0 raw=rgvblk0 block_major=1 raw_major=13 sectors=65536 block_size=512 readonly=1
hfs: mounted GunyahTest on device gvblk0
hfs: unmount initiated on GunyahTest on device gvblk0
hfs: mounted GunyahTest on device gvblk0
hfs: unmount initiated on GunyahTest on device gvblk0
GUNYAH-USER-HFS: PASS files=2 file_bytes=16391 mounts=2 readonly=1 unicode=1
'''
        self.assertTrue(runner.hfs_checks(log)['hfs_user_passed'])
        lines = log.splitlines(keepends=True)
        bad = [log.replace(line, '', 1) for line in lines]
        bad += [log + 'GUNYAH-USER: FAIL hfs-mount', log + log,
                log.replace('readonly=1', 'readonly=0'),
                ''.join(lines[:2] + [lines[2], lines[4], lines[3], lines[5], lines[6]])]
        for value in bad:
            with self.subTest(log=value):
                self.assertFalse(runner.hfs_checks(value)['hfs_user_passed'])

    def test_hfs_root_evidence_requires_selection_opt_out_and_user_pass(self):
        boot_args = 'rd=gvblk0 gunyah-block-publish=1 gunyah-hfs=1 gunyah-root-unauthenticated=1'
        log = '''GUNYAH-BSD: published block=gvblk0 raw=rgvblk0 block_major=1 raw_major=13 sectors=65536 block_size=512 readonly=1
GUNYAH-ROOT: device=gvblk0 major=1 minor=0 readonly=1 sectors=65536
BSD root: gvblk0, major 1, minor 0
mockfs_mountroot: root device is not a RAM disk; declining
hfs: mounted GunyahRoot on device b(1, 0)
GUNYAH-ROOT: authentication=skipped boot-arg=gunyah-root-unauthenticated
load_init_program: attempting to load /sbin/launchd
GUNYAH-USER: entered EL0; console open
GUNYAH-USER-ROOT: PASS fstype=hfs rootfs=1 readonly=1 unicode=1 init=/sbin/launchd devfs=1 file_bytes=16391
GUNYAH-USER: PASS pid=1 page_size=4096 file_bytes=16391 wakeups=3
'''
        self.assertTrue(runner.hfs_root_checks(log, boot_args)['hfs_root_user_passed'])
        lines = log.splitlines(keepends=True)
        bad = [(log.replace(line, '', 1), boot_args) for line in lines]
        bad += [(log + log, boot_args), (log.replace('major=1 minor=0', 'major=2 minor=0'), boot_args),
                (log.replace('BSD root: gvblk0, major 1', 'BSD root: gvblk0, major 2'), boot_args),
                (log.replace('on device b(1, 0)', 'on device b(2, 0)'), boot_args),
                (log.replace('on device b(1, 0)', 'on device gvblk0'), boot_args),
                (log.replace('sectors=65536 block_size', 'sectors=2048 block_size'), boot_args),
                (log + 'hfs: unmount initiated on GunyahRoot on device gvblk0\n', boot_args),
                (log + 'BSD root: md0, major 2, minor 0\n', boot_args),
                (log + 'GUNYAH-USER: FAIL root-fstype\n', boot_args),
                (log + 'panic(cpu 0 caller 0): rootvp not authenticated after mounting\n', boot_args),
                (log + 'Process 1 exec of /sbin/launchd failed, errno 8\n', boot_args),
                (''.join([lines[0], lines[2], lines[1]] + lines[3:]), boot_args),
                (log, boot_args.replace('rd=gvblk0', 'rd=md0')),
                (log, boot_args.replace(' gunyah-root-unauthenticated=1', ''))]
        for value, args in bad:
            with self.subTest(log=value, args=args):
                self.assertFalse(runner.hfs_root_checks(value, args)['hfs_root_user_passed'])

    def test_disk_window_matches_boot_request_and_disk_capacity(self):
        log = 'GUNYAH-BSD: window start=2048 sectors=65536 disk_sectors=69632 explicit=1'
        args = 'rd=gvblk0 gunyah-root-start=2048 gunyah-root-sectors=65536'
        self.assertTrue(runner.disk_window_checks(log, args, 69632*512)['disk_window_verified'])
        for changed in ('gunyah-root-start=2048', args + ' gunyah-root-start=2048',
                        args.replace('2048', '-1'), args.replace('65536', '0'),
                        args.replace('65536', '18446744073709551616'),
                        args.replace('2048', '69632')):
            self.assertFalse(runner.disk_window_checks(log, changed, 69632*512)['disk_window_verified'])
        for changed in ('', log + log, log.replace('2048', '0'),
                        log + 'GUNYAH-BSD: failure=invalid-window'):
            self.assertFalse(runner.disk_window_checks(changed, args, 69632*512)['disk_window_verified'])
        self.assertFalse(runner.disk_window_checks(log, args, 65536*512)['disk_window_verified'])

    def test_ramdisk_major_is_allocated_dynamically(self):
        for major in (1, 2, 12):
            self.assertTrue(runner.runtime_checks(f'BSD root: md0, major {major}, minor 0\n')['ramdisk_selected'])
        self.assertFalse(runner.runtime_checks('BSD root: gvblk0, major 1, minor 0\n')['ramdisk_selected'])


if __name__ == '__main__':
    unittest.main()
