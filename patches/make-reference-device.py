#!/usr/bin/env python3
"""Derive a reference-candidate device repo: same board, no storage/display/owner-root drivers."""
import re, shutil, sys
src, dst = sys.argv[1:3]
shutil.copytree(src, dst, ignore=shutil.ignore_patterns('.git'))
b = open(dst + '/board.toml').read()
m = re.search(r'^archives = \[\n(.*?)^\]', b, re.S | re.M)
keep = ('build-corecrypto-14.py', 'build-arm-driver.py ArmDTPlatform', 'build-arm-driver.py ArmCpu',
        'build-arm-driver.py NativeAES', 'build-native-aes-bindings.py', 'build-libpthread-kernel.py')
lines = [l for l in m.group(1).splitlines() if l.strip().startswith('"') and any(('"' + k) in l for k in keep)]
b = b[:m.start(1)] + '\n'.join(lines) + '\n' + b[m.end(1):]
open(dst + '/board.toml', 'w').write(b)
drop = ('NATIVE_VIRTIO_BLOCK', 'NATIVE_RAM_BLOCK', 'VERIFIED_ROOT', 'OWNER_', 'NATIVE_LEGACY_DISPLAY', 'BOARD_LAUNCH_POLICY', 'EXTRA_LD_ARCHIVES')
c = open(dst + '/configs/droidvm_defconfig').read().splitlines()
c = [l for l in c if not any(('CONFIG_XNU_' + d) in l and not l.startswith('#') for d in drop)]
open(dst + '/configs/droidvm_defconfig', 'w').write('\n'.join(c) + '\n')
print('reference device: %d archive builders' % len(lines))
