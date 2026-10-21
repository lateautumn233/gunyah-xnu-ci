#!/usr/bin/env python3
"""Build pinned Apple HFS as a built-in, plaintext test-volume filesystem."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

PIN = '31d5ec238dfab485e78a9a30b8b92d13e8914f03'
DEVICE = Path(__file__).resolve().parents[1]


def build(tree, env):
    source = tree / 'refer/hfs'
    if subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('HFS must match the pinned macOS 13.6 / XNU 8796.141.3 release')
    if subprocess.check_output(['git', '-C', source, 'status', '--porcelain'], text=True).strip():
        raise ValueError('HFS reference tree must be clean')
    out = tree / 'build/gunyah-hfs'
    staged = out / 'source'
    staged.mkdir(parents=True, exist_ok=True)
    for name in ('core', 'hfs_encodings'):
        shutil.copytree(source / name, staged / name, dirs_exist_ok=True)
    shutil.copytree(DEVICE / 'drivers/GunyahHfs', staged / 'adapter', dirs_exist_ok=True)
    sdk = Path(subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], env=env, text=True).strip())
    shutil.copy2(sdk / 'usr/include/TargetConditionals.h', staged)
    path = staged / 'core/hfs_iokit.h'
    value = path.read_text()
    include = '#include <AppleKeyStore/AppleKeyStoreFSServices.h>'
    assert value.count(include) == 1
    value = value.replace(include, '#if CONFIG_PROTECT\n' + include + '\n#endif')
    value = value.replace('int hfs_unwrap_key(', '#if CONFIG_PROTECT\nint hfs_unwrap_key(')
    value = value.replace('__END_DECLS', '#endif\n\n__END_DECLS')
    path.write_text(value)
    path = staged / 'core/hfs_vfsutils.c'
    value = path.read_text()
    old = '/* If CONFIG_PROTECT not built, ignore CP */\n\t\tvfs_clearflags(hfsmp->hfs_mp, MNT_CPROTECT);\t'
    assert value.count(old) == 1
    value = value.replace(old, '/* Gunyah has no AppleKeyStore: refuse protected volumes. */\n\t\tretval = ENOTSUP;\n\t\tgoto ErrorExit;')
    path.write_text(value)
    project = (source / 'hfs.xcodeproj/project.pbxproj').read_text()
    phase = project.split('FB20E0DB1AE950C200CEBE7B /* Sources */ = {')[1].split('runOnlyForDeploymentPostprocessing')[0]
    sources = [staged / 'core' / n for n in re.findall(r'/\* (\w+\.c) in Sources \*/', phase)]
    # Apple OSS omits the private key-roll implementation; CONFIG_PROTECT=0.
    sources = [p for p in sources if p.name != 'hfs_key_roll.c']
    # Legacy HFS encodings are macOS-only; iOS HFS+ uses Unicode directly.
    sources += [staged / 'adapter/register.c']
    recipe = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/vfs_conf.o.json'
    record = json.loads(recipe.read_text().strip().rstrip(','))
    objects, commands = [], []
    for src in sources:
        obj = out / (src.stem + '.o')
        args = iter(record['arguments'][1:])
        command = [env['GUNYAH_LINUX_CC'] if env.get('GUNYAH_LINUX') == '1' else record['arguments'][0]]
        for arg in args:
            if arg == record['file']:
                command.append(str(src))
            elif arg == '-o':
                next(args); command += ['-o', str(obj)]
            elif arg in ('-MJ', '-MF', '-MT', '-MQ', '-serialize-diagnostics'):
                next(args)
            elif arg not in ('-MD', '-MP', '-Weverything'):
                command.append(arg)
        command += ['-include', str(staged / 'adapter/compat.h'), '-I' + str(staged), '-I' + str(staged / 'core'), '-I' + str(staged / 'hfs_encodings')]
        if src.parent.name == 'hfs_encodings':
            command += ['-Dhfs_allocated=hfs_encodings_allocated']
        commands.append(command)
        with (out / (src.stem + '.log')).open('w') as log:
            result = subprocess.run(command, cwd=record['directory'], env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f'HFS compilation failed: {out / (src.stem + ".log")}')
        objects.append(obj)
    archive = out / 'libGunyahHfs.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'ar', 'rcs', archive, *objects], env=env, check=True)
    (out / 'build.json').write_text(json.dumps(dict(commit=PIN, version='650.140.2', content_protection=False, objects=len(objects), commands=commands, archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), indent=2) + '\n')
    print(f'Built {len(objects)} HFS objects: {archive}', flush=True)
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--environment', type=Path)
    args = parser.parse_args()
    env = dict(os.environ)
    if args.environment:
        env.update(json.loads(args.environment.read_text())['environment'])
    build(args.tree.resolve(), env)
