#!/usr/bin/env python3
"""Compile the Gunyah diagnostic security provider with existing XNU compile records.

With --archive, also emits libGunyahSecurity.a for -force_load; without it only
compiles (no link, no registration).
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

DEVICE = Path(__file__).resolve().parents[1]
SOURCES = ('GunyahEntitlements.c', 'GunyahTrustCache.c', 'GunyahOSEntitlements.cpp',
           'GunyahSignaturePolicy.cpp', 'GunyahEntitlementBridge.cpp', 'GunyahAmfi.cpp',
           'GunyahSecurityInit.cpp')


def build(tree, env, out, trust_module=None, archive=False):
    out.mkdir(parents=True, exist_ok=True)
    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    linux = env.get('GUNYAH_LINUX') == '1' or 'GUNYAH_LINUX_CC' in env
    commands, objects = [], []
    sources = [(DEVICE / 'security' / name) for name in SOURCES]
    if trust_module:
        sources.append(Path(trust_module).resolve())
    for source in sources:
        cxx = source.suffix == '.cpp'
        record = obj / ('iokit/DEVELOPMENT/IOPlatformExpert.cpo.json' if cxx else 'bsd/DEVELOPMENT/ubc_subr.o.json')
        data = json.loads(record.read_text().strip().rstrip(','))
        target = out / (source.stem + '.o')
        command = [env['GUNYAH_LINUX_CXX' if cxx else 'GUNYAH_LINUX_CC'] if linux else data['arguments'][0]]
        arguments = iter(data['arguments'][1:])
        replaced = 0
        for arg in arguments:
            if arg == data['file']:
                command.append(str(source)); replaced += 1
            elif arg == '-o':
                next(arguments); command.extend(['-o', str(target)])
            elif arg in ('-MJ', '-MF', '-MT', '-MQ', '-serialize-diagnostics'):
                next(arguments)
            elif arg not in ('-MD', '-MP'):
                command.append(arg)
        if replaced != 1:
            raise ValueError('Cannot identify source in compile record')
        with (out / (source.name + '.log')).open('w') as log:
            result = subprocess.run(command, cwd=data['directory'], env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(f'Compile failed: {out / (source.name + ".log")}')
        commands.append(command)
        objects.append(target)
        print(f'Compiled {source.name}', flush=True)
    library = None
    if archive:
        library = out / 'libGunyahSecurity.a'
        library.unlink(missing_ok=True)
        subprocess.run(['xcrun', 'ar', 'rcs', library, *objects], env=env, check=True)
    (out / 'build.json').write_text(json.dumps(dict(commands=commands, archive=str(library) if library else None,
        kernel_linked=False, provider_registered=False, runtime_tested=False), indent=2) + '\n')
    return library


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--environment', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--trust-module-source', type=Path)
    parser.add_argument('--archive', action='store_true')
    args = parser.parse_args()
    env = dict(os.environ)
    if args.environment:
        env.update(json.loads(args.environment.read_text())['environment'])
    tree = args.tree.resolve()
    build(tree, env, (args.output or tree / 'build/gunyah-security').resolve(), args.trust_module_source, args.archive)
