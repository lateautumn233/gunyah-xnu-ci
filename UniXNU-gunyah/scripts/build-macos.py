#!/usr/bin/env python3
"""Build the Gunyah source kernel from a prepared tree on macOS/Xcode.

The platform stage builds the actual source crypto/pthread and IOKit providers.
It does not prelink an IPSW or claim a bootable iOS userspace image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[1]
KERNEL = Path("build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped")


def preflight(tree):
    checks = {"macos": platform.system() == "Darwin", "python_3_11": sys.version_info >= (3, 11),
              "prepared_tree": (tree / "gunyah-inputs.json").is_file()}
    for name in ("git", "make", "clang", "cmake", "ninja", "unifdef", "xcrun", "xcodebuild", "ditto", "plutil"):
        checks[name] = shutil.which(name) is not None
    sdks = {}
    if checks["xcrun"]:
        for name in ("macosx", "iphoneos"):
            result = subprocess.run(["xcrun", "--sdk", name, "--show-sdk-path"], capture_output=True, text=True)
            checks[name + "_sdk"] = result.returncode == 0 and Path(result.stdout.strip()).is_dir()
            sdks[name] = result.stdout.strip()
    else:
        checks.update(macosx_sdk=False, iphoneos_sdk=False)
    return dict(checks=checks, sdk_paths=sdks, ready=all(checks.values()), xnu_build_verified=False)


def execute(argv, tree, env, log):
    print(f"Running {log.name}", flush=True)
    with log.open("w") as output:
        result = subprocess.run([str(x) for x in argv], cwd=tree, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Build failed; see {log}")


def compile_driver(tree, name, output_dir, env):
    record_path = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    record = json.loads(record_path.read_text().strip().rstrip(","))
    source = tree / "drivers" / name / (name + ".cpp")
    out = tree / "build" / output_dir
    out.mkdir(parents=True, exist_ok=True)
    obj = out / (name + ".o")
    command, replaced = [], 0
    recorded = record["arguments"]
    # A Darling -MJ record names the Mach-O compiler inside the container.
    # Replay target compilations through the selected Linux launcher instead.
    compiler = env["GUNYAH_LINUX_CXX"] if env.get("GUNYAH_LINUX") == "1" else recorded[0]
    command.append(compiler)
    arguments = iter(recorded[1:])
    for arg in arguments:
        if arg == record["file"]:
            command.append(str(source)); replaced += 1
        elif arg == "-o":
            next(arguments); command.extend(["-o", str(obj)])
        elif arg in ("-MJ", "-MF", "-MT", "-MQ", "-serialize-diagnostics"):
            next(arguments)  # Preserve original kernel dependency/compile records.
        else:
            command.append(arg)
    if replaced != 1:
        raise ValueError("Cannot identify source in XNU compile record")
    if name == "ArmDTPlatform" and env.get("GUNYAH_BUILTIN_HFS") == "1":
        command.append("-DGUNYAH_BUILTIN_HFS=1")
    execute(command, Path(record["directory"]), env, out / "compile.log")
    execute(["xcrun", "ar", "rcs", out / ("lib" + name + ".a"), obj], tree, env, out / "archive.log")


def build(tree, stage, jobs, extra_env=None):
    if any(key.startswith("XNU_") for key in os.environ):
        raise ValueError("Clear inherited XNU_* variables; the selected defconfig must control the build")
    sys.path.insert(0, str(tree / "scripts"))
    from unixnu.config import parse_config
    config = parse_config((DEVICE / "configs/gunyah_defconfig").read_text())
    env = dict(os.environ, JOBS=str(jobs))
    env["GUNYAH_XNU_PATCHES"] = str(DEVICE / "patches/xnu")
    env.update({key: "1" if value is True else "0" if value is False else str(value) for key, value in config.items()})
    env["XNU_EXTRA_CFLAGS"] = ("-Wno-reserved-identifier -Wno-pre-c11-compat -Wno-missing-designated-field-initializers "
                              "-Wno-suggest-override -Wno-unnecessary-virtual-specifier -Wno-suggest-destructor-override "
                              "-Wno-ms-bitfield-padding -DXNU_GUNYAH=1")
    if extra_env:
        env.update(extra_env)
    logs = tree / "build/gunyah-logs"
    logs.mkdir(parents=True, exist_ok=True)
    baseline = {**env, **{key: "0" for key in ("XNU_SOURCE_CORECRYPTO14", "XNU_SOURCE_PTHREAD", "XNU_ARM_DT_PLATFORM", "XNU_ARMCPU", "XNU_NATIVE_ARCH_TIMER", "XNU_SOURCE_MOCKFS")}}
    execute(["bash", "scripts/build-xnu-4k-baseline.sh"], tree, baseline, logs / "01-baseline.log")
    # 8796 has no CTF step and names the link output without ".noctf"; upstream scripts still use that name.
    legacy = tree / (str(KERNEL) + ".noctf")
    if not legacy.exists():
        legacy.symlink_to(KERNEL.name)
    checkpoint = tree / "build/xnu/checkpoints/native-4k-user-abi/kernel.macho"
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(tree / KERNEL, checkpoint)
    if stage == "platform":
        env["XNU_EXTRA_CFLAGS"] += " -DGUNYAH_BLOCK_BSD=1"
        execute([sys.executable, "scripts/build-corecrypto-14.py"], tree, env, logs / "02-crypto.log")
        execute([sys.executable, "scripts/build-corecrypto-14.py", "--namespace"], tree, env, logs / "03-crypto-namespace.log")
        if env.get("XNU_SOURCE_PTHREAD") == "1":
            execute([sys.executable, "scripts/build-libpthread-kernel.py"], tree, env, logs / "04-pthread.log")
        execute([sys.executable, DEVICE / "scripts/build-hfs.py", "--tree", tree], tree, env, logs / "04-hfs.log")
        env["GUNYAH_BUILTIN_HFS"] = "1"
        env["XNU_EXTRA_LD_ARCHIVES"] = env.get("XNU_EXTRA_LD_ARCHIVES", "") + " -force_load " + str(tree / "build/gunyah-hfs/libGunyahHfs.a")
        if env.get("GUNYAH_TRUST_MODULE_C"):
            # Opt-in diagnostic entitlement provider; amfi still stays NULL
            # unless the guest boots with gunyah-iphone-trust=1.
            execute([sys.executable, DEVICE / "scripts/build-security.py", "--tree", tree, "--archive",
                     "--trust-module-source", env["GUNYAH_TRUST_MODULE_C"]], tree, env, logs / "04-security.log")
            env["XNU_EXTRA_LD_ARCHIVES"] += " -force_load " + str(tree / "build/gunyah-security/libGunyahSecurity.a")
        compile_driver(tree, "ArmDTPlatform", "armdt-platform", env)
        compile_driver(tree, "ArmCpu", "armcpu", env)
        if env.get("XNU_SOURCE_MOCKFS") == "1":
            execute([sys.executable, "scripts/build-mockfs-fixture.py"], tree, env, logs / "04-mockfs.log")
        # The baseline already compiled these without GUNYAH_BLOCK_BSD; make does
        # not track flag changes, so force the platform hooks to be recompiled.
        for name in ("bsd/kern/bsd_init.c", "iokit/bsddev/IOKitBSDInit.cpp", "bsd/kern/ubc_subr.c", "osfmk/kern/startup.c", "osfmk/prng/prng_random.c"):
            (tree / ".cache/xnu-work" / name).touch()
        execute(["bash", "scripts/build-xnu-4k-baseline.sh"], tree, env, logs / "05-platform.log")
    execute([sys.executable, "scripts/audit-xnu-kernel.py", str(tree / KERNEL)], tree, env, logs / "06-kernel-audit.log")
    result = tree / "build/gunyah-result"
    result.mkdir(exist_ok=True)
    shutil.copy2(tree / KERNEL, result / "kernel.macho")
    report = dict(stage=stage, kernel_sha256=hashlib.sha256((result / "kernel.macho").read_bytes()).hexdigest(),
                  xnu_build_verified=True, xnu_boot_verified=False, ios_boot_verified=False)
    (result / "build-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Source kernel built: {result}; Gunyah boot validation still required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--stage", choices=("baseline", "platform"), default="platform")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    tree = args.tree.resolve()
    if not tree.is_dir():
        parser.error("Run workspace.py prepare first")
    report = preflight(tree)
    (tree / "gunyah-preflight.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["ready"]:
        print(json.dumps(report, indent=2))
        raise SystemExit(2)
    if not args.preflight:
        build(tree, args.stage, args.jobs)
    else:
        print("Build prerequisites present; no compilation performed")


if __name__ == "__main__":
    main()
