#!/usr/bin/env python3
"""Create a portable source bundle with pinned, self-contained git checkouts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

from workspace import DEVICE, SOURCES, run, verify
from iig_cache import verify as verify_iig_cache, LOCK as IIG_LOCK


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--fdt", type=Path, required=True)
    parser.add_argument("--counter-frequency", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linux-sources", type=Path, help="Include pinned Linux tool sources and their SDK mirror")
    parser.add_argument("--iig-cache", type=Path, help="Include the pinned generated DriverKit snapshot and raw HTML")
    parser.add_argument("--appleclang-packages", type=Path, help="Include pinned Apple CLT and Darling archives for Linux setup")
    parser.add_argument("--apple-iig", type=Path, help="Include the verified, self-contained Apple IIG/Darling runtime")
    args = parser.parse_args()
    if args.iig_cache and not args.linux_sources:
        parser.error("--iig-cache requires --linux-sources")
    if args.appleclang_packages and not args.linux_sources:
        parser.error("--appleclang-packages requires --linux-sources")
    if args.apple_iig:
        if not args.linux_sources:
            parser.error("--apple-iig requires --linux-sources")
        subprocess.run([sys.executable, DEVICE / "scripts/setup-iig.py", "verify",
                        "--output", args.apple_iig], check=True)
    apple_lock = json.loads((DEVICE / "linux/appleclang-sources.json").read_text())
    if args.appleclang_packages:
        for entry in apple_lock.values():
            path = args.appleclang_packages / entry["file"]
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if path.stat().st_size != entry["size"] or digest != entry["sha256"]:
                parser.error(f"Modified AppleClang/Darling package: {path}")
    if args.iig_cache:
        iig_lock = verify_iig_cache(args.iig_cache, args.sources / "xnu")
        for name, entry in iig_lock["outputs"].items():
            if hashlib.sha256((args.iig_cache / "html" / (name + ".html")).read_bytes()).hexdigest() != entry["html_sha256"]:
                parser.error(f"Modified IIG reference HTML: {name}")
    for name in SOURCES:
        verify(args.sources / name, name)
    if not 0 < args.counter_frequency < 1 << 32:
        parser.error("invalid measured counter frequency")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
        root = Path(directory) / "gunyah-xnu"
        root.mkdir()
        shutil.copytree(DEVICE, root / "device", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (root / "sources").mkdir()
        for name in SOURCES:
            destination = root / "sources" / name
            run("git", "clone", "--no-hardlinks", args.sources.resolve() / name, destination)
            verify(destination, name)
            if (destination / ".git/objects/info/alternates").exists():
                raise ValueError("Bundle must not depend on external object storage")
        (root / "inputs").mkdir()
        shutil.copy2(args.fdt, root / "inputs/final.dtb")
        metadata = {
            "sources": SOURCES, "counter_frequency": args.counter_frequency,
            "fdt_sha256": hashlib.sha256(args.fdt.read_bytes()).hexdigest(),
            "xnu_compiled": False, "xnu_booted": False,
            "sdk_included": False, "ipsw_included": False,
            "additional_network_inputs": ["DriverKit headers xnu-10063.121.3", "TrustCache headers xnu-8796.101.5"],
        }
        if args.linux_sources:
            lock = json.loads((DEVICE / "linux/sources.json").read_text())
            for name, entry in lock.items():
                reference = args.linux_sources.resolve() / name
                if run("git", "-C", reference, "rev-parse", "HEAD") != entry["commit"] or run(
                        "git", "-C", reference, "status", "--porcelain", "--untracked-files=no"):
                    raise ValueError(f"Modified or unpinned Linux source: {name}")
                if "sparse_path" in entry:
                    sdk = reference / entry["sparse_path"]
                    if run("git", "-C", reference, "ls-files", "--others", "--exclude-standard", entry["sparse_path"]):
                        raise ValueError("SDK mirror contains untracked files")
                    destination = root / "sdks" / sdk.name
                    shutil.copytree(sdk, destination, symlinks=True)
                    hashes = {}
                    for path in sorted(destination.rglob("*")):
                        if path.is_symlink():
                            if not path.resolve().is_relative_to(destination.resolve()):
                                raise ValueError(f"SDK symlink escapes package: {path}")
                            hashes[str(path.relative_to(root))] = {"symlink": path.readlink().as_posix()}
                        elif path.is_file():
                            hashes[str(path.relative_to(root))] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                    (root / "sdk-sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
                    metadata.update(sdk_included=True, sdk_path=str(destination.relative_to(root)),
                                    sdk_provenance=entry, sdk_manifest_sha256=hashlib.sha256((root / "sdk-sha256.json").read_bytes()).hexdigest())
                else:
                    destination = root / "sources" / name
                    run("git", "clone", "--no-hardlinks", reference, destination)
                    if (destination / ".git/objects/info/alternates").exists():
                        raise ValueError("Linux tools must not depend on external object storage")
            metadata.update(linux_sources=lock, linux_support_build_required=True,
                            linux_full_kernel_blockers=["Compatible IOKit Interface Generator (IIG)", "Configure AppleClang through Darling for XNU typed-allocation extensions"])
        if args.iig_cache:
            destination = root / "iig-cache"
            (destination / "html").mkdir(parents=True)
            for name in iig_lock["outputs"]:
                shutil.copy2(args.iig_cache / name, destination / name)
                shutil.copy2(args.iig_cache / "html" / (name + ".html"), destination / "html" / (name + ".html"))
            shutil.copy2(IIG_LOCK, destination / "provenance.json")
            metadata.update(iig_snapshot_included=True,
                            iig_snapshot_lock_sha256=hashlib.sha256(IIG_LOCK.read_bytes()).hexdigest(),
                            iig_snapshot_known_incompatibilities=iig_lock["known_kernel_abi_incompatibilities"])
        if args.appleclang_packages:
            destination = root / "appleclang-packages"
            destination.mkdir()
            for entry in apple_lock.values():
                shutil.copy2(args.appleclang_packages / entry["file"], destination / entry["file"])
            metadata.update(appleclang_packages_included=True, appleclang_sources=apple_lock,
                            appleclang_setup_required=True)
        if args.apple_iig:
            destination = root / "apple-iig"
            iig_sources = json.loads((DEVICE / "linux/iig-sources.json").read_text())
            for name in iig_sources["runtime"]:
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.apple_iig / name, target)
            (destination / "provenance.json").write_text(json.dumps(iig_sources, indent=2) + "\n")
            subprocess.run([sys.executable, DEVICE / "scripts/setup-iig.py", "verify",
                            "--output", destination], check=True)
            metadata.update(apple_iig_included=True, apple_iig_sources=iig_sources,
                            linux_full_kernel_blockers=[],
                            linux_setup_required=["Native host tools", "AppleClang/Darling", "Apple IIG launcher"])
        (root / "bundle.json").write_text(json.dumps(metadata, indent=2) + "\n")
        (root / "BUILD.txt").write_text(f'''Gunyah XNU source build preparation — not an iOS boot image

Use macOS with Xcode and the iphoneos SDK, Python >=3.11, git, make,
clang, cmake, ninja, unifdef, dtc. Keep the sources/ reference checkouts clean.
No SDK, IPSW or prelinked Apple components are included. The source build still
downloads omitted public DriverKit/TrustCache headers using pinned Apple tags.

From this directory:
python3 device/scripts/workspace.py prepare --sources sources --tree work/tree
python3 device/scripts/build-macos.py --tree work/tree --preflight
python3 device/scripts/build-macos.py --tree work/tree --stage platform --jobs 4

The platform build first creates the source baseline and compile records, then
builds source crypto/pthread and ArmDTPlatform/ArmCpu archives, relinks and audits.
Output: work/tree/build/gunyah-result/kernel.macho and build-result.json.
The macOS build sequence has NOT yet been run. A baseline-only build lacks the
crypto/CPU/platform providers and is an intermediate artifact, not a boot image.

Generate an ADT for the captured 512 MiB / 1-vCPU layout:
python3 device/scripts/make-gunyah-adt.py --fdt inputs/final.dtb \\
  --counter-frequency {args.counter_frequency} --unique-chip-id 0x47554e5941480001 \\
  --output work/kernel.macho.adt
Choose and preserve a distinct nonzero identity seed for each VM; the above is
an example. random-seed is regenerated on every invocation. Use a fresh final
FDT and measured CNTFRQ if VM configuration changes. Do not use a pre-shim dump.

Linux-verifiable checks (after prepare):
python3 device/tests/test_platform.py --fdt inputs/final.dtb --tree work/tree -v

Next: actual Xcode compilation, Gunyah kernel entry/console/timer validation,
then storage and a matched IPSW/prelink. No XNU/iOS runtime success is claimed.
''')
        if args.linux_sources:
            (root / "BUILD.txt").write_text('''Linux native toolchain + Apple SDK — source preparation, not a bootable kernel

Verified host: x86_64 Linux with LLVM/Clang 21, Python >=3.11.
Install host build dependencies: make, C/C++ compiler, LLVM development tools,
cmake, ninja, autoconf, automake, flex, bison, git, pkg-config, libbsd-dev,
libmd-dev, uuid-dev, libxml2-dev, zlib development headers, unifdef, pax, tcsh, dtc.
The native support tools run without macOS. XNU compilation can use the real
AppleClang executable through Darling, an additional Docker-based Linux stage.

The included iPhoneOS17.5.sdk is from the pinned xybp888/iOS-SDKs mirror.
This is a third-party snapshot, not authenticated against an Apple Xcode archive.
See bundle.json for provenance and sdk-sha256.json for all file/symlink hashes.
SDK version is not the iOS runtime/IPSW version. No IPSW is included.

From this directory (paths must not contain spaces or Make metacharacters):
python3 device/scripts/workspace.py prepare --sources sources --tree work/tree
python3 device/scripts/setup-linux.py build --sources sources \\
  --sdk sdks/iPhoneOS17.5.sdk --output work/linux --llvm-bin /usr/lib/llvm-21/bin
python3 device/tests/test_linux_tools.py --tools work/linux/bin -v
python3 device/scripts/build-linux.py --tree work/tree --toolchain work/linux \\
  --host-deps / --stage support --jobs 4

The support stage builds six native ELF setup tools, exports C dependency
headers and builds the real ARM64 libfirehose_kernel.a without xcodebuild.
Its .cache/linux-support-sdk is PARTIAL: it excludes generated DriverKit
interfaces and must not be substituted for the complete XNU build SDK.

Full baseline/platform compilation needs a compatible IIG implementation.
MIG is a separate tool and cannot replace IIG. The SDK contains no IIG binary.
The --iig option accepts a Linux-runnable tool/launcher. Apple IIG 427.100.5
with Xcode 16.2 libclang through Darling has generated all 18 interfaces, and
their kernel objects compiled against this XNU revision.

Stock Clang 21 lacks Apple's XNU
typed-allocation builtins and xnu_usage_semantics attribute. Test a compiler with:
python3 device/scripts/probe_xnu_compiler.py --tools work/linux/bin \\
  --output work/compiler-probe
Expected with stock LLVM: exit 2, ready=false. Apple SDK headers do not add
compiler features. No fallback constant macros or allocator removal is provided.
The full build checks these features before compiling the kernel. A passing
probe is necessary, but does not establish full compiler or runtime compatibility.

Toolchain tests cover SDK-based ARM64 compilation, archiving and static Mach-O
linking, compiling MIG-generated client/server sources, plist conversion and
rejecting unknown tools. They do not establish a successful XNU build or boot.

The build may download the pinned OpenStep parser wheel and omitted public
DriverKit/TrustCache headers. This is not a fully offline build environment.
Use device/scripts/make-gunyah-adt.py with inputs/final.dtb and measured CNTFRQ
19200000 for the captured single-vCPU VM layout; re-capture after VM changes.
''')
            if args.iig_cache:
                with (root / "BUILD.txt").open("a") as stream:
                    stream.write('''
This package includes iig-cache/: 36 recovered source files, their raw HTML,
and provenance. The 18 definitions in xnu-10063.121.3 match our patched
xnu-10063.141.1 .iig inputs byte for byte. The generated-source banner identifies
DriverKit-286. This third-party snapshot is not an authenticated Apple build;
the original generator command line is unauthenticated. Compilation has now
confirmed ABI incompatibility: dispatch calls the removed kernel helper
IORPCMessageFromMach and outgoing IORPC calls omit the required kernelContent.
The snapshot is retained for source/header research, not a full kernel build.

After workspace preparation:
python3 device/scripts/iig_cache.py verify --cache iig-cache --xnu work/tree/.cache/xnu-work
python3 device/tests/test_iig_cache.py --cache iig-cache \\
  --xnu work/tree/.cache/xnu-work --sdk sdks/iPhoneOS17.5.sdk -v
python3 device/scripts/build-linux.py --tree work/tree --toolchain work/linux \\
  --host-deps / --stage baseline --iig-cache iig-cache --prepare-only

Omitting --prepare-only rejects the incompatible snapshot before compilation.
With AppleClang a real attempt produced 922 intermediate kernel objects, but
failed on this IIG mismatch and Linux AWK escaping. The AWK issue is fixed and
init_sysent.o compiles. There is no built XNU kernel in this package.
The cache rejects changed interface inputs, generated files and unsupported
generator flags; it cannot regenerate interfaces after development edits.
''')
            with (root / "BUILD.txt").open("a") as stream:
                stream.write('''
AppleClang on Linux (tested Apple clang 15.0.0 / clang-1500.3.9.4):
Install Docker and cpio on the host. Docker must be accessible to your user.
The setup downloads from the pinned official Apple and Darling URLs if the
archives are absent. --appleclang-packages includes these two archives so the
fetch step below just verifies their sizes and SHA256. No macOS VM is used.

python3 device/scripts/setup-appleclang.py fetch --directory appleclang-packages
python3 device/scripts/setup-appleclang.py extract --directory appleclang-packages
python3 device/scripts/setup-appleclang.py image --directory appleclang-packages
python3 device/scripts/setup-appleclang.py start --directory appleclang-packages --workspace "$PWD"
python3 device/scripts/setup-appleclang.py configure --directory appleclang-packages --toolchain work/linux
TMPDIR="$PWD/work" python3 device/tests/test_linux_tools.py --tools work/linux/bin -v

The configure step preserves Linux host compilers and the native Mach-O linker,
and requires successful C/C++ XNU type-layout probes before activating the
AppleClang backend. All build directories must be under the mounted workspace.
Darling needs SYS_ADMIN/SYS_PTRACE and unconfined seccomp/AppArmor in this task
container. Only the project workspace and read-only extracted tools are mounted.
The container prefix is ephemeral; after removing/restarting the container,
remove it with docker rm -f gunyah-appleclang and run start/configure again.
Extraction requires a fresh apple-tools directory; keep existing artifacts or
choose a new package directory when repeating extraction.

Docker image construction still downloads the pinned Ubuntu image and current
Ubuntu dependencies. The image is not bit-reproducible or included in the bundle.
Apple package SHA256 and catalogue TOC SHA1 are recorded; the XAR certificate
signature chain was not independently authenticated. The earlier SDK mirror
provenance limitations still apply. No successful XNU/iOS boot is claimed.

''')
            if args.apple_iig:
                with (root / "BUILD.txt").open("a") as stream:
                    stream.write('''
Apple IIG on Linux (included apple-iig/; configure AFTER AppleClang):
python3 device/scripts/setup-iig.py verify --output apple-iig
python3 device/scripts/setup-iig.py configure --output apple-iig --toolchain work/linux
python3 device/scripts/build-linux.py --tree work/tree --toolchain work/linux \\
  --host-deps / --stage platform --iig work/linux/bin/target-iig --jobs 8

The runtime contains unmodified IIG from Xcode 16.4 and libclang from Xcode
16.2. This pairing uses libclang's C API and avoids the newer libc++ symbol
missing in Darling. All 18 generated interfaces matched the validated outputs.
Original XIP files are not included. device/linux/iig-sources.json records
mirror URLs, archive hashes, Apple root hash and extracted binary hashes.
Both original XIPs passed XAR signature/Apple certificate chain and signed
Content verification; revocation was not checked. To re-extract, obtain the
pinned XIPs and official root certificate, then use setup-iig.py extract and
assemble (see --help; extraction requires Python cryptography, openssl, cpio).
This authentication applies to IIG inputs, not the separate SDK mirror.

The link explicitly selects the pinned Apple kernel compiler runtime for
stack probes and the XNU PGO buffer ABI. No kernel/userland boot is implied
by compilation or static audit. No built kernel or IPSW is included here.
''')
        hashes = {}
        for path in sorted((root / "device").rglob("*")):
            if path.is_file():
                hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        (root / "device-sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
        with tarfile.open(args.output, "w:gz") as archive:
            archive.add(root, arcname="gunyah-xnu")
    with args.output.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(f"{digest}  {args.output.name}\n")
    print(f"Bundle: {args.output} ({args.output.stat().st_size} bytes)\nSHA256 {digest}")


if __name__ == "__main__":
    main()
