#!/usr/bin/env python3
"""Re-derive the curated upstream UniXNU patches for the pinned XNU (8796.141.3).

UniXNU's patches target 10063. For each name in the curated list this applies the
patch with `git apply`, then `patch --fuzz=3` where context drifted, applies the
few manual fixups below, and stores the resulting diff in patches/upstream/.
Run once when changing the XNU pin; the stored patches are what builds use.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

DEVICE = Path(__file__).resolve().parents[1]
CURATED = """apple-only-cpu-tunables architectural-timer-entry armvirt-platform-personality cxx-flag-dependencies
disabled-deferred-reclaim external-archive-dependencies kernel-sdk-root local-availability mockfs-intermediate-lookup
mockfs-memory-device-width mockfs-statfs mockfs-test-file mockfs-typed-allocation native-4k-bootstrap-capacity
native-4k-signature-hash-cache native-4k-user-abi native-aes-personality native-arm-pan native-dt-panic-region
native-priv-work-interval native-smp-secondary native-trust-cache-runtime native-work-interval-soft-fail
non-apple-cache-monitor non-apple-iommu-bootstrap non-apple-pmap-field null-root-media source-corecrypto14-bootstrap
source-machine-layer source-pthread-bootstrap zzx-pmap-sync-64bit-pa""".split()


def sh(*args, cwd, check=False):
    result = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return result


def fix_files_arm64(tree):
    # 8796 lists only two amcc sources; 10063's hunk does not apply.
    path = tree / "osfmk/conf/files.arm64"
    text = path.read_text()
    text = re.sub(r"^(osfmk/arm64/amcc_rorgn_ppl\.c optional nos_arm_asm config_pmap_ppl)$", r"\1 apple_amcc", text, flags=re.M)
    text = re.sub(r"^(osfmk/arm64/amcc_rorgn_common\.c optional nos_arm_asm)$", r"\1 apple_amcc", text, flags=re.M)
    path.write_text(text)


def fix_unstripped_name(tree):
    # 8796 names the link output mach.<config>.unstripped (no .noctf suffix).
    path = tree / "makedefs/MakeInc.kernel"
    path.write_text(path.read_text().replace(".unstripped.noctf", ".unstripped"))


FIXUPS = {"source-machine-layer": fix_files_arm64, "external-archive-dependencies": fix_unstripped_name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xnu", type=Path, required=True, help="Pinned xnu checkout (read only; cloned to scratch)")
    parser.add_argument("--upstream", type=Path, required=True, help="UniXNU checkout with patches/xnu")
    args = parser.parse_args()
    args.xnu, args.upstream = args.xnu.resolve(), args.upstream.resolve()
    out = DEVICE / "patches/upstream"
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        tree = Path(scratch) / "xnu"
        sh("git", "clone", "-q", "--no-hardlinks", args.xnu, tree, cwd=scratch, check=True)
        sh("git", "config", "user.email", "port@example.invalid", cwd=tree)
        sh("git", "config", "user.name", "port", cwd=tree)
        for name in CURATED:
            patch = args.upstream / "patches/xnu" / f"{name}.patch"
            mode = "exact"
            if sh("git", "apply", patch, cwd=tree).returncode:
                sh("patch", "-p1", "--fuzz=3", "--no-backup-if-mismatch", "-s", "-i", patch, cwd=tree)
                mode = "fuzz"
            for leftover in sh("git", "ls-files", "-o", "--exclude-standard", cwd=tree).stdout.split():
                if leftover.endswith((".rej", ".orig")):
                    (tree / leftover).unlink()
                    mode += " (rejected hunk dropped)"
            if name in FIXUPS:
                FIXUPS[name](tree)
                mode += " + fixup"
            sh("git", "add", "-A", cwd=tree)
            (out / f"{name}.patch").write_text(sh("git", "diff", "--cached", cwd=tree).stdout)
            sh("git", "commit", "-qm", name, cwd=tree)
            print(f"{name}: {mode}")


if __name__ == "__main__":
    main()
