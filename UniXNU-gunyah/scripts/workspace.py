#!/usr/bin/env python3
"""Prepare an isolated, pinned XNU build tree; never patch reference checkouts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[1]
SOURCES = json.loads((DEVICE / "sources.json").read_text())


def run(*args, cwd=None):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr or result.stdout}")
    return result.stdout.strip()


def verify(path, name):
    if run("git", "-C", path, "rev-parse", "HEAD") != SOURCES[name]["commit"]:
        raise ValueError(f"Wrong source commit: {path}")
    if run("git", "-C", path, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError(f"Modified reference source: {path}")


def fetch(base, names):
    base.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = base / name
        if not path.exists():
            path.mkdir()
            run("git", "init", path)
            run("git", "-C", path, "remote", "add", "origin", SOURCES[name]["url"])
        if not (path / ".git").exists():
            raise ValueError(f"Expected git checkout: {path}")
        try:
            run("git", "-C", path, "rev-parse", "HEAD")
        except RuntimeError:
            run("git", "-C", path, "-c", "http.version=HTTP/1.1", "fetch", "--depth", "1", "origin", SOURCES[name]["commit"])
            run("git", "-C", path, "checkout", "--detach", "FETCH_HEAD")
        verify(path, name)
        print(f"Pinned {name} {SOURCES[name]['commit']}", flush=True)


def apply(path, patch):
    reverse = subprocess.run(["git", "-C", str(path), "apply", "--reverse", "--check", str(patch)], capture_output=True)
    if reverse.returncode:
        run("git", "-C", path, "apply", "--check", patch)
        run("git", "-C", path, "apply", patch)


def retarget(tree):
    # Retarget the upstream driver script from iOS 17 (10063) to the iOS 16 line (8796).
    script = tree / "scripts/build-xnu-4k-baseline.sh"
    text = script.read_text()
    for old_value, new_value in (("-miphoneos-version-min=17.0", "-miphoneos-version-min=16.0"),
                                 ("-Wl,-ios_version_min,17.0", "-Wl,-ios_version_min,16.0")):
        if old_value not in text:
            raise ValueError(f"Upstream build script changed: {old_value}")
        text = text.replace(old_value, new_value)
    # The 10063 prelink-kit patches are not carried over; do not glob an empty directory.
    old_loop = 'for PATCH in "$ROOT"/patches/xnu/*.patch "$ROOT"/kits/NativePrelink/patches/*.patch; do'
    if old_loop not in text:
        raise ValueError("Upstream build script changed: patch loop")
    text = text.replace(old_loop, 'for PATCH in "$ROOT"/patches/xnu/*.patch; do')
    script.write_text(text)
    # libpthread-514.100.2 is the macOS 13.6 / iOS 16 kernel component paired with xnu-8796.
    pthread = tree / "scripts/build-libpthread-kernel.py"
    text = pthread.read_text()
    for old_value, new_value in (("c0e60fb5ecfc54cf379c261d3f9572cc22ded891", "a6c70ca0e544347a0377babf748f831577ec24f9"),
                                 ("arm64-apple-ios17.0", "arm64-apple-ios16.0"),
                                 ("(2, 0x110000)", "(2, 0x100000)")):
        if old_value not in text:
            raise ValueError(f"Upstream pthread script changed: {old_value}")
        text = text.replace(old_value, new_value)
    pthread.write_text(text)
    audit = tree / "scripts/audit-xnu-kernel.py"
    text = audit.read_text()
    for old_value, new_value in (("(2, 0x110000)", "(2, 0x100000)"), ("'iOS 17.0'", "'iOS 16.0'")):
        if old_value not in text:
            raise ValueError(f"Upstream kernel audit changed: {old_value}")
        text = text.replace(old_value, new_value)
    audit.write_text(text)


def prepare(sources, tree):
    for name in SOURCES:
        verify(sources / name, name)
    tree.mkdir(parents=True, exist_ok=True)
    # Freeze the inputs. Refuse to merge into an existing build directory.
    if any(tree.iterdir()):
        raise ValueError(f"Build tree must be empty: {tree}")
    run("git", "init", tree)  # Keep git apply rooted here even inside an outer checkout.
    upstream = sources / "UniXNU"
    for name in ("scripts", "drivers", "kits", "patches", "package"):
        shutil.copytree(upstream / name, tree / name, ignore=shutil.ignore_patterns("__pycache__"))
    # UniXNU's own xnu patches target 10063. Replace them with the curated set ported to the
    # pinned XNU (scripts/port-upstream-patches.py); the prelink kit patches are 10063-only too.
    shutil.rmtree(tree / "patches/xnu")
    shutil.copytree(DEVICE / "patches/upstream", tree / "patches/xnu")
    shutil.rmtree(tree / "kits/NativePrelink/patches")
    (tree / "kits/NativePrelink/patches").mkdir()
    (tree / "refer").mkdir()
    for name in SOURCES:
        if name != "UniXNU":
            run("git", "clone", "--no-hardlinks", sources / name, tree / "refer" / name)
    (tree / ".cache").mkdir()
    work = tree / ".cache/xnu-work"
    run("git", "clone", "--no-hardlinks", tree / "refer/xnu", work)
    patches = sorted((tree / "patches/xnu").glob("*.patch")) + sorted((tree / "kits/NativePrelink/patches").glob("*.patch"))
    for patch in patches:
        apply(work, patch)
    # Keep Gunyah patches separate: the upstream build script owns its own ordering.
    for patch in sorted((DEVICE / "patches/xnu").glob("*.patch")):
        apply(work, patch)
    for patch in sorted((DEVICE / "patches/drivers").glob("*.patch")) + sorted((DEVICE / "patches/project").glob("*.patch")):
        run("git", "apply", "--check", patch, cwd=tree)
        run("git", "apply", patch, cwd=tree)
    retarget(tree)  # after the project patches: they match the unmodified upstream script text
    shutil.copytree(DEVICE / "drivers", tree / "drivers", dirs_exist_ok=True)
    manifest = {"sources": SOURCES, "upstream_patch_count": len(patches), "device_patches": {
        str(p.relative_to(DEVICE)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((DEVICE / "patches").rglob("*.patch"))}}
    manifest["device_driver_files"] = {
        str(p.relative_to(DEVICE)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((DEVICE / "drivers").rglob("*")) if p.is_file()}
    (tree / "gunyah-inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Prepared {tree}; XNU compilation has not been performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "prepare"))
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--only", nargs="+", choices=tuple(SOURCES))
    args = parser.parse_args()
    if args.action == "fetch":
        fetch(args.sources.resolve(), args.only or SOURCES)
    else:
        if not args.tree:
            parser.error("prepare requires --tree")
        prepare(args.sources.resolve(), args.tree.resolve())


if __name__ == "__main__":
    main()
