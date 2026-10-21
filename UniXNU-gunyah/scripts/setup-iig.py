#!/usr/bin/env python3
"""Extract authenticated Xcode IIG inputs and assemble a Linux/Darling runtime.

The runtime uses IIG 427.100.5 from Xcode 16.4 and libclang's C API from Xcode
16.2. The original 16.4 libclang requires a libc++ symbol absent in Darling.
Both files remain byte-identical to their signed Apple archives.
"""
import argparse
import base64
import hashlib
import json
import lzma
from pathlib import Path
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zlib

DEVICE = Path(__file__).resolve().parents[1]
LOCK = json.loads((DEVICE / "linux/iig-sources.json").read_text())


def digest(path, algorithm="sha256"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_extracted(directory, version):
    entry = LOCK["versions"][version]
    for name, expected in entry["files"].items():
        check(digest(directory / name) == expected, f"Modified Xcode {version} file: {name}")


def verify_runtime(directory):
    for name, entry in LOCK["runtime"].items():
        expected = LOCK["versions"][entry["version"]]["files"][entry["file"]]
        path = directory / name
        check(path.is_file() and not path.is_symlink(), f"Runtime must contain its own file: {name}")
        check(digest(path) == expected, f"Modified IIG runtime file: {name}")


def extract(archive, output, version, root_certificate):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    entry = LOCK["versions"][version]
    check(archive.stat().st_size == entry["size"] and digest(archive) == entry["sha256"],
          "Xcode archive size/SHA256 mismatch")
    check(not output.exists(), "Extraction requires a fresh output directory")
    root_data = root_certificate.read_bytes()
    check(hashlib.sha256(root_data).hexdigest() == LOCK["apple_root"]["sha256"], "Apple root certificate mismatch")
    with archive.open("rb") as stream:
        magic, header, xar_version, compressed_size, plain_size, algorithm = struct.unpack(
            ">4sHHQQI", stream.read(28))
        check((magic, header, xar_version, algorithm) == (b"xar!", 28, 1, 1), "Unexpected XAR format")
        check(compressed_size < 1024 * 1024 and plain_size < 4 * 1024 * 1024, "Oversized XAR TOC")
        compressed = stream.read(compressed_size)
        plain = zlib.decompress(compressed)
        check(len(plain) == plain_size, "XAR TOC length mismatch")
        toc = ET.fromstring(plain).find("toc")
        heap = header + compressed_size
        certs = [x509.load_der_x509_certificate(base64.b64decode(e.text))
                 for e in toc.iter() if e.tag.endswith("X509Certificate")]
        check(len(certs) == 3 and certs[-1] == x509.load_der_x509_certificate(root_data), "Unexpected XAR certificate chain")
        output.mkdir(parents=True)
        proof = output / "verification"
        proof.mkdir()
        (proof / "toc.xml").write_bytes(plain)
        for index, cert in enumerate(certs):
            (proof / f"certificate-{index}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        subprocess.run(["openssl", "verify", "-CAfile", str(proof / "certificate-2.pem"),
                        "-untrusted", str(proof / "certificate-1.pem"), str(proof / "certificate-0.pem")], check=True)
        checksum, signature = toc.find("checksum"), toc.find("signature")
        check(checksum.get("style") == "sha1" and signature.get("style") == "RSA", "Unsupported XAR signature")
        stream.seek(heap + int(checksum.findtext("offset")))
        check(stream.read(20) == hashlib.sha1(compressed).digest(), "TOC digest mismatch")
        stream.seek(heap + int(signature.findtext("offset")))
        signature_bytes = stream.read(int(signature.findtext("size")))
        certs[0].public_key().verify(signature_bytes, compressed, padding.PKCS1v15(), hashes.SHA1())
        content, = [f for f in toc.findall("file") if f.findtext("name") == "Content"]
        offset = heap + int(content.findtext("data/offset"))
        length = int(content.findtext("data/length"))
        expected = content.findtext("data/archived-checksum")
        check(expected == entry["content_sha1"] and offset + length <= archive.stat().st_size, "Unexpected signed Content")
        stream.seek(offset)
        remaining, content_hash = length, hashlib.sha1()
        while remaining:
            chunk = stream.read(min(8 * 1024 * 1024, remaining))
            check(bool(chunk), "Truncated Content")
            content_hash.update(chunk)
            remaining -= len(chunk)
        check(content_hash.hexdigest() == expected, "Signed Content digest mismatch")
        stream.seek(offset)
        check(stream.read(4) == b"pbzx", "Expected PBZX Content")
        flags, = struct.unpack(">Q", stream.read(8))
        # Only two fixed files from the authenticated archive are extracted.
        patterns = [p for name in entry["files"] for p in (name, "./" + name)]
        with subprocess.Popen(["cpio", "-id", "--no-absolute-filenames", "--quiet", *patterns],
                              cwd=output, stdin=subprocess.PIPE) as unpack:
            while flags & 0x1000000:
                flags, size = struct.unpack(">QQ", stream.read(16))
                check(0 < size <= 32 * 1024 * 1024, "Unexpected PBZX chunk size")
                data = stream.read(size)
                check(len(data) == size, "Truncated PBZX chunk")
                if data.startswith(b"\xfd7zXZ\x00"):
                    data = lzma.decompress(data)
                unpack.stdin.write(data)
            unpack.stdin.close()
            check(unpack.wait() == 0 and stream.tell() == offset + length, "CPIO extraction failed")
    verify_extracted(output, version)
    (proof / "result.json").write_text(json.dumps(dict(version=version, source=entry,
        xar_signature_verified=True, certificate_chain_verified=True, revocation_checked=False), indent=2) + "\n")


def assemble(old, new, output):
    verify_extracted(old, "16.2")
    verify_extracted(new, "16.4")
    check(not output.exists(), "Runtime requires a fresh output directory")
    for name, entry in LOCK["runtime"].items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2((old if entry["version"] == "16.2" else new) / entry["file"], target)
    verify_runtime(output)
    (output / "provenance.json").write_text(json.dumps(LOCK, indent=2) + "\n")


def configure(runtime, toolchain):
    verify_runtime(runtime)
    path = toolchain / "bin/linux-toolchain.json"
    original = path.read_text()
    config = json.loads(original)
    workspace = Path(config["appleclang"]["workspace"])
    check(runtime.is_relative_to(workspace), "IIG runtime must be inside the Darling workspace")
    launcher = toolchain / "bin/target-iig"
    if not launcher.exists():
        launcher.symlink_to(DEVICE / "linux/darwin-tool.py")
    config["apple_iig"] = dict(binary=str(runtime / "bin/iig"), sources=LOCK)
    config["tools"]["iig"] = str(launcher)
    path.write_text(json.dumps(config, indent=2) + "\n")
    try:
        result = subprocess.run([launcher, "--version"], cwd=workspace, capture_output=True, text=True, check=True)
        check(result.stdout.strip() == LOCK["generator_version"], "Unexpected IIG version")
    except BaseException:
        path.write_text(original)
        raise
    print(f"IIG launcher: {launcher}; interface generation/compilation must still be validated")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("extract", "assemble", "verify", "configure"))
    parser.add_argument("--output", required=True, type=Path, help="Extraction or assembled runtime directory")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--version", choices=("16.2", "16.4"))
    parser.add_argument("--apple-root", type=Path)
    parser.add_argument("--xcode-16-2", type=Path)
    parser.add_argument("--xcode-16-4", type=Path)
    parser.add_argument("--toolchain", type=Path)
    args = parser.parse_args()
    if args.action == "extract":
        if not all((args.archive, args.version, args.apple_root)):
            parser.error("extract requires --archive, --version and --apple-root (URL/hash in linux/iig-sources.json)")
        extract(args.archive.resolve(), args.output.resolve(), args.version, args.apple_root.resolve())
    elif args.action == "assemble":
        if not args.xcode_16_2 or not args.xcode_16_4:
            parser.error("assemble requires both extracted Xcode directories")
        assemble(args.xcode_16_2.resolve(), args.xcode_16_4.resolve(), args.output.resolve())
    elif args.action == "configure":
        if not args.toolchain:
            parser.error("configure requires --toolchain")
        configure(args.output.resolve(), args.toolchain.resolve())
    else:
        verify_runtime(args.output.resolve())
        print("IIG and libclang match the pinned Apple archive files")


if __name__ == "__main__":
    main()
