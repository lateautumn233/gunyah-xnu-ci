#!/usr/bin/env python3
"""Verify source recovery and rejection of changed DriverKit cache inputs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import iig_cache


class CacheTests(unittest.TestCase):
    def test_html_preserves_source_and_removes_browser_labels(self):
        html = b'''<table class="code">
<tr><th id="1">1</th><td>\tfoo(<span class='inlayHint'>arg:&nbsp;</span>&amp;x); \\</td></tr>
<tr><th id="2">2</th><td><b>int</b> a &lt; b;</td></tr>
<tr><th id="3">3</th><td></td></tr></table>'''
        self.assertEqual(iig_cache.extract(html), b'\tfoo(&x); \\\nint a < b;\n\n')
        with self.assertRaises(ValueError):
            iig_cache.extract(html.replace(b'id="2"', b'id="4"'))
        with self.assertRaises(ValueError):
            iig_cache.extract(html[:-8])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_snapshot_extraction(self):
        lock = iig_cache.verify(CACHE, XNU)
        self.assertEqual(len(lock["outputs"]), 36)
        for name, entry in lock["outputs"].items():
            data = (CACHE / "html" / (name + ".html")).read_bytes()
            self.assertEqual(iig_cache.sha(data), entry["html_sha256"])
            self.assertEqual(iig_cache.extract(data), (CACHE / name).read_bytes())
        self.assertIn('0xab6f76dde6d693f2ULL', (CACHE / 'IOService.h').read_text())

    def test_incompatible_kernel_rpc_snapshot_rejected(self):
        # Inputs are identical, but the generated call bridge uses an older ABI.
        self.assertIn("kernelContent", (XNU / "iokit/IOKit/IORPC.h").read_text())
        source = (CACHE / "IOService.iig.cpp").read_text()
        self.assertIn("IORPCMessageFromMach(rpc.message, false)", source)
        self.assertIn("IORPC rpc = {", source)
        self.assertNotIn("kernelContent", source)
        with self.assertRaisesRegex(ValueError, "incompatible with the target kernel ABI"):
            iig_cache.verify(CACHE, XNU, require_kernel_compatibility=True)

    def test_changed_input_or_output_rejected(self):
        lock = json.loads(iig_cache.LOCK.read_text())
        for name in lock["inputs"]:
            p = self.root / "xnu" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(XNU / name, p)
        local_cache = self.root / "cache"
        local_cache.mkdir()
        for name in lock["outputs"]:
            shutil.copyfile(CACHE / name, local_cache / name)
        iig_cache.verify(local_cache, self.root / "xnu")
        source = self.root / "xnu/iokit/DriverKit/OSAction.iig"
        source.write_bytes(source.read_bytes() + b'\n// changed\n')
        with self.assertRaisesRegex(ValueError, "input mismatch"):
            iig_cache.verify(local_cache, self.root / "xnu")
        shutil.copyfile(XNU / "iokit/DriverKit/OSAction.iig", source)
        (local_cache / "OSAction.iig.cpp").write_text("// incomplete\n")
        with self.assertRaisesRegex(ValueError, "output mismatch"):
            iig_cache.verify(local_cache, self.root / "xnu")

    def test_real_emit_and_changed_flags_rejected(self):
        env = dict(GUNYAH_IIG_CACHE=str(CACHE), GUNYAH_IIG_XNU=str(XNU), GUNYAH_IIG_SDK=str(SDK))
        header, impl = self.root / "OSAction.h", self.root / "OSAction.iig.cpp"
        argv = ["--def", str(XNU / "iokit/DriverKit/OSAction.iig"), "--header", str(header),
                "--impl", str(impl), "--framework-name", "DriverKit", "--",
                *[f"-I{XNU / p}" for p in ("iokit", "osfmk", "bsd", "EXTERNAL_HEADERS")],
                f"-I{XNU.parent.parent / 'build/test-iig/bsd'}", "-isysroot", str(SDK),
                "-x", "c++", "-std=gnu++2b", "-D__IIG=1", "-DDRIVERKIT_PRIVATE=1",
                "-DPRIVATE_WIFI_ONLY=1", "-DXNU_PLATFORM_iPhoneOS"]
        with patch.dict(os.environ, env):
            iig_cache.emit(argv)
            self.assertEqual(header.read_bytes(), (CACHE / header.name).read_bytes())
            self.assertEqual(impl.read_bytes(), (CACHE / impl.name).read_bytes())
            with self.assertRaisesRegex(ValueError, "Unreviewed IIG arguments"):
                iig_cache.emit(argv + ["-DDRIVERKIT_PRIVATE=0"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--xnu", required=True, type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    args, rest = parser.parse_known_args()
    CACHE, XNU, SDK = args.cache.resolve(), args.xnu.resolve(), args.sdk.resolve()
    unittest.main(argv=[__file__, *rest])
