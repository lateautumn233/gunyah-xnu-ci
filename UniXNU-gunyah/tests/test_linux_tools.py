#!/usr/bin/env python3
"""Exercise native Linux tools with real ARM64 Mach-O, SDK and MIG outputs."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest


class LinuxToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.config = json.loads((TOOLS / "linux-toolchain.json").read_text())
        self.env = dict(os.environ, PATH=str(TOOLS) + os.pathsep + os.environ["PATH"],
                        MIGCOM=self.config["tools"]["migcom"], MIGCC=str(TOOLS / "target-clang"))

    def run_tool(self, *argv):
        result = subprocess.run([str(x) for x in argv], cwd=self.path, env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_sdk_compile_archive_and_static_kernel_link(self):
        source = self.path / "entry.c"
        source.write_text('#include <TargetConditionals.h>\n#include <stdint.h>\n'
                          '#if !TARGET_OS_IOS || !TARGET_CPU_ARM64\n#error Wrong target\n#endif\n'
                          'volatile uint64_t value; void _start(void) { value = 42; for (;;) {} }\n')
        obj, archive, kernel = [self.path / name for name in ("entry.o", "entry.a", "kernel")]
        self.run_tool(TOOLS / "xcrun", "--sdk", "iphoneos", "clang", "-isysroot", self.config["sdk"],
                      "-mkernel", "-ffreestanding", "-fno-stack-protector", "-c", source, "-o", obj)
        self.assertEqual(struct.unpack_from("<4I", obj.read_bytes()), (0xfeedfacf, 0x100000c, 0, 1))
        self.run_tool(TOOLS / "xcrun", "ar", "rcs", archive, obj)
        self.assertIn("__start", self.run_tool(TOOLS / "xcrun", "nm", "-g", "-U", "-j", archive))
        self.run_tool(TOOLS / "target-clang", "-nostdlib", "-static", "-Wl,-e,__start", "-Wl,-image_base,0xfffffff007004000",
                      "-Wl,-segprot,__TEXT,r-x,r-x", obj, "-o", kernel)
        self.assertEqual(struct.unpack_from("<4I", kernel.read_bytes()), (0xfeedfacf, 0x100000c, 0, 2))
        self.assertEqual(self.run_tool(TOOLS / "xcrun", "nm", "-u", "-j", kernel).strip(), "")

    def test_mig_generates_compilable_client_and_server(self):
        definitions = self.path / "probe.defs"
        definitions.write_text('subsystem gunyah_test 42000;\n'
                               'type mach_port_t = MACH_MSG_TYPE_COPY_SEND;\n'
                               'type int_t = MACH_MSG_TYPE_INTEGER_32 ctype: int;\n'
                               'import <mach/mach_types.h>;\n'
                               'routine ping(request: mach_port_t; value: int_t; out result: int_t);\n')
        self.run_tool(TOOLS / "xcrun", "mig", "-arch", "arm64", "-isysroot", self.config["sdk"],
                      "-novouchers", "-header", "probe.h", "-sheader", "probeServer.h",
                      "-user", "probeUser.c", "-server", "probeServer.c", definitions)
        for source in ("probeUser.c", "probeServer.c"):
            self.run_tool(TOOLS / "target-clang", "-isysroot", self.config["sdk"], "-c", source, "-o", source + ".o")
        self.assertIn("_gunyah_test_server", self.run_tool(TOOLS / "xcrun", "nm", "-g", "-U", "-j", "probeServer.c.o"))

    def test_plist_and_openstep_conversion(self):
        source, output = self.path / "source.pbxproj", self.path / "output.json"
        source.write_text('// !$*UTF8*$!\n{ name = "a b"; values = (one, two); /* comment */ }\n')
        self.run_tool(TOOLS / "plutil", "-convert", "json", "-o", output, source)
        self.assertEqual(json.loads(output.read_text()), {"name": "a b", "values": ["one", "two"]})
        source.write_bytes(plistlib.dumps({"CFBundleVersion": "23.6.0"}))
        self.assertEqual(self.run_tool(TOOLS / "plutil", "-extract", "CFBundleVersion", "raw", "-n", source), "23.6.0")
        self.run_tool(TOOLS / "plutil", "-convert", "binary1", "-o", source, source)
        self.assertEqual(plistlib.loads(source.read_bytes())["CFBundleVersion"], "23.6.0")

    def test_unknown_tool_fails(self):
        result = subprocess.run([TOOLS / "xcrun", "xcodebuild"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_compiler_error_status_survives_launcher(self):
        result = subprocess.run([TOOLS / "target-clang", "-x", "c", "-c", "-", "-o", "bad.o"],
                                input="#error intentional compiler failure\n", cwd=self.path,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intentional compiler failure", result.stderr)
        self.assertFalse((self.path / "bad.o").exists())

    def test_response_file_paths_and_compile_record(self):
        (self.path / "input file.c").write_text('_Static_assert(VALUE == 12, "quoted macro");\nint response_symbol;\n')
        (self.path / "compile.rsp").write_text('-c "input file.c" -D"VALUE=(5 + 7)" -o "output file.o" '
                                             '-MJ compile.json -MD -MF "output file.d"\n')
        self.run_tool(TOOLS / "target-clang", "@compile.rsp", "-c")
        record = json.loads((self.path / "compile.json").read_text().strip().rstrip(","))
        self.assertEqual(Path(record["directory"]), self.path)
        self.assertIn("input file.c", record["arguments"])
        self.assertIn("_response_symbol", self.run_tool(TOOLS / "xcrun", "nm", "-g", "-j", "output file.o"))
        self.assertIn("input\\ file.c", (self.path / "output file.d").read_text())

    def test_symbolset_plist_lint_and_in_place_conversion(self):
        path = self.path / "symbolsets.plist"
        value = {"Symbols": [{"SymbolName": "_kernel_probe"}]}
        path.write_bytes(plistlib.dumps(value))
        self.assertEqual(self.run_tool(TOOLS / "plutil", "-lint", "-s", path), "")
        self.run_tool(TOOLS / "plutil", "-convert", "binary1", "-s", path)
        self.assertTrue(path.read_bytes().startswith(b"bplist"))
        self.assertEqual(plistlib.loads(path.read_bytes()), value)
        path.write_bytes(b'<?xml version="1.0"?><plist><dict>')
        result = subprocess.run([TOOLS / "plutil", "-lint", "-s", path], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", required=True, type=Path)
    args, rest = parser.parse_known_args()
    TOOLS = args.tools.resolve()
    unittest.main(argv=[__file__, *rest])
