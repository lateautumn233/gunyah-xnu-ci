#!/usr/bin/env python3
"""Check real captured FDT conversion, malformed inputs and the UART patch core."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adt", DEVICE / "scripts/make-gunyah-adt.py")
adt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adt)


def decode(data):
    """Independent bounded ADT reader for consumer ABI assertions."""
    def walk(offset):
        count, children = struct.unpack_from("<II", data, offset)
        offset += 8
        props = {}
        for _ in range(count):
            key, size = struct.unpack_from("<32sI", data, offset)
            key = key.split(b"\0")[0].decode()
            offset += 36
            if key in props or offset + size > len(data):
                raise ValueError("Bad property")
            props[key] = data[offset:offset + size]
            offset += (size + 3) & ~3
        nested = {}
        for _ in range(children):
            child, offset = walk(offset)
            nested[child[0]["name"].rstrip(b"\0").decode()] = child
        return (props, nested), offset
    root, consumed = walk(0)
    if consumed != len(data):
        raise ValueError("Trailing ADT data")
    return root


class PlatformTests(unittest.TestCase):
    def test_pci_windows_consumer(self):
        r = self.resources()
        bus, devices = decode(adt.generate(r, 0x10000000, 1234))[1]['arm-io']
        pci = devices['gunyah-pci'][0]
        start, base, _ = struct.unpack('<3Q', bus['ranges'])
        offset, size = struct.unpack('<2Q', pci['reg'])
        self.assertEqual((offset + base - start, size), tuple(r['pci_ecam']))
        self.assertEqual(struct.unpack('<2I', pci['bus-range']), (0, 0))
        self.assertIn('dma-coherent', pci)
        self.assertEqual(list(struct.iter_unpack('<4Q', pci['gunyah,pci-windows-v1'])), r['pci_windows'])
        self.assertEqual(len(r['pci_windows']), 2)

    def test_pci_nonidentity_translation(self):
        words = adt.Fdt(INPUT_FDT).words('/pci', 'ranges')
        words[2] = 0x10000000
        fdt = self.mutate(['-t', 'x', '/pci', 'ranges', *[f'{w:x}' for w in words]])
        r = self.resources(fdt)
        self.assertEqual(r['pci_windows'][0][1:3], (0x10000000, 0x2000000))

    def test_reject_bad_pci_windows(self):
        original = adt.Fdt(INPUT_FDT).words('/pci', 'ranges')
        cases = [original[:-1]]
        for index, value in ((0, 0x01000000), (4, 0x80400000), (4, 0x10000),
                             (6, 0), (5, 0xffffffff)):
            words = original.copy()
            words[index] = value
            cases.append(words)
        cases.append(original + original[:7])
        overflow = original.copy()
        overflow[3:5] = [0xffffffff, 0xfffffff0]
        cases.append(overflow)
        for words in cases:
            with self.subTest(words=words), self.assertRaises(ValueError):
                self.resources(self.mutate(['-t', 'x', '/pci', 'ranges', *[f'{w:x}' for w in words]]))

    def test_reject_bad_pci_bus(self):
        with self.assertRaises(ValueError):
            self.resources(self.mutate(['-t', 'x', '/pci', 'bus-range', '0', '1']))

    def test_ramdisk_placeholder(self):
        _, children = decode(adt.generate(self.resources(), 0x10000000, 1234, 65536, ramdisk=True))
        memory_map = children['chosen'][1]['memory-map'][0]
        self.assertEqual(struct.unpack('<2Q', memory_map['RAMDisk']), (0, 0))
        _, children = decode(adt.generate(self.resources(), 0x10000000, 1234))
        self.assertNotIn('RAMDisk', children['chosen'][1]['memory-map'][0])

    def test_reserved_panic_region_placeholder(self):
        resources = self.resources()
        _, children = decode(adt.generate(resources, 0x10000000, 1234, 65536))
        self.assertEqual(struct.unpack('<2Q', children['pram'][0]['reg']), (0, 65536))
        self.assertEqual(children['chosen'][0]['embedded-panic-log-size'], struct.pack('<I', 65536))
        for size in (4096, 16385, 2 * 1024 * 1024):
            with self.assertRaises(ValueError):
                adt.generate(resources, 0x10000000, 1234, size)

    def resources(self, fdt=None):
        return adt.collect(fdt or INPUT_FDT, 19200000)

    def mutate(self, args):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "case.dtb"
        shutil.copy2(INPUT_FDT, output)
        subprocess.run(["fdtput", *args[:2], str(output), *args[2:]], check=True, capture_output=True)
        return output

    def test_consumer_resources_and_nvram(self):
        r = self.resources()
        root, children = decode(adt.generate(r, 0x10000000, 1234))
        self.assertEqual(root["name"], b"device-tree\0")
        self.assertEqual(set(children), {"chosen", "cpus", "psci", "defaults", "options", "product", "gunyah-uart", "arm-io"})
        bus, devices = children["arm-io"]
        start, physical, size = struct.unpack("<3Q", bus["ranges"])
        dist, dsize, redist, rsize = struct.unpack("<4Q", devices["intc"][0]["reg"])
        self.assertEqual((physical+dist-start, dsize), tuple(r["gicd"]))
        self.assertEqual((physical+redist-start, rsize), tuple(r["gicr"]))
        self.assertLessEqual(redist+rsize, size)
        self.assertNotEqual(physical, 0)
        self.assertEqual(struct.unpack("<2Q", children["gunyah-uart"][0]["reg"]), tuple(r["uart"]))
        self.assertEqual(devices["intc"][0]["virtual-timer-intid"], struct.pack("<I", r["timer_intid"]))
        self.assertEqual(children["psci"][0]["method"], b"hvc\0")
        chosen, _ = children["chosen"]
        image = chosen["nvram-proxy-data"]
        self.assertEqual(len(image), 8192)
        self.assertEqual(struct.unpack_from("<I", image, 16)[0], zlib.adler32(image[20:]))
        for offset in (0, 32, 2096):
            header = image[offset:offset+16]
            checksum = sum(header[:1] + header[2:])
            while checksum > 255:
                checksum = (checksum & 255) + (checksum >> 8)
            self.assertEqual(header[1], checksum)

    def test_fresh_entropy(self):
        first = decode(adt.generate(self.resources(), 0x10000000, 1234))[1]["chosen"][0]
        second = decode(adt.generate(self.resources(), 0x10000000, 1234))[1]["chosen"][0]
        self.assertEqual(len(first["random-seed"]), 64)
        self.assertNotEqual(first["random-seed"], second["random-seed"])
        self.assertEqual(first["unique-chip-id"], second["unique-chip-id"])

    def test_timer_is_from_fdt(self):
        fdt = self.mutate(["-t", "x", "/timer", "interrupts", "1", "d", "108", "1", "e", "108", "1", "a", "108"])
        self.assertEqual(self.resources(fdt)["timer_intid"], 26)

    def test_reject_wrong_conduit(self):
        with self.assertRaises(ValueError):
            self.resources(self.mutate(["-t", "s", "/psci", "method", "smc"]))

    def test_reject_wrong_uart_width(self):
        with self.assertRaises(ValueError):
            self.resources(self.mutate(["-t", "x", "/U6_16550A@3f8", "reg-io-width", "4"]))

    def test_reject_non_ppi_timer(self):
        with self.assertRaises(ValueError):
            self.resources(self.mutate(["-t", "x", "/timer", "interrupts", "1", "d", "108", "1", "e", "108", "0", "b", "108"]))

    def test_reject_bad_window(self):
        for window in (0, 0x10001000, 0x20000000):
            with self.assertRaises(ValueError):
                adt.generate(self.resources(), window, 1234)

    def test_reject_reserved_overlap(self):
        with self.assertRaises(ValueError):
            self.resources(self.mutate(["-t", "x", "/memory", "reg", "0", "80400000", "0", "1fa00000"]))

    def test_uart_core(self):
        header = TREE / ".cache/xnu-work/pexpert/arm/gunyah_uart.h"
        source = '''#include <stdint.h>
#include <assert.h>
#include "gunyah_uart.h"
int main(void) {
 uint8_t p[8] = {0, 0xff, 0xaa, 0x83, 0, 0, 0, 0};
 assert(gunyah_16550_valid_reg(0x3f8,8));
 assert(!gunyah_16550_valid_reg(0,8));
 assert(!gunyah_16550_valid_reg(0x3f8,32));
 assert(!gunyah_16550_valid_reg(0x100000000ULL,8));
 assert(!gunyah_16550_valid_reg(4095,8));
 gunyah_16550_init(p); assert(p[1]==0 && p[3]==3 && p[2]==0xaa);
 assert(!gunyah_16550_tx_ready(p)); assert(!gunyah_16550_rx_ready(p));
 p[5]=0x21; assert(gunyah_16550_tx_ready(p) && gunyah_16550_rx_ready(p));
 gunyah_16550_tx(p,0x5a); assert(gunyah_16550_rx(p)==0x5a);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            c = Path(directory) / "uart.c"
            c.write_text(source)
            output = Path(directory) / "uart"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                            "-I", str(header.parent), str(c), "-o", str(output)], check=True)
            subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fdt", required=True, type=Path)
    parser.add_argument("--tree", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    INPUT_FDT, TREE = args.fdt, args.tree
    unittest.main(argv=[__file__, *remaining])
