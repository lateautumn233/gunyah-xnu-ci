#!/usr/bin/env python3
"""Convert a final, shim-patched Gunyah FDT into a single-core XNU bring-up ADT."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib


def u32(value):
    return struct.pack("<I", value)


def qwords(*values):
    return struct.pack("<" + "Q" * len(values), *values)


def node(name, props=(), children=()):
    properties = [("name", name.encode() + b"\0"), *props]
    if len({key for key, _ in properties}) != len(properties):
        raise ValueError("Duplicate ADT property")
    data = struct.pack("<II", len(properties), len(children))
    for key, value in properties:
        if len(key.encode()) >= 32:
            raise ValueError("ADT property name too long")
        data += struct.pack("<32sI", key.encode(), len(value)) + value + bytes(-len(value) % 4)
    return data + b"".join(children)


def nvram():
    # Same empty volatile CHRP layout used by UniXNU's make-dt.py and IODTNVRAM.
    def header(name, size):
        data = bytearray(struct.pack("<BBH12s", 0x70, 0, size // 16, name))
        checksum = sum(data)
        while checksum > 255:
            checksum = (checksum & 255) + (checksum >> 8)
        data[1] = checksum
        return data
    image = bytearray(8192)
    image[:16] = header(b"nvram", 32)
    image[32:48] = header(b"common", 2064)
    image[2096:2112] = header(b"free", len(image) - 2096)
    struct.pack_into("<I", image, 16, zlib.adler32(image[20:]))
    return [("nvram-bank-size", u32(len(image))), ("nvram-bank-count", u32(1)),
            ("nvram-current-bank", u32(0)), ("nvram-proxy-data", bytes(image))]


class Fdt:
    def __init__(self, path):
        self.path = str(path)

    def query(self, *args):
        result = subprocess.run(["fdtget", *args[:2], self.path, *args[2:]],
                                capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"FDT query failed {args}: {result.stderr.strip()}")
        return result.stdout.strip()

    def words(self, path, key):
        return [int(x, 16) for x in self.query("-t", "x", path, key).split()]

    def string(self, path, key):
        return self.query("-t", "s", path, key)

    def children(self, path):
        result = subprocess.run(["fdtget", "-l", self.path, path], capture_output=True, text=True, check=True)
        return result.stdout.split()

    def properties(self, path):
        result = subprocess.run(["fdtget", "-p", self.path, path], capture_output=True, text=True, check=True)
        return result.stdout.split()

    def regs(self, path):
        parent = path.rsplit("/", 1)[0] or "/"
        if self.words(parent, "#address-cells") != [2] or self.words(parent, "#size-cells") != [2]:
            raise ValueError(f"Unsupported reg cells: {path}")
        words = self.words(path, "reg")
        if len(words) % 4:
            raise ValueError(f"Truncated reg: {path}")
        regions = []
        for i in range(0, len(words), 4):
            base = words[i] << 32 | words[i + 1]
            size = words[i + 2] << 32 | words[i + 3]
            if base == size == 0:
                continue  # RM leaves a zero pair at the end of the main RAM reg.
            if not size or base + size > 1 << 64:
                raise ValueError(f"Invalid region: {path}")
            regions.append((base, size))
        return regions


def collect(path, frequency):
    fdt = Fdt(path)
    if not 0 < frequency < 1 << 32:
        raise ValueError("Counter frequency must be the measured guest CNTFRQ_EL0")
    if "gunyah-hypervisor" not in fdt.string("/hypervisor", "compatible").split():
        raise ValueError("Expected final Gunyah FDT, not the pre-shim crosvm dump")
    if fdt.string("/psci", "method") != "hvc":
        raise ValueError("Only the verified HVC conduit is supported")
    cpus = [name for name in fdt.children("/cpus") if name.startswith("cpu@")]
    if len(cpus) != 1 or fdt.words("/cpus", "#address-cells") != [1]:
        raise ValueError("Only the single-vCPU baseline is supported")
    affinity = fdt.words("/cpus/" + cpus[0], "reg")
    if len(affinity) != 1 or affinity[0] != 0:
        raise ValueError("Expected boot CPU affinity zero")
    uart_path = fdt.string("/chosen", "stdout-path")
    if not uart_path.startswith("/") or ":" in uart_path or fdt.string(uart_path, "compatible") != "ns16550a":
        raise ValueError("Expected direct ns16550a stdout path")
    uart, = fdt.regs(uart_path)
    for key, expected in (("reg-shift", 0), ("reg-io-width", 1)):
        if key in fdt.properties(uart_path) and fdt.words(uart_path, key) != [expected]:
            raise ValueError("Only byte-spaced, byte-access UART is supported")
    if not 0 < uart[0] < 1 << 32 or uart[1] != 8 or uart[0] % 4096 > 4088:
        raise ValueError("Unsupported UART region")
    if fdt.string("/intc", "compatible") != "arm,gic-v3":
        raise ValueError("GICv3 required")
    gicd, gicr = fdt.regs("/intc")
    irq = fdt.words("/timer", "interrupts")
    if len(irq) < 9 or irq[6] != 1 or not 0 <= irq[7] < 16 or irq[8] & 15 != 8:
        raise ValueError("Virtual timer must describe a level PPI")
    memory, = fdt.regs("/memory")
    reserved = []
    handoff_found = False
    for name in fdt.children("/reserved-memory"):
        path_ = "/reserved-memory/" + name
        if "compatible" in fdt.properties(path_):
            compatible = fdt.string(path_, "compatible").split()
            if "restricted-dma-pool" in compatible:
                raise ValueError("Pseudo-unprotected baseline must not have a DMA pool")
            handoff_found |= "droidvm,shim-handoff" in compatible
        reserved += fdt.regs(path_)
    if not handoff_found:
        raise ValueError("Missing shim handoff reservation")
    framebuffers = ["/" + n for n in fdt.children("/") if n.startswith("framebuffer@")]
    if len(framebuffers) != 1:
        raise ValueError("One simplefb is required")
    fbpath = framebuffers[0]
    fb, = fdt.regs(fbpath)
    if fdt.string(fbpath, "format") != "a8r8g8b8" or fb not in reserved:
        raise ValueError("Framebuffer format/reservation mismatch")
    if any(base < memory[0] + memory[1] and memory[0] < base + size for base, size in reserved):
        raise ValueError("Reserved region overlaps advertised allocatable RAM")
    if gicd[1] < 0x10000 or gicr[1] < 0x20000 or max(gicd[0]+gicd[1], gicr[0]+gicr[1]) > 0x40000000:
        raise ValueError("Unsupported GIC ranges")
    pci, = fdt.regs("/pci")
    if (fdt.string("/pci", "compatible") != "pci-host-ecam-generic"
            or fdt.words("/pci", "#address-cells") != [3]
            or fdt.words("/pci", "#size-cells") != [2]
            or "dma-coherent" not in fdt.properties("/pci")):
        raise ValueError("Expected coherent generic PCI ECAM host")
    pci_buses = fdt.words("/pci", "bus-range")
    # The initial transport handles this VM's single root bus, without bridges.
    if pci_buses != [0, 0] or pci[1] != 1 << 20 or pci[0] % 4096:
        raise ValueError("Only one complete, page-aligned PCI ECAM root bus is supported")
    words = fdt.words("/pci", "ranges")
    if not words or len(words) % 7 or len(words) > 8 * 7:
        raise ValueError("Invalid PCI ranges")
    pci_windows = []
    occupied = [memory, *reserved, pci, gicd, gicr, uart]
    for i in range(0, len(words), 7):
        flags, hi, lo, phi, plo, shi, slo = words[i:i+7]
        child, parent, size = hi << 32 | lo, phi << 32 | plo, shi << 32 | slo
        if (flags not in (0x02000000, 0x03000000, 0x42000000, 0x43000000)
                or not size or not child or not parent
                or child + size > 1 << 64 or parent + size > 1 << 64
                or ((flags >> 24) & 3 == 2 and child + size > 1 << 32)
                or any(parent < b+s and b < parent+size for b, s in occupied)
                or any(child < c+s and c < child+size for _, c, _, s in pci_windows)):
            raise ValueError("Unsupported, overlapping or overflowing PCI window")
        pci_windows.append((flags, child, parent, size))
        occupied.append((parent, size))
    # XNU treats a zero SoC base as absent. UART is below this bus and gets its own absolute node.
    bus_base = min(pci[0], gicd[0], gicr[0])
    bus_end = max(pci[0]+pci[1], gicd[0]+gicd[1], gicr[0]+gicr[1])
    if not bus_base:
        raise ValueError("XNU requires a nonzero arm-io physical base")
    return dict(ram=memory, uart=uart, gicd=gicd, gicr=gicr, framebuffer=fb,
                bus=(0, bus_base, bus_end-bus_base), timer_intid=irq[7]+16,
                cpu_affinity=affinity[0], counter_frequency=frequency, psci="hvc",
                pci_ecam=pci, pci_bus_range=pci_buses, pci_windows=pci_windows, reserved=reserved)


def generate(resources, window, identity, panic_size=0, ramdisk=False):
    r = resources
    if window < 0x10000000 or window % 0x200000 or window > r["ram"][1]:
        raise ValueError("Owned window must fit RAM, be >=256MiB and a multiple of 2MiB")
    if not 0 < identity < 1 << 64:
        raise ValueError("A nonzero persistent VM identity seed is required")
    if panic_size and (panic_size < 16384 or panic_size > 1024 * 1024 or panic_size % 4096):
        raise ValueError("Panic allocation must be 16KiB..1MiB and page aligned")
    # The EFI gate must allocate reserved pages and fill this physical pointer.
    panic_props = [("embedded-panic-log-size", u32(panic_size))] if panic_size else []
    panic_nodes = [node("pram", [("reg", qwords(0, panic_size))])] if panic_size else []
    bus_base = r["bus"][1]
    gic_regs = qwords(r["gicd"][0]-bus_base, r["gicd"][1], r["gicr"][0]-bus_base, r["gicr"][1])
    return node("device-tree", [("model", b"gunyah-source-kernel\0"),
        ("compatible", b"gunyah,virtual-machine\0"), ("#address-cells", u32(2)), ("#size-cells", u32(2))], [
        node("chosen", [("random-seed", os.urandom(64)), ("unique-chip-id", qwords(identity)),
            ("chip-id", u32(0)), ("osenvironment", b"ramdisk\0"),
            ("dram-base", qwords(r["ram"][0])), ("dram-size", qwords(r["ram"][1])),
            ("darwinboot-memory-size", qwords(window)), *panic_props, *nvram()],
            [node("memory-map", [("RAMDisk", qwords(0, 0))] if ramdisk else [])]),
        node("cpus", children=[node("cpu0", [("state", b"running\0"), ("reg", u32(r["cpu_affinity"])),
            ("device_type", b"cpu\0"), ("compatible", b"arm,armv8\0"),
            ("timebase-frequency", u32(r["counter_frequency"]))])]),
        node("psci", [("compatible", b"arm,psci-0.2\0"), ("method", b"hvc\0")]),
        node("defaults", [("vmm-present", u32(1)), ("sleep-disabled", u32(1))]),
        node("options"),
        node("product", [("product-name", b"Gunyah virtual machine\0"), ("model", b"gunyah,virtual-machine\0")]),
        node("gunyah-uart", [("compatible", b"ns16550a\0"), ("reg", qwords(*r["uart"]))]),
        node("arm-io", [("device_type", b"arm-io\0"), ("#address-cells", u32(2)),
            ("#size-cells", u32(2)), ("ranges", qwords(*r["bus"]))], [
            node("intc", [("compatible", b"arm,gic-v3\0"), ("reg", gic_regs),
                ("virtual-timer-intid", u32(r["timer_intid"]))]),
            node("gunyah-pci", [("compatible", b"gunyah,pci-ecam\0"),
                ("reg", qwords(r["pci_ecam"][0]-bus_base, r["pci_ecam"][1])),
                ("bus-range", b"".join(u32(v) for v in r["pci_bus_range"])),
                ("dma-coherent", b""),
                # Private versioned ABI, not a standard PCI ranges property.
                ("gunyah,pci-windows-v1", b"".join(qwords(*w) for w in r["pci_windows"]))])]), *panic_nodes])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fdt", type=Path, required=True)
    parser.add_argument("--counter-frequency", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--unique-chip-id", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--owned-memory-size", type=lambda x: int(x, 0), default=0x10000000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    resources = collect(args.fdt, args.counter_frequency)
    data = generate(resources, args.owned_memory_size, args.unique_chip_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    report = dict(resources=resources, owned_memory_size=args.owned_memory_size,
                  source_fdt_sha256=hashlib.sha256(args.fdt.read_bytes()).hexdigest(),
                  adt_sha256=hashlib.sha256(data).hexdigest(), xnu_boot_verified=False,
                  note="Source-kernel only; no storage, prelink, Apple product identity or framebuffer ADT node. GOP uses boot_args.")
    args.output.with_suffix(args.output.suffix + ".json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {args.output} ({len(data)} bytes); XNU runtime validation pending")


if __name__ == "__main__":
    main()
