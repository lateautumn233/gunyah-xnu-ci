// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

// Guest MMIO must be a single non-writeback load/store so the hypervisor can
// emulate the fault (ISV=1). Newer compilers merge or post-index volatile
// accesses, which Gunyah cannot decode, so these are explicit.
static inline uint8_t gunyahMmioRead8(uintptr_t p) { uint32_t v; __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); return uint8_t(v); }
static inline uint16_t gunyahMmioRead16(uintptr_t p) { uint32_t v; __asm__ volatile("ldrh %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); return uint16_t(v); }
static inline uint32_t gunyahMmioRead32(uintptr_t p) { uint32_t v; __asm__ volatile("ldr %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); return v; }
static inline void gunyahMmioWrite8(uintptr_t p, uint8_t v) { __asm__ volatile("strb %w0, [%1]" :: "r"(uint32_t(v)), "r"(p) : "memory"); }
static inline void gunyahMmioWrite16(uintptr_t p, uint16_t v) { __asm__ volatile("strh %w0, [%1]" :: "r"(uint32_t(v)), "r"(p) : "memory"); }
static inline void gunyahMmioWrite32(uintptr_t p, uint32_t v) { __asm__ volatile("str %w0, [%1]" :: "r"(v), "r"(p) : "memory"); }

// Bounded, read-only discovery of firmware-assigned modern virtio PCI BARs.
// This does not size BARs, negotiate features, reset the device or enable DMA.
namespace GunyahPci {
struct Window { uint64_t flags, bus, physical, size; };
struct Capability { uint64_t physical; uint32_t offset, length; uint8_t bar; };
struct Block {
  Capability caps[5]; // types 1..4: common, notify, ISR, device config
  uint32_t notifyMultiplier;
};
enum Result { NotBlock, Valid, BadHeader, BadChain, BadCapability, BadBar, BadWindow, MissingCapability };
inline uint16_t u16(const uint8_t *p) { return uint16_t(p[0] | uint16_t(p[1]) << 8); }
inline uint32_t u32(const uint8_t *p) { return u16(p) | uint32_t(u16(p + 2)) << 16; }

// Decode sizing readback only after the caller has disabled address decoding
// and bus mastering and restored both halves of the original BAR.
inline bool barAperture(uint32_t low, uint32_t high, uint32_t maskLow, uint32_t maskHigh,
                        uint64_t &base, uint64_t &size)
{
  unsigned type = (low >> 1) & 3;
  if ((low & 1) || (type != 0 && type != 2) || (maskLow & 15) != (low & 15)) return false;
  base = low & ~uint64_t(15);
  uint64_t mask = maskLow & ~uint64_t(15);
  if (type == 2) { base |= uint64_t(high) << 32; mask |= uint64_t(maskHigh) << 32; }
  else mask |= 0xffffffff00000000ULL;
  size = ~mask + 1;
  return base && size >= 16 && !(size & (size - 1)) && !(base & (size - 1)) && base <= UINT64_MAX - size;
}

inline bool readBounds(uint64_t capacity, uint64_t sector, uint32_t bytes)
{
  return bytes && bytes <= 65536 && !(bytes & 511) && sector < capacity && bytes / 512 <= capacity - sector;
}

inline Result discover(const uint8_t (&config)[256], const Window *windows, unsigned count, Block &out)
{
  out = {};
  if (u16(config) != 0x1af4 || (u16(config + 2) != 0x1042 && u16(config + 2) != 0x1001)) return NotBlock;
  if ((config[0x0e] & 0x7f) != 0 || !(u16(config + 6) & 0x10)) return BadHeader;
  uint64_t bars[6] = {};
  uint8_t kind[6] = {}; // 0 invalid, 2 memory32, 3 memory64 (upper half stays invalid)
  bool prefetch[6] = {};
  for (unsigned bar = 0; bar < 6; bar++) {
    uint32_t low = u32(config + 0x10 + bar * 4);
    if (!low || (low & 1)) continue;
    unsigned type = (low >> 1) & 3;
    if (type != 0 && type != 2) continue;
    bars[bar] = low & ~uint64_t(15);
    kind[bar] = type == 2 ? 3 : 2;
    prefetch[bar] = (low & 8) != 0;
    if (type == 2) {
      if (bar == 5) return BadBar;
      bars[bar] |= uint64_t(u32(config + 0x14 + bar * 4)) << 32;
      bar++;
    }
  }
  bool visited[64] = {};
  unsigned found = 0;
  for (unsigned pos = config[0x34]; pos; pos = config[pos + 1]) {
    if (pos < 0x40 || pos > 0xfc || (pos & 3) || visited[pos / 4]) return BadChain;
    visited[pos / 4] = true;
    if (config[pos] != 9) continue;
    unsigned length = config[pos + 2], type = config[pos + 3];
    if (length < 16 || length > 256 - pos) return BadCapability;
    if (type < 1 || type > 4) continue;
    if (found & (1U << type)) return BadCapability;
    if (type == 2 && length < 20) return BadCapability;
    unsigned bar = config[pos + 4];
    uint32_t offset = u32(config + pos + 8), bytes = u32(config + pos + 12);
    unsigned minimum = type == 1 ? 56 : type == 2 ? 2 : type == 3 ? 1 : 8;
    if (bytes < minimum || (type == 1 && (offset & 3)) || (type == 2 && (offset & 1)) ||
        (type == 4 && (offset & 3)) || uint64_t(offset) + bytes > (uint64_t(1) << 32)) return BadCapability;
    if (bar >= 6 || !kind[bar] || !bars[bar] || bars[bar] > UINT64_MAX - offset) return BadBar;
    uint64_t address = bars[bar] + offset;
    if (address > UINT64_MAX - bytes) return BadBar;
    unsigned matches = 0;
    uint64_t physical = 0;
    for (unsigned i = 0; i < count; i++) {
      const Window &w = windows[i];
      // Firmware may place a 64-bit BAR below 4 GiB; window space need not match BAR width.
      if (!w.size || w.bus > UINT64_MAX - w.size || w.physical > UINT64_MAX - w.size ||
          (w.flags != 0x02000000 && w.flags != 0x03000000 &&
           w.flags != 0x42000000 && w.flags != 0x43000000)) continue;
      if (prefetch[bar] != bool(w.flags & 0x40000000) || bars[bar] < w.bus ||
          address < w.bus || address - w.bus >= w.size || bytes > w.size - (address - w.bus)) continue;
      if (kind[bar] == 2 && address + bytes > (uint64_t(1) << 32)) return BadBar;
      physical = w.physical + (address - w.bus);
      matches++;
    }
    if (matches != 1) return BadWindow;
    out.caps[type] = {physical, offset, bytes, uint8_t(bar)};
    if (type == 2) out.notifyMultiplier = u32(config + pos + 16);
    found |= 1U << type;
  }
  return found == 0x1e ? Valid : MissingCapability;
}
} // namespace GunyahPci
