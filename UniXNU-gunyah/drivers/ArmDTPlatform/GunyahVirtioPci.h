// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLocks.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <libkern/crypto/sha2.h>
#include "GunyahPci.h"

// Opt-in synchronous read-only transport. A published instance owns its ECAM,
// capability mappings and ordinary shared-RAM buffers for the VM's lifetime.
class GunyahVirtioPci {
  struct Descriptor { uint64_t address; uint32_t length; uint16_t flags, next; };
  struct Request { uint32_t operation, reserved; uint64_t sector; };
  struct Used { uint32_t id, length; };
  static_assert(sizeof(Descriptor) == 16 && sizeof(Request) == 16 && sizeof(Used) == 8, "split queue ABI");
  static constexpr unsigned queueSize = 8, transferSize = 65536;
  uintptr_t config;
  const GunyahPci::Block block;
  IOMemoryMap *ecam = nullptr;
  IOLock *lock = nullptr;
  IOMemoryMap *maps[5] = {};
  uintptr_t common = 0, notify = 0, deviceConfig = 0;
  IOBufferMemoryDescriptor *queue = nullptr, *transfer = nullptr;
  bool queuePrepared = false, transferPrepared = false, claimed = false, online = false;
  uint16_t savedCommand = 0, availableIndex = 0, usedIndex = 0;
  uint64_t queuePhysical = 0, transferPhysical = 0, capacity = 0;
  unsigned completed = 0;
  static void barrier() { __asm__ volatile("dmb osh" ::: "memory"); }
  static uint8_t r8(uintptr_t p) { return *reinterpret_cast<volatile uint8_t *>(p); }
  static uint16_t r16(uintptr_t p) { return *reinterpret_cast<volatile uint16_t *>(p); }
  static uint32_t r32(uintptr_t p) { return *reinterpret_cast<volatile uint32_t *>(p); }
  static void w8(uintptr_t p, uint8_t v) { *reinterpret_cast<volatile uint8_t *>(p) = v; barrier(); }
  static void w16(uintptr_t p, uint16_t v) { *reinterpret_cast<volatile uint16_t *>(p) = v; barrier(); }
  static void w32(uintptr_t p, uint32_t v) { *reinterpret_cast<volatile uint32_t *>(p) = v; barrier(); }
  static void address(uintptr_t p, uint64_t v) { w32(p, uint32_t(v)); w32(p + 4, uint32_t(v >> 32)); }
  bool fail(const char *reason) { IOLog("GUNYAH-BLOCK: failure=%s\n", reason); return false; }

  bool sizeBars(const uint8_t (&snapshot)[256], const GunyahPci::Window *windows, unsigned count)
  {
    savedCommand = r16(config + 4);
    claimed = true;
    // 16-bit access: do not echo the adjacent W1C PCI status bits.
    w16(config + 4, savedCommand & ~7U);
    if (r16(config + 4) & 7) return fail("disable-decode");
    bool seen[6] = {};
    for (unsigned t = 1; t <= 4; t++) {
      unsigned bar = block.caps[t].bar;
      if (seen[bar]) continue;
      seen[bar] = true;
      uintptr_t at = config + 0x10 + bar * 4;
      uint32_t low = GunyahPci::u32(snapshot + 0x10 + bar * 4);
      bool wide = (low & 6) == 4;
      uint32_t high = wide ? GunyahPci::u32(snapshot + 0x14 + bar * 4) : 0;
      if (r32(at) != low || (wide && r32(at + 4) != high)) return fail("bar-changed");
      w32(at, UINT32_MAX);
      if (wide) w32(at + 4, UINT32_MAX);
      uint32_t maskLow = r32(at), maskHigh = wide ? r32(at + 4) : 0;
      if (wide) w32(at + 4, high);
      w32(at, low);
      if (r32(at) != low || (wide && r32(at + 4) != high)) return fail("bar-restore");
      uint64_t base = 0, bytes = 0;
      if (!GunyahPci::barAperture(low, high, maskLow, maskHigh, base, bytes)) return fail("bar-mask");
      unsigned matches = 0;
      for (unsigned w = 0; w < count; w++) {
        const GunyahPci::Window &window = windows[w];
        if (bool(low & 8) == bool(window.flags & 0x40000000) && base >= window.bus &&
            base - window.bus < window.size && bytes <= window.size - (base - window.bus)) matches++;
      }
      if (matches != 1) return fail("bar-window");
      for (unsigned c = 1; c <= 4; c++) {
        const GunyahPci::Capability &cap = block.caps[c];
        if (cap.bar == bar && (cap.offset >= bytes || cap.length > bytes - cap.offset)) return fail("cap-aperture");
      }
      IOLog("GUNYAH-BLOCK: bar=%u bus=0x%llx bytes=0x%llx restored=1\n", bar, base, bytes);
    }
    // Enable memory decoding, suppress INTx, keep bus mastering off until DMA is ready.
    w16(config + 4, (savedCommand & ~7U) | 0x402);
    if ((r16(config + 4) & 0x407) != 0x402) return fail("memory-decode");
    return true;
  }

  bool mapCaps()
  {
    for (unsigned t = 1; t <= 4; t++) {
      const GunyahPci::Capability &cap = block.caps[t];
      // Bound virtual mapping even if the backend advertises a larger aperture.
      uint64_t length = t == 1 ? 56 : t == 2 ? cap.length : t == 3 ? 1 : 8;
      if (length > 1024 * 1024) return fail("notify-window-too-large");
      IOMemoryDescriptor *memory = IOMemoryDescriptor::withPhysicalAddress(cap.physical, length, kIODirectionInOut);
      maps[t] = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
      if (memory) memory->release();
      if (!maps[t]) return fail("map-capability");
      if (t == 1) common = maps[t]->getVirtualAddress();
    }
    deviceConfig = maps[4]->getVirtualAddress();
    return true;
  }

  bool reset()
  {
    online = false;
    if (!common) return true;
    w8(common + 0x14, 0);
    uint64_t deadline;
    clock_interval_to_deadline(1000, kMillisecondScale, &deadline);
    while (r8(common + 0x14)) {
      if (mach_absolute_time() >= deadline) return false;
      IODelay(1);
    }
    barrier();
    return true;
  }

  bool configure()
  {
    if (!reset()) return fail("reset-timeout");
    w8(common + 0x14, 1);
    w8(common + 0x14, 3);
    w32(common, 0); uint32_t low = r32(common + 4);
    w32(common, 1); uint32_t high = r32(common + 4);
    IOLog("GUNYAH-BLOCK: features_low=0x%x features_high=0x%x\n", low, high);
    if (!(low & (1U << 5)) || !(high & 1)) return fail("requires-ro-version1");
    w32(common + 8, 0); w32(common + 12, 1U << 5);
    w32(common + 8, 1); w32(common + 12, 1);
    w8(common + 0x14, 11);
    if (r8(common + 0x14) != 11 || !r16(common + 0x12)) return fail("feature-negotiation");
    w16(common + 0x10, 0xffff); // no MSI-X config vector
    w16(common + 0x16, 0); // queue zero
    if (r16(common + 0x1c) || r16(common + 0x18) < queueSize) return fail("queue-unavailable");
    uint64_t notifyOffset = uint64_t(r16(common + 0x1e)) * block.notifyMultiplier;
    if ((notifyOffset & 1) || notifyOffset > block.caps[2].length - 2) return fail("notify-bounds");
    notify = maps[2]->getVirtualAddress() + notifyOffset;
    bool stable = false;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
      uint8_t generation = r8(common + 0x15);
      uint32_t capacityLow = r32(deviceConfig), capacityHigh = r32(deviceConfig + 4);
      barrier();
      if (generation == r8(common + 0x15)) { capacity = capacityLow | uint64_t(capacityHigh) << 32; stable = true; break; }
    }
    if (!stable || capacity < 256 || capacity > UINT64_MAX / 512) return fail("capacity");
    queue = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
      kIODirectionInOut | kIOMemoryPhysicallyContiguous, 4096, 4096);
    transfer = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
      kIODirectionInOut | kIOMemoryPhysicallyContiguous, transferSize, 4096);
    if (!queue || !transfer) return fail("allocate");
    queuePrepared = queue->prepare() == kIOReturnSuccess;
    transferPrepared = transfer->prepare() == kIOReturnSuccess;
    if (!queuePrepared || !transferPrepared) return fail("prepare");
    IOByteCount queueLength = 0, transferLength = 0;
    queuePhysical = queue->getPhysicalSegment(0, &queueLength);
    transferPhysical = transfer->getPhysicalSegment(0, &transferLength);
    if (!queuePhysical || !transferPhysical || queueLength < 4096 || transferLength < transferSize ||
        (queuePhysical & 4095) || (transferPhysical & 4095)) return fail("dma-contiguity");
    bzero(queue->getBytesNoCopy(), 4096);
    auto *available = reinterpret_cast<volatile uint16_t *>(static_cast<uint8_t *>(queue->getBytesNoCopy()) + 128);
    available[0] = 1; // VIRTQ_AVAIL_F_NO_INTERRUPT
    barrier();
    w16(common + 0x18, queueSize);
    w16(common + 0x1a, 0xffff);
    if (r16(common + 0x18) != queueSize || r16(common + 0x1a) != 0xffff || r16(common + 0x10) != 0xffff) return fail("queue-config");
    address(common + 0x20, queuePhysical);
    address(common + 0x28, queuePhysical + 128);
    address(common + 0x30, queuePhysical + 256);
    w16(common + 0x1c, 1);
    if (r16(common + 0x1c) != 1) return fail("queue-enable");
    w16(config + 4, (savedCommand & ~7U) | 0x406);
    if ((r16(config + 4) & 0x407) != 0x406) return fail("bus-master");
    w8(common + 0x14, 15);
    online = r8(common + 0x14) == 15;
    IOLog("GUNYAH-BLOCK: ready=%u sectors=%llu queue_size=%u queue_gpa=0x%llx data_gpa=0x%llx\n",
          unsigned(online), capacity, queueSize, queuePhysical, transferPhysical);
    return online;
  }

  IOReturn read(uint64_t sector, uint32_t bytes)
  {
    if (!GunyahPci::readBounds(capacity, sector, bytes)) return kIOReturnBadArgument;
    if (!online) return kIOReturnNotReady;
    auto *q = static_cast<uint8_t *>(queue->getBytesNoCopy());
    auto *descriptors = reinterpret_cast<Descriptor *>(q);
    *reinterpret_cast<Request *>(q + 512) = {0, 0, sector}; // VIRTIO_BLK_T_IN only
    volatile uint8_t *status = q + 528;
    *status = 0xff;
    bzero(transfer->getBytesNoCopy(), bytes);
    descriptors[0] = {queuePhysical + 512, sizeof(Request), 1, 1};
    descriptors[1] = {transferPhysical, bytes, 3, 2};
    descriptors[2] = {queuePhysical + 528, 1, 2, 0};
    auto *available = reinterpret_cast<volatile uint16_t *>(q + 128);
    auto *used = reinterpret_cast<volatile uint16_t *>(q + 256);
    available[2 + availableIndex % queueSize] = 0;
    barrier();
    available[1] = ++availableIndex;
    barrier();
    w16(notify, 0);
    uint64_t deadline;
    clock_interval_to_deadline(1000, kMillisecondScale, &deadline);
    while (used[1] == usedIndex) {
      if (mach_absolute_time() >= deadline) { online = false; return kIOReturnTimeout; }
      barrier();
      IODelay(1);
    }
    barrier();
    auto *element = reinterpret_cast<volatile Used *>(q + 260) + usedIndex % queueSize;
    bool valid = used[1] == uint16_t(usedIndex + 1) && element->id == 0 && element->length == bytes + 1 && *status == 0;
    if (!valid) { online = false; return kIOReturnIOError; }
    usedIndex++;
    (void)r8(maps[3]->getVirtualAddress()); // read-to-clear ISR
    completed++;
    return kIOReturnSuccess;
  }

  bool selftest()
  {
    for (unsigned sample = 0; sample < 16; sample++) {
      uint32_t bytes = sample == 0 || sample == 3 ? 512 : sample == 1 ? 8192 : sample == 2 ? 65536 : 4096;
      uint64_t sector = sample == 0 ? 0 : sample == 1 ? 7 : sample == 2 ? 113 : sample == 3 ? capacity - 1 :
                        sample == 4 ? capacity - 8 : (uint64_t(sample) * 137 + 53) % (capacity - bytes / 512 + 1);
      IOReturn result = read(sector, bytes);
      if (result != kIOReturnSuccess) { IOLog("GUNYAH-BLOCK: read-error=0x%x sample=%u\n", result, sample + 1); return false; }
      uint8_t digest[32]; char hex[65];
      SHA256_CTX hash;
      SHA256_Init(&hash); SHA256_Update(&hash, transfer->getBytesNoCopy(), bytes); SHA256_Final(digest, &hash);
      for (unsigned n = 0; n < 32; n++) { hex[2*n] = "0123456789abcdef"[digest[n] >> 4]; hex[2*n+1] = "0123456789abcdef"[digest[n] & 15]; }
      hex[64] = 0;
      IOLog("GUNYAH-BLOCK: sample=%u sector=%llu bytes=%u sha256=%s used=%u\n", sample + 1, sector, bytes, hex, usedIndex);
    }
    uint16_t before = availableIndex;
    bool bounds = read(capacity, 512) == kIOReturnBadArgument && read(capacity-1, 1024) == kIOReturnBadArgument &&
      read(UINT64_MAX, 512) == kIOReturnBadArgument && read(0, 0) == kIOReturnBadArgument &&
      read(0, 513) == kIOReturnBadArgument && read(0, transferSize+512) == kIOReturnBadArgument && availableIndex == before;
    IOLog("GUNYAH-BLOCK: bounds=%s rejected=6 submitted=%u\n", bounds ? "PASS" : "FAIL", availableIndex);
    return bounds;
  }

  void stop()
  {
    // A status-zero acknowledgement is mandatory before releasing DMA storage.
    if (!reset()) panic("GunyahVirtioPci: refusing to free active DMA buffers after reset timeout");
    if (claimed) {
      w16(config + 4, savedCommand & ~4U);
      if (r16(config + 4) & 4) panic("GunyahVirtioPci: bus mastering remained enabled");
    }
  }

public:
  GunyahVirtioPci(uintptr_t cfg, const GunyahPci::Block &caps) : config(cfg), block(caps) {}
  bool run(const uint8_t (&snapshot)[256], const GunyahPci::Window *windows, unsigned count,
           unsigned device, IOMemoryMap *retainMapping = nullptr)
  {
    IOLog("GUNYAH-BLOCK: start device=00:%02x.0 mode=read-only\n", device);
    bool passed = sizeBars(snapshot, windows, count) && mapCaps() && configure() && selftest();
    if (passed && retainMapping) {
      lock = IOLockAlloc();
      if (lock) {
        ecam = retainMapping;
        ecam->retain();
        IOLog("GUNYAH-BLOCK: result=PASS reads=%u persistent=1\n", completed);
        return true;
      }
      passed = fail("allocate-lock");
    }
    stop();
    if (queuePrepared) queue->complete();
    if (transferPrepared) transfer->complete();
    if (queue) queue->release();
    if (transfer) transfer->release();
    for (unsigned t = 1; t <= 4; t++) if (maps[t]) maps[t]->release();
    IOLog("GUNYAH-BLOCK: result=%s reads=%u reset=1 bus_master=0\n", passed ? "PASS" : "FAIL", completed);
    return passed;
  }

  uint64_t sectors() const { return capacity; } // Immutable after publication.
  bool isOnline()
  {
    IOLockLock(lock);
    bool result = online;
    IOLockUnlock(lock);
    return result;
  }

  IOReturn readBytes(uint64_t offset, uint32_t bytes, void *destination, uint32_t &done)
  {
    done = 0;
    if (!destination || offset > capacity * 512 || bytes > capacity * 512 - offset)
      return kIOReturnBadArgument;
    IOLockLock(lock);
    IOReturn result = online ? kIOReturnSuccess : kIOReturnNotReady;
    while (result == kIOReturnSuccess && done < bytes) {
      uint64_t position = offset + done;
      uint32_t skip = position % 512;
      uint32_t amount = bytes - done;
      if (amount > transferSize - skip) amount = transferSize - skip;
      result = read(position / 512, (skip + amount + 511) & ~511U);
      if (result != kIOReturnSuccess) {
        // Do not leave a timed-out request able to DMA, or retry uncertain I/O.
        stop();
        IOLog("GUNYAH-BLOCK: offline error=0x%x reset=1 bus_master=0\n", result);
        break;
      }
      memcpy(static_cast<uint8_t *>(destination) + done,
             static_cast<uint8_t *>(transfer->getBytesNoCopy()) + skip, amount);
      done += amount;
    }
    IOLockUnlock(lock);
    return result;
  }
};
