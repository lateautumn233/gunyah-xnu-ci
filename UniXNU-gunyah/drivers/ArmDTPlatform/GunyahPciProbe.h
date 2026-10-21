// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOMemoryDescriptor.h>
#include "GunyahPci.h"
#include "GunyahVirtioPci.h"
#include "GunyahBlockBsd.h"

// Opt-in platform diagnostic. Read PCI configuration only; the firmware's
// queue state is left intact until a separate transport takes ownership.
static void gunyahPciProbe(IOService *provider)
{
  unsigned enabled = 0;
  PE_parse_boot_argn("gunyah-pci-selftest", &enabled, sizeof(enabled));
  if (enabled != 1) return;
  unsigned blockTest = 0, blockDevice = UINT32_MAX, publish = 0;
  PE_parse_boot_argn("gunyah-block-selftest", &blockTest, sizeof(blockTest));
  PE_parse_boot_argn("gunyah-block-device", &blockDevice, sizeof(blockDevice));
  PE_parse_boot_argn("gunyah-block-publish", &publish, sizeof(publish));
  // Diagnostic topology reserves device 1 for the EFI ESP. Never take it over.
  if (blockTest == 1 && (blockDevice < 2 || blockDevice > 31)) {
    IOLog("GUNYAH-BLOCK: failure=invalid-test-device\n"); blockTest = 0;
  }
  bool blockTestFound = false;
  IORegistryEntry *entry = provider->childFromPath("arm-io/gunyah-pci", gIODTPlane);
  OSData *reg = entry ? OSDynamicCast(OSData, entry->getProperty("reg")) : nullptr;
  OSData *ranges = entry ? OSDynamicCast(OSData, entry->getProperty("gunyah,pci-windows-v1")) : nullptr;
  OSData *buses = entry ? OSDynamicCast(OSData, entry->getProperty("bus-range")) : nullptr;
  IORegistryEntry *bus = provider->childFromPath("arm-io", gIODTPlane);
  OSData *busRange = bus ? OSDynamicCast(OSData, bus->getProperty("ranges")) : nullptr;
  uint64_t r[2] = {}, parent[3] = {};
  uint32_t busNumbers[2] = {};
  GunyahPci::Window windows[8] = {};
  unsigned windowCount = ranges ? ranges->getLength() / sizeof(windows[0]) : 0;
  bool valid = reg && reg->getLength() == sizeof(r) && busRange && busRange->getLength() == sizeof(parent)
    && ranges && windowCount && windowCount <= 8 && ranges->getLength() == windowCount * sizeof(windows[0])
    && buses && buses->getLength() == sizeof(busNumbers) && entry->getProperty("dma-coherent");
  if (valid) {
    memcpy(r, reg->getBytesNoCopy(), sizeof(r));
    memcpy(parent, busRange->getBytesNoCopy(), sizeof(parent));
    memcpy(busNumbers, buses->getBytesNoCopy(), sizeof(busNumbers));
    memcpy(windows, ranges->getBytesNoCopy(), ranges->getLength());
  }
  if (entry) entry->release();
  if (bus) bus->release();
  valid = valid && busNumbers[0] == 0 && busNumbers[1] == 0 && r[1] == 0x100000
    && r[0] >= parent[0] && r[0] - parent[0] <= parent[2] && r[1] <= parent[2] - (r[0] - parent[0])
    && parent[1] <= UINT64_MAX - (r[0] - parent[0]);
  if (!valid) { IOLog("GUNYAH-PCI: result=FAIL reason=ADT\n"); return; }
  uint64_t physical = parent[1] + r[0] - parent[0];
  if (!physical || physical > UINT64_MAX - r[1]) { IOLog("GUNYAH-PCI: result=FAIL reason=ECAM\n"); return; }
  IOMemoryDescriptor *memory = IOMemoryDescriptor::withPhysicalAddress(physical, r[1], kIODirectionInOut);
  IOMemoryMap *mapping = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
  if (memory) memory->release();
  if (!mapping) { IOLog("GUNYAH-PCI: result=FAIL reason=map\n"); return; }
  IOLog("GUNYAH-PCI: start ecam=0x%llx bytes=0x%llx windows=%u\n", physical, r[1], windowCount);
  for (unsigned i = 0; i < windowCount; i++) {
    IOLog("GUNYAH-PCI: window=%u flags=0x%llx bus=0x%llx physical=0x%llx bytes=0x%llx\n",
          i, windows[i].flags, windows[i].bus, windows[i].physical, windows[i].size);
  }
  unsigned devices = 0, blocks = 0, failures = 0;
  for (unsigned device = 0; device < 32; device++) {
    unsigned functions = 1;
    for (unsigned function = 0; function < functions; function++) {
      auto *cfg = reinterpret_cast<volatile uint32_t *>(mapping->getVirtualAddress() + (device << 15) + (function << 12));
      uint32_t id = cfg[0];
      if ((id & 0xffff) == 0xffff || (id & 0xffff) == 0) continue;
      uint8_t config[256];
      for (unsigned word = 0; word < 64; word++) {
        uint32_t value = cfg[word];
        memcpy(config + word * 4, &value, 4);
      }
      __asm__ volatile("dmb osh" ::: "memory");
      if (function == 0 && (config[0x0e] & 0x80)) functions = 8;
      devices++;
      IOLog("GUNYAH-PCI: device=00:%02x.%u vendor=0x%04x product=0x%04x command=0x%04x\n",
            device, function, id & 0xffff, id >> 16, GunyahPci::u16(config + 4));
      GunyahPci::Block block;
      GunyahPci::Result result = GunyahPci::discover(config, windows, windowCount, block);
      if (result == GunyahPci::NotBlock) continue;
      if (result != GunyahPci::Valid) {
        failures++;
        IOLog("GUNYAH-PCI: block=00:%02x.%u refused=%u\n", device, function, unsigned(result));
        continue;
      }
      blocks++;
      for (unsigned type = 1; type <= 4; type++) {
        const GunyahPci::Capability &cap = block.caps[type];
        IOLog("GUNYAH-PCI: block=00:%02x.%u type=%u bar=%u offset=0x%x bytes=0x%x physical=0x%llx\n",
              device, function, type, cap.bar, cap.offset, cap.length, cap.physical);
      }
      IOLog("GUNYAH-PCI: block=00:%02x.%u notify_multiplier=%u\n", device, function, block.notifyMultiplier);
      if (blockTest == 1 && device == blockDevice && function == 0) {
        blockTestFound = true;
        if (GunyahBlockBsd::transport) continue; // Never take over a live backend twice.
        if (publish == 1) {
          auto *transport = new GunyahVirtioPci(reinterpret_cast<uintptr_t>(cfg), block);
          if (!transport) IOLog("GUNYAH-BLOCK: failure=allocate-transport\n");
          else if (transport->run(config, windows, windowCount, device, mapping))
            GunyahBlockBsd::transport = transport;
          else delete transport;
        } else {
          GunyahVirtioPci transport(reinterpret_cast<uintptr_t>(cfg), block);
          transport.run(config, windows, windowCount, device);
        }
      }
    }
  }
  mapping->release();
  if (blockTest == 1 && !blockTestFound) IOLog("GUNYAH-BLOCK: failure=test-device-not-found\n");
  IOLog("GUNYAH-PCI: result=%s devices=%u blocks=%u failures=%u\n",
        blocks && !failures ? "PASS" : "FAIL", devices, blocks, failures);
  if (publish == 1) IOService::publishResource("GunyahBlockProbeComplete");
}
