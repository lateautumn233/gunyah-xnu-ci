// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host-side protocol tests; never touch a physical PCI device.
#include <cassert>
#include <cstring>
#include <cstdio>
#include "GunyahPci.h"
using namespace GunyahPci;
static uint8_t cfg[256];
static void w32(unsigned off, uint32_t v) {
  for (unsigned n = 0; n < 4; n++) cfg[off + n] = uint8_t(v >> (n * 8));
}
static void fixture() {
  memset(cfg, 0, sizeof(cfg));
  w32(0, 0x10421af4); cfg[6] = 0x10; w32(0x10, 0x02000000); cfg[0x34] = 0x40;
  for (unsigned type = 1; type <= 4; type++) {
    unsigned p = 0x40 + (type - 1) * 24;
    cfg[p] = 9; cfg[p+1] = type == 4 ? 0 : p+24;
    cfg[p+2] = type == 2 ? 20 : 16; cfg[p+3] = type;
    w32(p+8, (type-1)*4096); w32(p+12, 4096);
    if (type == 2) w32(p+16, 4);
  }
}
int main() {
  uint64_t base, size;
  assert(barAperture(0x2018000, 0, 0xffffc000, 0, base, size) && base == 0x2018000 && size == 0x4000);
  assert(barAperture(0x0c, 1, 0xffffc00c, 0xffffffff, base, size) && base == 0x100000000 && size == 0x4000);
  assert(!barAperture(0x2018001, 0, 0xffffc001, 0, base, size)); // IO BAR
  assert(!barAperture(0x2018000, 0, 0xffffc004, 0, base, size)); // type changed
  assert(!barAperture(0x2018000, 0, 0xffffd000, 0, base, size)); // non-power-of-two mask
  assert(!barAperture(0x2018010, 0, 0xffffc000, 0, base, size)); // unaligned allocation
  assert(!barAperture(0x4, 0, 0x4, 0, base, size)); // zero/overflow aperture
  assert(readBounds(2048, 2047, 512));
  assert(readBounds(2048, 1920, 65536));
  assert(!readBounds(2048, 2048, 512));
  assert(!readBounds(2048, 2047, 1024));
  assert(!readBounds(2048, UINT64_MAX, 512));
  assert(!readBounds(2048, 0, 0));
  assert(!readBounds(2048, 0, 513));
  assert(!readBounds(2048, 0, 66048));
  Window windows[] = {{0x02000000, 0x02000000, 0x12000000, 0x2000000},
                      {0x43000000, 0x100000000, 0x200000000, 0x10000000}};
  Block out;
  fixture(); assert(discover(cfg, windows, 2, out) == Valid);
  assert(out.caps[1].physical == 0x12000000 && out.caps[4].physical == 0x12003000);
  assert(out.notifyMultiplier == 4);
  // 64-bit BAR above 4 GiB, translated host physical window.
  w32(0x10, 0x0c); w32(0x14, 1);
  assert(discover(cfg, windows, 2, out) == Valid && out.caps[1].physical == 0x200000000);
  cfg[0x44] = 1; assert(discover(cfg, windows, 2, out) == BadBar); // high half is not a BAR
  fixture(); w32(0x10, 0x02000004); // non-prefetchable 64-bit BAR in 32-bit window
  assert(discover(cfg, windows, 2, out) == Valid);
  fixture(); cfg[0x41] = 0x40; assert(discover(cfg, windows, 2, out) == BadChain);
  fixture(); cfg[0x41] = 0x41; assert(discover(cfg, windows, 2, out) == BadChain);
  fixture(); cfg[0x41] = 0xff; assert(discover(cfg, windows, 2, out) == BadChain);
  fixture(); cfg[0x42] = 255; assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); cfg[0x5b] = 1; assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); cfg[0x5a] = 16; assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); cfg[0x44] = 6; assert(discover(cfg, windows, 2, out) == BadBar);
  fixture(); w32(0x10, 0x02000001); assert(discover(cfg, windows, 2, out) == BadBar);
  fixture(); w32(0x10, 0); assert(discover(cfg, windows, 2, out) == BadBar);
  fixture(); w32(0x48, 0xfffffff0); assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); w32(0x4c, 55); assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); w32(0x48, 1); assert(discover(cfg, windows, 2, out) == BadCapability);
  fixture(); w32(0x48, 0x1fffffc); assert(discover(cfg, windows, 2, out) == BadWindow);
  fixture(); w32(0x10, 0x02000008); assert(discover(cfg, windows, 2, out) == BadWindow);
  fixture(); windows[1] = windows[0]; assert(discover(cfg, windows, 2, out) == BadWindow);
  fixture(); cfg[0x41] = 0; assert(discover(cfg, windows, 1, out) == MissingCapability);
  fixture(); cfg[6] = 0; assert(discover(cfg, windows, 1, out) == BadHeader);
  fixture(); cfg[0x0e] = 1; assert(discover(cfg, windows, 1, out) == BadHeader);
  fixture(); w32(0, 0x10011af4); assert(discover(cfg, windows, 1, out) == Valid);
  fixture(); w32(0, 0x10411af4); assert(discover(cfg, windows, 1, out) == NotBlock);
  puts("PCI parser: valid translations and malformed BAR/capability inputs PASS");
}
