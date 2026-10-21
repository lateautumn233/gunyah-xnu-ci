// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <miscfs/devfs/devfs.h>
#include "GunyahVirtioPci.h"
#include "GunyahDiskWindow.h"
#include "GunyahGpt.h"

// Built-in bridge: an explicit sector window, without IOMedia or GPT parsing.
// Registration runs after bsd_autoconf, when devfs and device switches exist.
namespace GunyahBlockBsd {
static GunyahVirtioPci *transport = nullptr;
static bool published = false;
static uint64_t firstSector = 0, sectorCount = 0;
static int rootMajor = -1;       // Block major of gvblk0 once published.
static bool rootSelected = false; // rd=gvblk0 resolved through gunyah_block_root_device.
// Runtime visibility for long guest runs: one line per second while reads flow.
static uint64_t statRequests = 0, statBytes = 0, statLastTick = 0, statWindowBytes = 0;

static int open(dev_t dev, int flags, int, struct proc *)
{
  if (minor(dev) || !transport || !transport->isOnline()) return ENXIO;
  return flags & FWRITE ? EROFS : 0;
}

static int close(dev_t, int, int, struct proc *) { return 0; }

static void strategy(buf_t bp)
{
  uint32_t count = buf_count(bp), done = 0;
  int error = 0;
  buf_setresid(bp, count);
  if (minor(buf_device(bp)) || !transport) error = ENXIO;
  else if (!(buf_flags(bp) & B_READ)) error = EROFS;
  else if (buf_flags(bp) & B_PHYS) error = ENOTSUP;
  else if (buf_blkno(bp) < 0 || uint64_t(buf_blkno(bp)) > sectorCount) error = EINVAL;
  else if (count) {
    uint64_t offset = uint64_t(buf_blkno(bp)) * 512;
    uint64_t remaining = sectorCount * 512 - offset;
    uint32_t wanted = remaining < count ? uint32_t(remaining) : count;
    caddr_t address = nullptr;
    if (wanted) {
      error = buf_map(bp, &address);
      if (!error) {
        IOReturn result = transport->readBytes(firstSector * 512 + offset, wanted, address, done);
        error = result == kIOReturnSuccess ? 0 : result == kIOReturnNotReady ? ENXIO : EIO;
        buf_unmap(bp);
      }
    }
    buf_setresid(bp, count - done);
    statRequests++; statBytes += done; statWindowBytes += done;
    uint64_t now = mach_absolute_time();
    if (now - statLastTick >= 19200000) {  // 1 s at the 19.2 MHz counter
      IOLog("GUNYAH-BLOCK-STAT: requests=%llu bytes=%llu last_1s_bytes=%llu last_sector=%lld\n",
            statRequests, statBytes, statWindowBytes, (long long)buf_blkno(bp));
      statLastTick = now; statWindowBytes = 0;
    }
  }
  if (error) buf_seterror(bp, error);
  buf_biodone(bp);
}

static int ioctl(dev_t dev, u_long cmd, caddr_t data, int, struct proc *)
{
  if (minor(dev) || !transport || !transport->isOnline()) return ENXIO;
  switch (cmd) {
    case DKIOCGETBLOCKSIZE:
    case DKIOCGETPHYSICALBLOCKSIZE: *reinterpret_cast<uint32_t *>(data) = 512; return 0;
    // Keep one immutable sector size shared by block/raw clients.
    case DKIOCSETBLOCKSIZE: return *reinterpret_cast<uint32_t *>(data) == 512 ? 0 : EINVAL;
    case DKIOCGETBLOCKCOUNT: *reinterpret_cast<uint64_t *>(data) = sectorCount; return 0;
    case DKIOCISWRITABLE: *reinterpret_cast<uint32_t *>(data) = 0; return 0;
    case DKIOCGETMAXBLOCKCOUNTREAD: *reinterpret_cast<uint64_t *>(data) = 128; return 0;
    case DKIOCGETMAXBLOCKCOUNTWRITE: *reinterpret_cast<uint64_t *>(data) = 0; return 0;
    case DKIOCGETMAXSEGMENTCOUNTREAD: *reinterpret_cast<uint64_t *>(data) = 1; return 0;
    default: return ENOTTY;
  }
}

static int size(dev_t dev)
{
  if (minor(dev) || !transport) return -1;
  // XNU specfs uses d_psize as the logical block SIZE, not disk capacity.
  // Returning a sector count here silently changes buffered-read offsets.
  return 512;
}

static int read(dev_t dev, struct uio *uio, int)
{
  // Raw disk ABI requires whole sectors. Copy via uiomove so PAN remains
  // enabled: buf_map on physio's B_PHYS buffers returns the user address.
  if (minor(dev) || !transport || !transport->isOnline()) return ENXIO;
  if (uio_offset(uio) < 0 || (uio_offset(uio) & 511) || (uio_resid(uio) & 511)) return EINVAL;
  for (int i = 0; i < uio_iovcnt(uio); i++) {
    user_addr_t base;
    user_size_t length;
    if (uio_getiov(uio, i, &base, &length) || (length & 511)) return EINVAL;
  }
  uint64_t diskBytes = sectorCount * 512;
  if (uint64_t(uio_offset(uio)) > diskBytes) return EINVAL;
  if (!uio_resid(uio) || uint64_t(uio_offset(uio)) == diskBytes) return 0;
  auto *scratch = static_cast<char *>(IOMallocData(65536));
  if (!scratch) return ENOMEM;
  int error = 0;
  while (uio_resid(uio) > 0 && uint64_t(uio_offset(uio)) < diskBytes) {
    uint64_t available = diskBytes - uint64_t(uio_offset(uio));
    if (available > uint64_t(uio_resid(uio))) available = uio_resid(uio);
    uint32_t wanted = available > 65536 ? 65536 : uint32_t(available), done = 0;
    IOReturn result = transport->readBytes(firstSector * 512 + uint64_t(uio_offset(uio)), wanted, scratch, done);
    if (done) error = uiomove(scratch, done, uio);
    if (!error && result != kIOReturnSuccess) error = result == kIOReturnNotReady ? ENXIO : EIO;
    if (error) break;
  }
  IOFreeData(scratch, 65536);
  return error;
}

static int write(dev_t, struct uio *, int) { return EROFS; }

static const struct bdevsw blockSwitch = {open, close, strategy, ioctl, eno_dump, size, D_DISK};
static const struct cdevsw rawSwitch = {open, close, read, write, ioctl, eno_stop, eno_reset,
  nullptr, eno_select, eno_mmap, eno_strat, eno_getc, eno_putc, D_DISK};
}

#if GUNYAH_BUILTIN_HFS
extern "C" void gunyah_hfs_register(void);
#endif
extern "C" void gunyah_block_publish(void);
extern "C" void gunyah_block_publish(void)
{
  using namespace GunyahBlockBsd;
#if GUNYAH_BUILTIN_HFS
  unsigned hfs = 0;
  PE_parse_boot_argn("gunyah-hfs", &hfs, sizeof(hfs));
  if (hfs == 1) gunyah_hfs_register();
#endif
  unsigned enabled = 0;
  PE_parse_boot_argn("gunyah-block-publish", &enabled, sizeof(enabled));
  if (enabled != 1 || published) return;
  // Platform configure is asynchronous and can finish AFTER bsd_autoconf.
  // Wait for explicit completion, with a bounded failure path for md0 boots.
  OSDictionary *matching = IOService::resourceMatching("GunyahBlockProbeComplete");
  IOService *service = matching ? IOService::waitForMatchingService(matching, 5ULL * kSecondScale) : nullptr;
  if (matching) matching->release();
  if (!service) { IOLog("GUNYAH-BSD: failure=transport-timeout\n"); return; }
  service->release();
  if (published || !transport || !transport->isOnline()) return;
  sectorCount = transport->sectors();
  // Boot args are strings so malformed/overflowing numbers cannot silently
  // become valid offsets. A 64-byte buffer exceeds any valid uint64 decimal.
  char startText[64] = {}, countText[64] = {};
  bool hasStart = PE_parse_boot_arg_str("gunyah-root-start", startText, sizeof(startText));
  bool hasCount = PE_parse_boot_arg_str("gunyah-root-sectors", countText, sizeof(countText));
  if (hasStart != hasCount || (hasStart &&
      (!GunyahDiskWindow::decimal(startText, firstSector) ||
       !GunyahDiskWindow::decimal(countText, sectorCount))) ||
      !GunyahDiskWindow::valid(transport->sectors(), firstSector, sectorCount)) {
    IOLog("GUNYAH-BSD: failure=invalid-window\n");
    return;
  }
  char uuid[64] = {};
  bool hasUuid = PE_parse_boot_arg_str("gunyah-root-partuuid", uuid, sizeof(uuid));
  if (hasUuid) {
    if (hasStart || hasCount) { IOLog("GUNYAH-BSD: failure=gpt-conflicting-selectors\n"); return; }
    auto *work = static_cast<uint8_t *>(IOMallocData(GunyahGpt::WorkspaceBytes));
    if (!work) { IOLog("GUNYAH-BSD: failure=gpt-allocation\n"); return; }
    auto readDisk = [](void *context, uint64_t offset, uint32_t bytes, void *data) -> bool {
      uint32_t done = 0;
      auto *disk = static_cast<GunyahVirtioPci *>(context);
      return disk->readBytes(offset, bytes, data, done) == kIOReturnSuccess && done == bytes;
    };
    GunyahGpt::Selection selected = {};
    const char *error = GunyahGpt::select(readDisk, transport, transport->sectors(), uuid, work, selected);
    IOFreeData(work, GunyahGpt::WorkspaceBytes);
    if (error) { IOLog("GUNYAH-BSD: failure=gpt-%s\n", error); return; }
    firstSector = selected.start;
    sectorCount = selected.count;
    IOLog("GUNYAH-GPT: selected uuid=%s index=%u start=%llu sectors=%llu copies=2 crc=PASS\n",
          uuid, selected.index, firstSector, sectorCount);
  }
  IOLog("GUNYAH-BSD: window start=%llu sectors=%llu disk_sectors=%llu explicit=%u\n",
        firstSector, sectorCount, transport->sectors(), unsigned(hasStart));
  int blockMajor = bdevsw_add(-1, &blockSwitch);
  if (blockMajor < 0) { IOLog("GUNYAH-BSD: failure=bdevsw\n"); return; }
  int rawMajor = cdevsw_add_with_bdev(-1, &rawSwitch, blockMajor);
  if (rawMajor < 0) {
    bdevsw_remove(blockMajor, &blockSwitch);
    IOLog("GUNYAH-BSD: failure=cdevsw\n"); return;
  }
  void *blockNode = devfs_make_node(makedev(blockMajor, 0), DEVFS_BLOCK, UID_ROOT, GID_OPERATOR, 0600, "gvblk0");
  void *rawNode = devfs_make_node(makedev(rawMajor, 0), DEVFS_CHAR, UID_ROOT, GID_OPERATOR, 0600, "rgvblk0");
  if (!blockNode || !rawNode) {
    if (blockNode) devfs_remove(blockNode);
    if (rawNode) devfs_remove(rawNode);
    cdevsw_remove(rawMajor, &rawSwitch);
    bdevsw_remove(blockMajor, &blockSwitch);
    IOLog("GUNYAH-BSD: failure=devfs\n"); return;
  }
  published = true;
  rootMajor = blockMajor;
  IOLog("GUNYAH-BSD: published block=gvblk0 raw=rgvblk0 block_major=%d raw_major=%d sectors=%llu block_size=512 readonly=1\n",
        blockMajor, rawMajor, sectorCount);
}

// rd=gvblk0 root selection. IOFindBSDRoot resolves it to the published block
// dev_t exactly like a memory device, without an IOMedia service or BSD-name
// registry matching. Only the live read-only node qualifies.
extern "C" bool gunyah_block_root_device(const char *name, dev_t *device);
extern "C" bool gunyah_block_root_device(const char *name, dev_t *device)
{
  using namespace GunyahBlockBsd;
  if (!name || !device || strcmp(name, "gvblk0") != 0) return false;
  if (!published || rootMajor < 0 || !transport || !transport->isOnline()) {
    IOLog("GUNYAH-ROOT: failure=device-not-published name=gvblk0\n");
    return false;
  }
  *device = makedev(rootMajor, 0);
  rootSelected = true;
  IOLog("GUNYAH-ROOT: device=gvblk0 major=%d minor=0 readonly=1 sectors=%llu\n", rootMajor, sectorCount);
  return true;
}

// The diagnostic HFS+ root carries no Apple trust chain or sealed-volume
// authentication. FSIOC_KERNEL_ROOTAUTH is skipped only when the root really
// is gvblk0 AND the operator passed gunyah-root-unauthenticated=1; any other
// root keeps the upstream "rootvp not authenticated" panic.
extern "C" bool gunyah_block_root_unauthenticated(void);
extern "C" bool gunyah_block_root_unauthenticated(void)
{
  using namespace GunyahBlockBsd;
  if (!rootSelected) return false;
  unsigned allow = 0;
  PE_parse_boot_argn("gunyah-root-unauthenticated", &allow, sizeof(allow));
  if (allow != 1) {
    IOLog("GUNYAH-ROOT: authentication=required boot-arg=gunyah-root-unauthenticated missing\n");
    return false;
  }
  IOLog("GUNYAH-ROOT: authentication=skipped boot-arg=gunyah-root-unauthenticated\n");
  return true;
}
