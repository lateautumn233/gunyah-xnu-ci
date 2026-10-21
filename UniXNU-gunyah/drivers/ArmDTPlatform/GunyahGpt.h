// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
#include "GunyahDiskWindow.h"

// Deliberately bounded GPT subset: 512-byte sectors, revision 1, 128 entries
// of 128 bytes. Require both copies to agree; never repair or silently fall
// back to a damaged/stale copy. GUID is a selector, not authentication.
namespace GunyahGpt {
static inline uint32_t le32(const uint8_t *p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
static inline uint64_t le64(const uint8_t *p) { return le32(p) | uint64_t(le32(p+4)) << 32; }
static inline bool equal(const uint8_t *a, const uint8_t *b, unsigned n) {
  for (unsigned i=0; i<n; i++) if (a[i] != b[i]) return false;
  return true;
}
static inline bool zero(const uint8_t *p, unsigned n) {
  for (unsigned i=0; i<n; i++) if (p[i]) return false;
  return true;
}
static inline uint32_t crc(const uint8_t *p, unsigned n, bool header=false) {
  uint32_t value = 0xffffffffU;
  for (unsigned i=0; i<n; i++) {
    value ^= header && i >= 16 && i < 20 ? 0 : p[i];
    for (unsigned bit=0; bit<8; bit++) value = (value >> 1) ^ (0xedb88320U & (0U-(value & 1)));
  }
  return ~value;
}
static inline int hex(char c) {
  if (c >= '0' && c <= '9') return c-'0';
  if (c >= 'a' && c <= 'f') return c-'a'+10;
  if (c >= 'A' && c <= 'F') return c-'A'+10;
  return -1;
}
static inline bool guid(const char *s, uint8_t *out) {
  unsigned at=0;
  uint8_t canonical[16];
  for (unsigned i=0; i<36;) {
    if (i==8 || i==13 || i==18 || i==23) { if (s[i++]!='-') return false; continue; }
    int hi=hex(s[i++]); if (hi<0) return false;
    int lo=hex(s[i++]); if (lo<0) return false;
    canonical[at++] = uint8_t(hi*16+lo);
  }
  if (s[36] || zero(canonical,16)) return false;
  const unsigned order[16]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
  for (unsigned i=0;i<16;i++) out[i]=canonical[order[i]];
  return true;
}
struct Selection { uint64_t start, count; unsigned index; };
using Read = bool (*)(void *, uint64_t, uint32_t, void *);
static constexpr unsigned WorkspaceBytes = 32768;

static inline bool header(const uint8_t *h, uint64_t current, uint64_t alternate, uint64_t total) {
  const uint8_t signature[8]={'E','F','I',' ','P','A','R','T'};
  return equal(h,signature,8) && le32(h+8)==0x10000 && le32(h+12)==92 && le32(h+20)==0
    && crc(h,92,true)==le32(h+16) && le64(h+24)==current && le64(h+32)==alternate
    && le64(h+40)>=34 && le64(h+40)<=le64(h+48) && le64(h+48)<total-33
    && !zero(h+56,16) && le32(h+80)==128 && le32(h+84)==128;
}
static inline const char *select(Read read, void *context, uint64_t total,
                                const char *uuid, uint8_t *work, Selection &result) {
  uint8_t wanted[16];
  if (!guid(uuid,wanted)) return "uuid";
  if (total<68 || total>UINT64_MAX/512) return "capacity";
  uint8_t primary[512], backup[512];
  if (!read(context,0,512,primary)) return "mbr-read";
  if (primary[510]!=0x55 || primary[511]!=0xaa || primary[450]!=0xee || le32(primary+454)!=1
      || le32(primary+458)!=(total-1>UINT32_MAX ? UINT32_MAX : uint32_t(total-1))
      || !zero(primary+462,48)) return "protective-mbr";
  if (!read(context,512,512,primary) || !read(context,(total-1)*512,512,backup)) return "header-read";
  if (!header(primary,1,total-1,total) || !header(backup,total-1,1,total)) return "header";
  if (!equal(primary+40,backup+40,32) || !equal(primary+80,backup+80,12)
      || le64(primary+72)!=2 || le64(backup+72)!=total-33) return "header-mismatch";
  if (!read(context,1024,16384,work) || !read(context,(total-33)*512,16384,work+16384)) return "entries-read";
  if (crc(work,16384)!=le32(primary+88) || crc(work+16384,16384)!=le32(backup+88)
      || !equal(work,work+16384,16384)) return "entries-crc";
  unsigned matches=0;
  for (unsigned i=0;i<128;i++) {
    const uint8_t *entry=work+i*128;
    if (zero(entry,16)) continue;
    uint64_t start=le64(entry+32), end=le64(entry+40);
    if (zero(entry+16,16) || start<le64(primary+40) || end>le64(primary+48) || end<start) return "partition-range";
    for (unsigned j=0;j<i;j++) {
      const uint8_t *other=work+j*128;
      if (!zero(other,16) && (equal(entry+16,other+16,16)
          || (start<=le64(other+40) && le64(other+32)<=end))) return "partition-conflict";
    }
    if (equal(entry+16,wanted,16)) {
      const uint8_t hfs[16]={0,0x53,0x46,0x48,0,0,0xaa,0x11,0xaa,0x11,0,0x30,0x65,0x43,0xec,0xac};
      if (!equal(entry,hfs,16)) return "partition-type";
      result={start,end-start+1,i+1};
      matches++;
    }
  }
  return matches==1 ? nullptr : "uuid-not-found";
}
}
