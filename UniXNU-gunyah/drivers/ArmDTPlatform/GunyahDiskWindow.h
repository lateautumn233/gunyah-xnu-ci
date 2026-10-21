// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

namespace GunyahDiskWindow {
// Decimal only; reject signs, whitespace, truncation and overflow.
static inline bool decimal(const char *text, uint64_t &value)
{
  if (!text || !*text) return false;
  value = 0;
  unsigned digits = 0;
  for (; *text; ++text) {
    if (++digits > 20) return false;
    if (*text < '0' || *text > '9') return false;
    unsigned digit = unsigned(*text - '0');
    if (value > (UINT64_MAX - digit) / 10) return false;
    value = value * 10 + digit;
  }
  return true;
}
static inline bool valid(uint64_t total, uint64_t start, uint64_t count)
{
  return total <= UINT64_MAX / 512 && count && start < total && count <= total - start;
}
}
