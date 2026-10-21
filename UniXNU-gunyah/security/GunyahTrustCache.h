/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_TRUST_CACHE_H
#define GUNYAH_TRUST_CACHE_H
#include <stddef.h>
#include <stdint.h>

/* Raw v2 module lookup. Caller owns immutable backing storage and must verify
 * its pinned digest/authentication before using a match in a trust decision.
 * A match does not grant platform flags or interpret constraintCategory.
 */
typedef struct { const uint8_t *entries; uint32_t count; } GTModule;
typedef struct { uint8_t hash_type, flags, constraint_category; } GTMatch;
enum { GT_OK = 0, GT_INVALID = -1, GT_MISSING = -2 };
int gt_open(const void *payload, size_t size, GTModule *module);
int gt_find(const GTModule *module, const uint8_t cdhash[20], GTMatch *match);
#endif
