/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahTrustCache.h"

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int compare(const uint8_t *a, const uint8_t *b)
{
    for (unsigned i = 0; i < 20; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

int gt_open(const void *payload, size_t size, GTModule *module)
{
    if (!module) return GT_INVALID;
    module->entries = NULL; module->count = 0;
    if (!payload || size < 24) return GT_INVALID;
    const uint8_t *bytes = payload;
    uint32_t count = le32(bytes + 20);
    /* Bound allocations/work for diagnostic firmware input. */
    if (le32(bytes) != 2 || count > 65536 ||
        (size - 24) / 24 != count || (size - 24) % 24) return GT_INVALID;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = bytes + 24 + (size_t)i * 24;
        if (entry[23] || (i && compare(entry - 24, entry) >= 0)) return GT_INVALID;
    }
    module->entries = bytes + 24;
    module->count = count;
    return GT_OK;
}

int gt_find(const GTModule *module, const uint8_t cdhash[20], GTMatch *match)
{
    if (!match) return GT_INVALID;
    match->hash_type = match->flags = match->constraint_category = 0;
    if (!module || !module->entries || module->count > 65536 || !cdhash) return GT_INVALID;
    uint32_t first = 0, last = module->count;
    while (first < last) {
        uint32_t mid = first + (last - first) / 2;
        const uint8_t *entry = module->entries + (size_t)mid * 24;
        int order = compare(cdhash, entry);
        if (order < 0) last = mid;
        else if (order > 0) first = mid + 1;
        else {
            match->hash_type = entry[20];
            match->flags = entry[21];
            match->constraint_category = entry[22];
            return GT_OK;
        }
    }
    return GT_MISSING;
}
