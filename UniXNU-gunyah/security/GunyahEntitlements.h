/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_ENTITLEMENTS_H
#define GUNYAH_ENTITLEMENTS_H
#include <stddef.h>
#include <stdint.h>

/* Diagnostic DER-v1 subset: ASCII keys, booleans, strings, string arrays.
 * Parsing conveys no trust or entitlement grant. Caller must authenticate the
 * blob separately and retain immutable backing storage for the context lifetime.
 * Unknown types/versions and inputs exceeding these limits are rejected.
 */
#define GE_MAX_ENTRIES 64
#define GE_MAX_BLOB 16384
#define GE_MAX_STRING 512
#define GE_MAX_ARRAY 32
enum { GE_OK = 0, GE_MALFORMED = -1, GE_NOT_FOUND = -2, GE_WRONG_TYPE = -3 };
enum { GE_BOOLEAN = 1, GE_STRING = 12, GE_STRING_ARRAY = 48 };
typedef struct { const uint8_t *bytes; size_t size; } GEView;
typedef struct { GEView key, value; uint8_t type; } GEEntry;
typedef struct { GEEntry entries[GE_MAX_ENTRIES]; size_t count; } GEContext;

int ge_parse(const uint8_t *data, size_t size, GEContext *context);
int ge_find(const GEContext *context, const char *key, size_t size, const GEEntry **entry);
int ge_boolean(const GEContext *context, const char *key, size_t size, int *value);
int ge_array_contains(const GEContext *context, const char *key, size_t size,
                      const char *value, size_t value_size, int *contains);
int ge_array_item(const GEEntry *entry, size_t index, GEView *value);
#endif
