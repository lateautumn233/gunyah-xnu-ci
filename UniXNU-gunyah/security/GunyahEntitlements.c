/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahEntitlements.h"

static int tlv(GEView *input, uint8_t *tag, GEView *body)
{
    if (input->size < 2) return GE_MALFORMED;
    const uint8_t *p = input->bytes;
    size_t header = 2, size = p[1];
    *tag = p[0];
    if (size & 128) {
        size_t count = size & 127;
        if (!count || count > 4 || count > input->size - 2 || !p[2]) return GE_MALFORMED;
        size = 0;
        for (size_t i = 0; i < count; ++i) size = (size << 8) | p[2 + i];
        if (size < 128) return GE_MALFORMED;
        header += count;
    }
    if (size > input->size - header) return GE_MALFORMED;
    body->bytes = p + header; body->size = size;
    input->bytes += header + size; input->size -= header + size;
    return GE_OK;
}

static int ascii(GEView value, int key)
{
    if (value.size > GE_MAX_STRING || (key && !value.size)) return 0;
    for (size_t i = 0; i < value.size; ++i)
        if (value.bytes[i] < 32 || value.bytes[i] > 126) return 0;
    return 1;
}

static int compare(GEView a, GEView b)
{
    size_t size = a.size < b.size ? a.size : b.size;
    for (size_t i = 0; i < size; ++i) {
        if (a.bytes[i] < b.bytes[i]) return -1;
        if (a.bytes[i] > b.bytes[i]) return 1;
    }
    return a.size < b.size ? -1 : a.size != b.size;
}

static int valid_value(uint8_t type, GEView value)
{
    if (type == GE_BOOLEAN) return value.size == 1 && (value.bytes[0] == 0 || value.bytes[0] == 255);
    if (type == GE_STRING) return ascii(value, 0);
    if (type != GE_STRING_ARRAY) return 0;
    size_t count = 0;
    while (value.size) {
        uint8_t tag; GEView item;
        if (++count > GE_MAX_ARRAY || tlv(&value, &tag, &item) || tag != GE_STRING || !ascii(item, 0)) return 0;
    }
    return 1;
}

int ge_parse(const uint8_t *data, size_t size, GEContext *context)
{
    if (!context) return GE_MALFORMED;
    context->count = 0;
    if (!data || !size || size > GE_MAX_BLOB) return GE_MALFORMED;
    GEView input = {data, size}, outer, version, dict;
    uint8_t tag;
    if (tlv(&input, &tag, &outer) || tag != 0x70 || input.size) return GE_MALFORMED;
    if (tlv(&outer, &tag, &version) || tag != 2 || version.size != 1 || version.bytes[0] != 1) return GE_MALFORMED;
    if (tlv(&outer, &tag, &dict) || tag != 0xb0 || outer.size) return GE_MALFORMED;
    size_t count = 0;
    while (dict.size) {
        GEView pair; GEEntry entry;
        if (count == GE_MAX_ENTRIES || tlv(&dict, &tag, &pair) || tag != 0x30) return GE_MALFORMED;
        if (tlv(&pair, &tag, &entry.key) || tag != GE_STRING || !ascii(entry.key, 1)) return GE_MALFORMED;
        if (tlv(&pair, &entry.type, &entry.value) || pair.size || !valid_value(entry.type, entry.value)) return GE_MALFORMED;
        if (count && compare(context->entries[count - 1].key, entry.key) >= 0) return GE_MALFORMED;
        context->entries[count++] = entry;
    }
    context->count = count; /* Publish only after complete validation. */
    return GE_OK;
}

int ge_find(const GEContext *context, const char *key, size_t size, const GEEntry **entry)
{
    if (entry) *entry = NULL;
    if (!context || context->count > GE_MAX_ENTRIES || !key || !entry) return GE_MALFORMED;
    GEView target = {(const uint8_t *)key, size};
    if (!ascii(target, 1)) return GE_MALFORMED;
    for (size_t i = 0; i < context->count; ++i) {
        int order = compare(context->entries[i].key, target);
        if (!order) { *entry = &context->entries[i]; return GE_OK; }
        if (order > 0) break;
    }
    return GE_NOT_FOUND;
}

int ge_boolean(const GEContext *context, const char *key, size_t size, int *value)
{
    if (!value) return GE_MALFORMED;
    *value = 0;
    const GEEntry *entry;
    int result = ge_find(context, key, size, &entry);
    if (result) return result;
    if (entry->type != GE_BOOLEAN) return GE_WRONG_TYPE;
    *value = entry->value.bytes[0] != 0;
    return GE_OK;
}

int ge_array_contains(const GEContext *context, const char *key, size_t size,
                      const char *value, size_t value_size, int *contains)
{
    if (!contains || !value) return GE_MALFORMED;
    *contains = 0;
    const GEEntry *entry;
    int result = ge_find(context, key, size, &entry);
    if (result) return result;
    if (entry->type != GE_STRING_ARRAY) return GE_WRONG_TYPE;
    GEView rest = entry->value, target = {(const uint8_t *)value, value_size};
    while (rest.size) {
        uint8_t tag; GEView item;
        if (tlv(&rest, &tag, &item)) return GE_MALFORMED;
        if (!compare(item, target)) *contains = 1;
    }
    return GE_OK;
}

int ge_array_item(const GEEntry *entry, size_t index, GEView *value)
{
    if (!entry || !value) return GE_MALFORMED;
    value->bytes = NULL; value->size = 0;
    if (entry->type != GE_STRING_ARRAY) return GE_WRONG_TYPE;
    GEView rest = entry->value;
    size_t current = 0;
    while (rest.size) {
        GEView item; uint8_t tag;
        if (tlv(&rest, &tag, &item) || tag != GE_STRING) return GE_MALFORMED;
        if (current++ == index) { *value = item; return GE_OK; }
    }
    return GE_NOT_FOUND;
}
