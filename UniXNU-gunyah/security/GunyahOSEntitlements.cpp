/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahOSEntitlements.hpp"
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>

OSDefineMetaClassAndStructors(GunyahOSEntitlements, OSObject);

static OSString *copyString(GEView view)
{
    if (view.size > GE_MAX_STRING) return nullptr;
    char text[GE_MAX_STRING + 1];
    memcpy(text, view.bytes, view.size);
    text[view.size] = 0;
    return OSString::withCString(text);
}

static OSObject *copyEntry(const GEEntry &entry)
{
    if (entry.type == GE_BOOLEAN) {
        OSBoolean *value = entry.value.bytes[0] ? kOSBooleanTrue : kOSBooleanFalse;
        value->retain();
        return value;
    }
    if (entry.type == GE_STRING) return copyString(entry.value);
    if (entry.type != GE_STRING_ARRAY) return nullptr;
    OSArray *array = OSArray::withCapacity(1);
    if (!array) return nullptr;
    for (size_t i = 0; i <= GE_MAX_ARRAY; ++i) {
        GEView view;
        int result = ge_array_item(&entry, i, &view);
        if (result == GE_NOT_FOUND) return array;
        if (result != GE_OK) break;
        OSString *item = copyString(view);
        if (!item) break;
        bool stored = array->setObject(item);
        item->release();
        if (!stored) break;
    }
    array->release();
    return nullptr;
}

GunyahOSEntitlements *GunyahOSEntitlements::withDER(const void *bytes, size_t size)
{
    if (!bytes || !size || size > GE_MAX_BLOB) return nullptr;
    auto object = new GunyahOSEntitlements;
    if (!object) return nullptr;
    object->backing = nullptr;
    object->xmlBacking = nullptr;
    object->derBacking = nullptr;
    object->bound = false;
    bzero(object->boundHash, sizeof(object->boundHash));
    object->context.count = 0;
    object->invalidated = true;
    if (!object->init()) { object->release(); return nullptr; }
    object->backing = OSData::withBytes(bytes, (unsigned)size);
    if (!object->backing || ge_parse((const uint8_t *)object->backing->getBytesNoCopy(),
                                    size, &object->context) != GE_OK) {
        object->release();
        return nullptr;
    }
    __atomic_store_n(&object->invalidated, false, __ATOMIC_RELEASE);
    return object;
}

GunyahOSEntitlements *GunyahOSEntitlements::withSignedDER(const void *xml, size_t xmlSize,
                                                        const void *der, size_t derSize)
{
    if (!xml || !der || xmlSize < 8 || xmlSize > GE_MAX_BLOB + 8 ||
        derSize <= 8 || derSize > GE_MAX_BLOB + 8) return nullptr;
    const uint8_t *x = (const uint8_t *)xml, *d = (const uint8_t *)der;
    auto be32 = [](const uint8_t *p) -> uint32_t {
        return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    };
    if (be32(x) != 0xfade7171 || be32(d) != 0xfade7172 ||
        be32(x + 4) != xmlSize || be32(d + 4) != derSize) return nullptr;
    auto object = withDER(d + 8, derSize - 8);
    if (!object) return nullptr;
    object->xmlBacking = OSData::withBytes(xml, (unsigned)xmlSize);
    object->derBacking = OSData::withBytes(der, (unsigned)derSize);
    if (!object->xmlBacking || !object->derBacking) { object->release(); return nullptr; }
    return object;
}

void GunyahOSEntitlements::bindHash(const uint8_t hash[20])
{
    memcpy(boundHash, hash, sizeof(boundHash));
    bound = true; // Called only by policy before publishing the object.
}

bool GunyahOSEntitlements::matchesHash(const uint8_t hash[20]) const
{
    return hash && bound && !__atomic_load_n(&invalidated, __ATOMIC_ACQUIRE) &&
           memcmp(hash, boundHash, sizeof(boundHash)) == 0;
}

bool GunyahOSEntitlements::isPolicyBound() const
{
    return bound && !__atomic_load_n(&invalidated, __ATOMIC_ACQUIRE);
}

const void *GunyahOSEntitlements::xmlBlob(size_t *size) const
{
    if (!size) return nullptr;
    *size = 0;
    if (!xmlBacking || __atomic_load_n(&invalidated, __ATOMIC_ACQUIRE)) return nullptr;
    *size = xmlBacking->getLength();
    return xmlBacking->getBytesNoCopy();
}

const void *GunyahOSEntitlements::derBlob(size_t *size) const
{
    if (!size) return nullptr;
    *size = 0;
    if (!derBacking || __atomic_load_n(&invalidated, __ATOMIC_ACQUIRE)) return nullptr;
    *size = derBacking->getLength();
    return derBacking->getBytesNoCopy();
}

void GunyahOSEntitlements::invalidate()
{
    __atomic_store_n(&invalidated, true, __ATOMIC_RELEASE);
}

int GunyahOSEntitlements::queryBoolean(const char *key, bool *value) const
{
    if (!value) return GE_MALFORMED;
    *value = false;
    if (!key || __atomic_load_n(&invalidated, __ATOMIC_ACQUIRE)) return GE_NOT_FOUND;
    int resultValue = 0;
    int result = ge_boolean(&context, key, strnlen(key, GE_MAX_STRING + 1), &resultValue);
    if (result == GE_OK) *value = resultValue != 0;
    return result;
}

OSObject *GunyahOSEntitlements::copyValue(const char *key) const
{
    if (!key || __atomic_load_n(&invalidated, __ATOMIC_ACQUIRE)) return nullptr;
    const GEEntry *entry;
    if (ge_find(&context, key, strnlen(key, GE_MAX_STRING + 1), &entry) != GE_OK) return nullptr;
    return copyEntry(*entry);
}

OSDictionary *GunyahOSEntitlements::copyDictionary() const
{
    if (__atomic_load_n(&invalidated, __ATOMIC_ACQUIRE)) return nullptr;
    OSDictionary *dict = OSDictionary::withCapacity((unsigned)context.count);
    if (!dict) return nullptr;
    for (size_t i = 0; i < context.count; ++i) {
        OSString *key = copyString(context.entries[i].key);
        OSObject *value = copyEntry(context.entries[i]);
        bool stored = key && value && dict->setObject(key, value);
        if (key) key->release();
        if (value) value->release();
        if (!stored) { dict->release(); return nullptr; }
    }
    return dict;
}

void GunyahOSEntitlements::free()
{
    invalidate();
    context.count = 0;
    if (backing) { backing->release(); backing = nullptr; }
    if (xmlBacking) { xmlBacking->release(); xmlBacking = nullptr; }
    if (derBacking) { derBacking->release(); derBacking = nullptr; }
    OSObject::free();
}
