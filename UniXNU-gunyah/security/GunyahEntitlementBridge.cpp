/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahEntitlementBridge.hpp"
#include "GunyahOSEntitlements.hpp"
#include "GunyahSignaturePolicy.hpp"
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>
extern "C" {
#include <sys/codesign.h>
#include <sys/errno.h>
#include <sys/proc_internal.h>
#include <kern/kalloc.h>
}

static GunyahOSEntitlements *object(const void *value)
{
    return OSDynamicCast(GunyahOSEntitlements, (OSObject *)value);
}

static GunyahOSEntitlements *copyProcObject(proc_t proc)
{
    if (!proc) return nullptr;
    OSObject *retained = nullptr;
    /* Match XNU csops' proc-lock snapshot, retaining the object before dropping
     * the lock. Subsequent queries use only that object, never a borrowed blob.
     * Caller owns the proc lifetime; exec can invalidate this snapshot later.
     */
    proc_lock(proc);
    if ((proc_getcsflags(proc) & (CS_VALID | CS_SIGNED)) == (CS_VALID | CS_SIGNED)) {
        struct cs_blob *blob = csproc_get_blob(proc);
        if (blob) retained = (OSObject *)csblob_os_entitlements_copy(blob);
    }
    proc_unlock(proc);
    auto result = object(retained);
    if (!result || !result->isPolicyBound()) {
        if (retained) retained->release();
        return nullptr;
    }
    return result;
}

static void invalidate(void *value)
{
    auto ent = object(value);
    if (ent) ent->invalidate(); // XNU owns/relinquishes the separate cs_blob ref.
}

static void *asDictionary(void *value)
{
    auto ent = object(value);
    return ent && ent->isPolicyBound() ? ent->copyDictionary() : nullptr;
}

static bool copyXML(void *value, CS_GenericBlob **output)
{
    if (!output) return false;
    *output = nullptr;
    auto ent = object(value);
    if (!ent || !ent->isPolicyBound()) return false;
    size_t size = 0;
    const void *bytes = ent->xmlBlob(&size);
    if (!bytes) return false;
    void *copy = kalloc_data(size, Z_WAITOK);
    if (!copy) return false;
    memcpy(copy, bytes, size);
    *output = (CS_GenericBlob *)copy; // csops frees with kfree_data(..., length).
    return true;
}

static bool borrowDER(void *value, const CS_GenericBlob **output)
{
    if (!output) return false;
    *output = nullptr;
    auto ent = object(value);
    if (!ent || !ent->isPolicyBound()) return false;
    size_t size = 0;
    *output = (const CS_GenericBlob *)ent->derBlob(&size);
    return *output != nullptr;
}

static kern_return_t adjust(void *value, struct cs_blob *blob)
{
    if (!blob) return KERN_FAILURE;
    if (!value) {
        /* XNU calls this for every signature. A blob with no entitlement object
         * is acceptable only when it carries no entitlement data to accelerate;
         * anything carrying XML/DER without a bound object stays rejected.
         */
        void *xml = nullptr;
        size_t xmlLength = 0;
        /* csblob_get_entitlements() hides the XML blob unless CS_VALID is set and
         * fails when a slot exists without a matching blob; require both.
         */
        if (!(csblob_get_flags(blob) & CS_VALID) || csblob_os_entitlements_get(blob) ||
            csblob_get_entitlements(blob, &xml, &xmlLength) != 0 || xml ||
            csblob_get_der_entitlements_unsafe(blob)) return KERN_FAILURE;
        return KERN_SUCCESS;
    }
    auto ent = object(value);
    if (!ent || csblob_os_entitlements_get(blob) != value ||
        !(csblob_get_flags(blob) & CS_VALID) || !ent->matchesHash(csblob_get_cdhash(blob)))
        return KERN_FAILURE;
    return KERN_SUCCESS;
}

static kern_return_t adjustMonitor(void *, const CEQueryContext_t, const void *, const char *, uint32_t)
{
    return KERN_NOT_SUPPORTED;
}

static kern_return_t booleanQuery(const void *value, const char *key)
{
    auto ent = object(value);
    bool enabled = false;
    return ent && ent->isPolicyBound() && ent->queryBoolean(key, &enabled) == GE_OK && enabled
        ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t stringQuery(const void *value, const char *key, const char *expected)
{
    auto ent = object(value);
    if (!ent || !ent->isPolicyBound() || !key || !expected || strnlen(expected, GE_MAX_STRING + 1) > GE_MAX_STRING)
        return KERN_FAILURE;
    OSObject *copy = ent->copyValue(key);
    OSString *string = OSDynamicCast(OSString, copy);
    bool equal = string && string->isEqualTo(expected);
    if (copy) copy->release();
    return equal ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t copyValue(const void *value, const char *key, void **output)
{
    if (!output) return KERN_INVALID_ARGUMENT;
    *output = nullptr;
    auto ent = object(value);
    if (!ent || !ent->isPolicyBound() || !key) return KERN_FAILURE;
    *output = ent->copyValue(key); // Caller owns returned reference.
    return *output ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t procBoolean(proc_t proc, const char *key)
{
    auto ent = copyProcObject(proc);
    if (!ent) return KERN_FAILURE;
    kern_return_t result = booleanQuery(ent, key);
    ent->release();
    return result;
}

static kern_return_t procString(proc_t proc, const char *key, const char *expected)
{
    auto ent = copyProcObject(proc);
    if (!ent) return KERN_FAILURE;
    kern_return_t result = stringQuery(ent, key, expected);
    ent->release();
    return result;
}

static kern_return_t procCopy(proc_t proc, const char *key, void **output)
{
    if (!output) return KERN_INVALID_ARGUMENT;
    *output = nullptr;
    auto ent = copyProcObject(proc);
    if (!ent) return KERN_FAILURE;
    kern_return_t result = copyValue(ent, key, output);
    ent->release();
    return result;
}

void gunyah_fill_entitlement_callbacks(amfi_t *interface)
{
    if (!interface) return;
    interface->OSEntitlements_invalidate = invalidate;
    interface->OSEntitlements_asdict = asDictionary;
    interface->OSEntitlements_get_xml = copyXML;
    interface->OSEntitlements_get_transmuted = borrowDER;
    interface->OSEntitlements = {OSENTITLEMENTS_INTERFACE_VERSION, adjustMonitor, adjust,
        booleanQuery, procBoolean, stringQuery, procString, copyValue, procCopy};
}

int gunyah_bind_entitlements(const GunyahSignaturePolicy *policy, struct cs_blob *blob)
{
    /* Do not attach while amfi is NULL: cs_blob_cleanup calls invalidate before
     * releasing the object even when the signature operation later fails. */
    if (!policy || !blob) return EINVAL;
    if (!amfi || amfi->OSEntitlements_invalidate != invalidate ||
        amfi->OSEntitlements.adjustContextWithoutMonitor != adjust ||
        amfi->OSEntitlements.version != OSENTITLEMENTS_INTERFACE_VERSION) return ENOTSUP;
    GunyahOSEntitlements *prepared = nullptr;
    int error = policy->prepare(blob, &prepared);
    if (error) return error;
    csblob_os_entitlements_set(blob, prepared); // Retains for XNU cleanup.
    prepared->release();                       // Drop our construction ref.
    return 0;
}
