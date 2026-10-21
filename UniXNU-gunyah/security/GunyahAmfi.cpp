/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahAmfi.hpp"
#include "GunyahEntitlementBridge.hpp"
#include <libkern/libkern.h>
#include <string.h>

/* CEError_t is an opaque pointer, so each error needs its own identity. kNoError
 * must differ from every error a stub can return.
 */
struct CEError { const char *name; };
static const CEError ceNoError = {"no error"};
static const CEError ceAPIMisuse = {"gunyah: CoreEntitlements unsupported"};
static const CEError ceInvalidArgument = {"invalid argument"};
static const CEError ceAllocationFailed = {"allocation failed"};
static const CEError ceMalformed = {"malformed entitlements"};
static const CEError ceQueryUnsatisfied = {"query cannot be satisfied"};
#if CE_ACCELERATION_SUPPORTED
static const CEError ceNotEligible = {"not eligible for acceleration"};
#endif

static TCReturn_t tcDenied(uint8_t component)
{
    return buildTCRet(component, kTCReturnUnsupported, 0);
}

static TCReturn_t tcConstructInvalid(TrustCache_t *, const uint8_t *, size_t)
{ return tcDenied(kTCComponentConstructInvalid); }
static TCReturn_t tcCheckRuntimeForUUID(const TrustCacheRuntime_t *, const uint8_t *, const TrustCache_t **tc)
{ if (tc) *tc = nullptr; return tcDenied(kTCComponentCheckRuntimeForUUID); }
static TCReturn_t tcLoadModule(TrustCacheRuntime_t *, const TCType_t, TrustCache_t *, const uintptr_t, const size_t)
{ return tcDenied(kTCComponentLoadModule); }
static TCReturn_t tcLoad(TrustCacheRuntime_t *, TCType_t, TrustCache_t *, const uintptr_t, const size_t,
    const uintptr_t, const size_t)
{ return tcDenied(kTCComponentLoad); }
static TCReturn_t tcExtractModule(TrustCache_t *, const uint8_t *, size_t)
{ return tcDenied(kTCComponentExtractModule); }
/* A miss, not an error: no CDHash is ever reported as trusted. */
static TCReturn_t tcQuery(const TrustCacheRuntime_t *, TCQueryType_t, const uint8_t *, TrustCacheQueryToken_t *token)
{
    if (token) memset(token, 0, sizeof(*token));
    return buildTCRet(kTCComponentQuery, kTCReturnNotFound, 0);
}
static TCReturn_t tcGetModule(const TrustCache_t *, const uint8_t **module, size_t *size)
{
    if (module) *module = nullptr;
    if (size) *size = 0;
    return tcDenied(kTCComponentGetModule);
}
static TCReturn_t tcGetUUID(const TrustCache_t *, uint8_t uuid[kUUIDSize])
{ if (uuid) memset(uuid, 0, kUUIDSize); return tcDenied(kTCComponentGetUUID); }
static TCReturn_t tcGetCapabilities(const TrustCache_t *, TCCapabilities_t *caps)
{ if (caps) *caps = 0; return tcDenied(kTCComponentModuleCapabilities); }
static TCReturn_t tcQueryTCType(const TrustCacheQueryToken_t *, TCType_t *type)
{ if (type) *type = kTCTypeInvalid; return tcDenied(kTCComponentQueryTCType); }
static TCReturn_t tcQueryCapabilities(const TrustCacheQueryToken_t *, TCCapabilities_t *caps)
{ if (caps) *caps = 0; return tcDenied(kTCComponentModuleCapabilities); }
static TCReturn_t tcQueryHashType(const TrustCacheQueryToken_t *, uint8_t *type)
{ if (type) *type = 0; return tcDenied(kTCComponentQueryHashType); }
static TCReturn_t tcQueryFlags(const TrustCacheQueryToken_t *, uint64_t *flags)
{ if (flags) *flags = 0; return tcDenied(kTCComponentQueryFlags); }
static TCReturn_t tcQueryConstraint(const TrustCacheQueryToken_t *, uint8_t *category)
{ if (category) *category = 0; return tcDenied(kTCComponentQueryConstraintCategory); }

static CEError_t ceAcquireUnmanaged(const CERuntime_t, CEValidationResult, struct CEQueryContext *)
{ return &ceAPIMisuse; }
static CEError_t ceValidate(const CERuntime_t, CEValidationResult *, const uint8_t *, const uint8_t *)
{ return &ceAPIMisuse; }
static CEError_t ceContextQuery(CEQueryContext_t, const CEQueryOperation_t *, size_t)
{ return &ceQueryUnsatisfied; }
static struct CEQueryContext ceConjure(der_vm_context_t)
{ struct CEQueryContext empty; memset(&empty, 0, sizeof(empty)); return empty; }
static der_vm_context_t derInvalid()
{ der_vm_context_t empty; memset(&empty, 0, sizeof(empty)); return empty; }
static der_vm_context_t derCreate(const CERuntime_t, ccder_tag, bool, const uint8_t *, const uint8_t *)
{ return derInvalid(); }
static der_vm_context_t derExecute(const der_vm_context_t, CEQueryOperation_t)
{ return derInvalid(); }
static CEError_t derIterate(const der_vm_context_t, void *, der_vm_iteration_callback)
{ return &ceAPIMisuse; }
static bool derIsValid(const der_vm_context_t) { return false; }
static CEType_t derType(const der_vm_context_t, ccder_tag *tag) { if (tag) *tag = 0; return (CEType_t)0; }
static int64_t derInteger(const der_vm_context_t) { return 0; }
static CEBuffer derBuffer(const der_vm_context_t) { return CEBuffer{nullptr, 0}; }
static bool derBool(const der_vm_context_t) { return false; }
#if CE_ACCELERATION_SUPPORTED
static CEError_t ceIndexSize(CEQueryContext_t, size_t *size) { if (size) *size = 0; return &ceNotEligible; }
static CEError_t ceBuildIndex(CEQueryContext_t) { return &ceNotEligible; }
static CEError_t ceFreeIndex(CEQueryContext_t) { return &ceNotEligible; }
static bool ceIsAccelerated(CEQueryContext_t) { return false; }
#endif
static const char *ceErrorString(CEError_t error) { return error ? error->name : "unsupported"; }
static CEError_t ceIsSubset(CEQueryContext_t, CEQueryContext_t) { return &ceQueryUnsatisfied; }

/* Legacy profile/UDID/context-object hooks: no caller exists in this XNU, and
 * a provider that has none of that data must say so rather than invent it.
 */
static bool noLegacyProfile(const uint8_t **profile, size_t *length)
{ if (profile) *profile = nullptr; if (length) *length = 0; return false; }
static bool noUDID(const uint8_t **udid, size_t *length)
{ if (udid) *udid = nullptr; if (length) *length = 0; return false; }
static void *noContextObject(CEQueryContext_t) { return nullptr; }
/* Per-object legacy query; entitlement queries use the OSEntitlements v1 table. */
static CEError_t noLegacyQuery(void *, uint8_t *, CEQuery_t, size_t)
{ return &ceQueryUnsatisfied; }

const amfi_t *gunyah_amfi_interface(void)
{
    static amfi_t table;
    static bool ready;
    if (ready) return &table;
    memset(&table, 0, sizeof(table));
    gunyah_fill_entitlement_callbacks(&table);
    table.OSEntitlements_query = noLegacyQuery;
    table.get_legacy_profile_exemptions = noLegacyProfile;
    table.get_udid = noUDID;
    table.query_context_to_object = noContextObject;
    table.CoreEntitlements = {CE_BRIDGE_STRUCT_VERSION, ceAcquireUnmanaged, ceValidate, ceContextQuery, ceConjure,
        derCreate, derExecute, derIterate, derIsValid, derType, derInteger, derBuffer, derBool,
        &ceNoError, &ceAPIMisuse, &ceInvalidArgument, &ceAllocationFailed, &ceMalformed, &ceQueryUnsatisfied,
#if CE_ACCELERATION_SUPPORTED
        &ceNotEligible,
#endif
        ceErrorString, derBuffer, ceIsSubset,
#if CE_ACCELERATION_SUPPORTED
        ceIndexSize, ceBuildIndex, ceFreeIndex, ceIsAccelerated
#endif
    };
    table.TrustCache = {TRUST_CACHE_INTERFACE_VERSION, tcLoadModule, tcLoad, tcQuery, tcGetCapabilities,
        tcQueryTCType, tcQueryCapabilities, tcQueryHashType, tcQueryFlags, tcQueryConstraint,
        tcConstructInvalid, tcCheckRuntimeForUUID, tcExtractModule, tcGetModule, tcGetUUID};
    ready = true;
    return &table;
}
