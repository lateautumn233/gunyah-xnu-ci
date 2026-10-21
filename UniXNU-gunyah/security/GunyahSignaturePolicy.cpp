/* SPDX-License-Identifier: BSD-2-Clause */
#include "GunyahSignaturePolicy.hpp"
#include <libkern/libkern.h>
#include <libkern/OSByteOrder.h>
extern "C" {
#include <sys/codesign.h>
#include <sys/errno.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <pexpert/pexpert.h>
}

OSDefineMetaClassAndStructors(GunyahSignaturePolicy, OSObject);

/* Full SHA256 pins audited against the fixed iPhone inputs. Never accept an
 * arbitrary blob merely because it supplies its own internally consistent hash.
 */
static const char osModuleHash[] = "b7ab28e0009900326ae685a88748008a9653e6bcbd70674135dac4eb5231ad64";
static const char launchdCD[] = "b65c36c9f5b287a6a8f5ca83d9427fb55ef04f4e661f40e643d011f7a2bad3d7";
static const char dyldCD[] = "684d847c40e6e873eeaec693011d4d997a869d2addd173f03fc3425ebc89c443";
static const char launchdXML[] = "aa19776d632829897f6f45eaac7639f5983bf22386757ff35aea02885d54e854";
static const char launchdDER[] = "5f971dbded6bcbdb2339fa6123d8878d3a7cbbcf73c7884c3d17b6790bae1999";

static void sha256(const void *bytes, size_t size, uint8_t digest[32])
{
    ccdigest(ccsha256_di(), size, bytes, digest);
}

static bool matches(const uint8_t digest[32], const char *hex)
{
    const char digits[] = "0123456789abcdef";
    unsigned difference = 0;
    for (unsigned i = 0; i < 32; ++i) {
        difference |= (unsigned)(digits[digest[i] >> 4] ^ hex[i * 2]);
        difference |= (unsigned)(digits[digest[i] & 15] ^ hex[i * 2 + 1]);
    }
    return difference == 0;
}

static bool pinned(const void *bytes, size_t size, const char *hash)
{
    uint8_t digest[32];
    sha256(bytes, size, digest);
    return matches(digest, hash);
}

GunyahSignaturePolicy *GunyahSignaturePolicy::withOSTrustCache(const void *rawModule, size_t size)
{
    unsigned enabled = 0;
    PE_parse_boot_argn("gunyah-iphone-trust", &enabled, sizeof(enabled));
    if (enabled != 1 || !rawModule || size != 24 + 2760 * 24) return nullptr;
    auto policy = new GunyahSignaturePolicy;
    if (!policy) return nullptr;
    policy->moduleBytes = nullptr;
    policy->module = {};
    if (!policy->init()) { policy->release(); return nullptr; }
    policy->moduleBytes = OSData::withBytes(rawModule, (unsigned)size);
    /* Hash the owned copy, not mutable caller storage. */
    if (!policy->moduleBytes ||
        !pinned(policy->moduleBytes->getBytesNoCopy(), size, osModuleHash) ||
        gt_open(policy->moduleBytes->getBytesNoCopy(), size, &policy->module) != GT_OK) {
        policy->release();
        return nullptr;
    }
    return policy;
}

int GunyahSignaturePolicy::prepare(struct cs_blob *blob, GunyahOSEntitlements **result) const
{
    if (!result) return EINVAL;
    *result = nullptr;
    if (!blob || !moduleBytes || csblob_os_entitlements_get(blob)) return EINVAL;
    if (!(csblob_get_flags(blob) & CS_VALID) || csblob_get_hashtype(blob) != CS_HASHTYPE_SHA256) return EPERM;
    const CS_CodeDirectory *cd = csblob_get_code_directory(blob);
    uintptr_t base = csblob_get_addr(blob), pointer = (uintptr_t)cd;
    size_t total = csblob_get_size(blob);
    if (!cd || pointer < base || pointer - base > total || total - (pointer - base) < 8) return EBADEXEC;
    size_t length = OSSwapBigToHostInt32(cd->length);
    if (length < sizeof(CS_CodeDirectory) || length > total - (pointer - base)) return EBADEXEC;
    uint8_t digest[32];
    sha256(cd, length, digest);
    bool launchd = matches(digest, launchdCD), dyld = matches(digest, dyldCD);
    const uint8_t *cdhash = csblob_get_cdhash(blob);
    if (!cdhash || memcmp(cdhash, digest, 20)) return EBADEXEC;
    GTMatch match;
    /* Not a member of the pinned OS trust cache: leave unbound (EPERM); the
     * entitlement adjust step then rejects anything carrying entitlements. */
    if (gt_find(&module, cdhash, &match) != GT_OK || match.hash_type != CS_HASHTYPE_SHA256 ||
        match.flags != 0) return EPERM;
    /* launchd/dyld additionally require their audited category and exact blobs.
     * Other members use the entitlements their own signature carries: the
     * trust-cache CDHash covers the special slots, which csblob_get_* verify. */
    if ((launchd || dyld) && match.constraint_category != 2) return EPERM;
    void *xml = nullptr;
    const CS_GenericBlob *der = nullptr;
    size_t xmlSize = 0, derSize = 0;
    int error = csblob_get_entitlements(blob, &xml, &xmlSize);
    if (error) return error;
    error = csblob_get_der_entitlements(blob, &der, &derSize);
    if (error) return error;
    if (dyld && (xml || der || xmlSize || derSize)) return EBADEXEC;
    GunyahOSEntitlements *object;
    if (launchd) {
        /* This exact XML/DER pair was compared semantically offline. */
        if (!xml || !der || xmlSize != 1677 || derSize != 1105 ||
            !pinned(xml, xmlSize, launchdXML) || !pinned(der, derSize, launchdDER)) return EBADEXEC;
        object = GunyahOSEntitlements::withSignedDER(xml, xmlSize, der, derSize);
    } else if (xml && der) {
        /* Other trust-cache members: the DER is the signed source of truth. An
         * unparsable/oversized set fails closed (EPERM leaves the blob unbound). */
        object = GunyahOSEntitlements::withSignedDER(xml, xmlSize, der, derSize);
        if (!object) return EPERM;
    } else if (!xml && !der) {
        static const uint8_t empty[] = {0x70, 5, 2, 1, 1, 0xb0, 0};
        object = GunyahOSEntitlements::withDER(empty, sizeof(empty));
    } else {
        return EPERM; /* XML-only or DER-only: not representable here */
    }
    if (!object) return ENOMEM;
    object->bindHash(cdhash);
    *result = object;
    return 0;
}

void GunyahSignaturePolicy::free()
{
    module = {};
    if (moduleBytes) { moduleBytes->release(); moduleBytes = nullptr; }
    OSObject::free();
}
