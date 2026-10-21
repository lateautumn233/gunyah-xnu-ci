/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_OS_ENTITLEMENTS_HPP
#define GUNYAH_OS_ENTITLEMENTS_HPP
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
extern "C" {
#include "GunyahEntitlements.h"
}

/* Storage/query adapter only, not AMFI or a signature trust decision.
 * Signature policy must authenticate and authorize the DER before attaching this
 * object. Each caller must retain the object for the full operation. Invalidate
 * revokes subsequent queries; an already-running query may finish. Storage stays
 * alive until the last reference is released, so invalidation cannot free views.
 */
class GunyahOSEntitlements : public OSObject {
    OSDeclareDefaultStructors(GunyahOSEntitlements);
private:
    friend class GunyahSignaturePolicy;
    OSData *backing;
    OSData *xmlBacking;
    OSData *derBacking;
    uint8_t boundHash[20];
    bool bound;
    GEContext context;
    bool invalidated;
    void bindHash(const uint8_t hash[20]);
public:
    static GunyahOSEntitlements *withDER(const void *bytes, size_t size);
    static GunyahOSEntitlements *withSignedDER(const void *xml, size_t xmlSize,
                                              const void *der, size_t derSize);
    bool matchesHash(const uint8_t hash[20]) const;
    bool isPolicyBound() const;
    const void *xmlBlob(size_t *size) const;
    const void *derBlob(size_t *size) const;
    void invalidate();
    int queryBoolean(const char *key, bool *value) const;
    OSObject *copyValue(const char *key) const;
    OSDictionary *copyDictionary() const;
    void free() override;
};
#endif
