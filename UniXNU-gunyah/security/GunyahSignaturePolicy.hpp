/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_SIGNATURE_POLICY_HPP
#define GUNYAH_SIGNATURE_POLICY_HPP
#include "GunyahOSEntitlements.hpp"
extern "C" {
#include "GunyahTrustCache.h"
}
struct cs_blob;

/* Explicit diagnostic policy for two pinned iPhone 20H392 inputs, not Apple
 * signature authentication. Does not register MACF/AMFI or set platform flags.
 * The caller must retain this immutable policy while preparing an object.
 */
class GunyahSignaturePolicy : public OSObject {
    OSDeclareDefaultStructors(GunyahSignaturePolicy);
private:
    OSData *moduleBytes;
    GTModule module;
public:
    static GunyahSignaturePolicy *withOSTrustCache(const void *rawModule, size_t size);
    /* Only for a kernel-validated, unpublished cs_blob owned by the MAC hook.
     * Success returns one owned reference. Attach only after a compatible AMFI
     * lifecycle bridge is registered: csblob_os_entitlements_set retains it;
     * caller then releases its reference. Failure leaves *result == nullptr.
     * This function never attaches: XNU cleanup dereferences amfi unconditionally.
     */
    int prepare(struct cs_blob *blob, GunyahOSEntitlements **result) const;
    void free() override;
};
#endif
