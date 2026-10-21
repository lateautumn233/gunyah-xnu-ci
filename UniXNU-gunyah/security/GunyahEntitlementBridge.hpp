/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_ENTITLEMENT_BRIDGE_HPP
#define GUNYAH_ENTITLEMENT_BRIDGE_HPP
#include <mach/kern_return.h>
#include <libkern/amfi/amfi.h>

/* Fill only lifecycle/export and OSEntitlements-v1 callbacks. The owner must
 * supply CoreEntitlements, legacy query and TrustCache interfaces separately.
 * This is not a complete amfi_t and MUST NOT be registered as one by itself.
 * Object callbacks require a live retained OSObject; proc callbacks require a
 * live proc reference supplied by their XNU caller.
 */
void gunyah_fill_entitlement_callbacks(amfi_t *interface);
class GunyahSignaturePolicy;
/* For MAC signature hook's exclusively owned, unpublished cs_blob. Requires
 * our lifecycle callbacks in the already-registered complete AMFI interface.
 * Caller retains policy. XNU owns attached objects, including on later failure.
 */
int gunyah_bind_entitlements(const GunyahSignaturePolicy *policy, struct cs_blob *blob);
#endif
