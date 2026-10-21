/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_AMFI_HPP
#define GUNYAH_AMFI_HPP
#include <mach/kern_return.h>
#include <libkern/amfi/amfi.h>

/* Complete, deny-by-default amfi_t for the Gunyah diagnostic provider.
 * OSEntitlements members come from GunyahEntitlementBridge; every TrustCache,
 * CoreEntitlements and legacy member explicitly rejects (never grants).
 * Registration is not performed here: amfi_interface_register() panics on a
 * second call and must precede lockdown, so the caller owns the single call.
 */
const amfi_t *gunyah_amfi_interface(void);
#endif
