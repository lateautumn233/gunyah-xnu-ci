/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef GUNYAH_SECURITY_INIT_HPP
#define GUNYAH_SECURITY_INIT_HPP
#ifdef __cplusplus
extern "C" {
#endif
struct cs_blob;
/* Early bootstrap hook, before lockdown. No-op unless gunyah-iphone-trust=1,
 * so the diagnostic kernel keeps amfi == NULL (existing behavior) by default.
 * If the pinned trust module is rejected, amfi stays NULL and everything that
 * needs a provider keeps failing closed.
 */
void gunyah_security_init(void);
/* Called on the unpublished cs_blob before entitlement acceleration. Returns 0
 * with the blob bound, ENOTSUP when no provider is active, EPERM for inputs the
 * pinned policy does not know (left unbound; adjust() then decides), and any
 * other errno for a pinned input whose content does not match.
 */
int gunyah_security_bind(struct cs_blob *blob);
#ifdef __cplusplus
}
#endif
#endif
