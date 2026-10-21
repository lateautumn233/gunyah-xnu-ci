// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// Build the pinned filesystem with the external kext KPI view, independently
// of XNU's private CONFIG_* switches. Kernel MAC/signature policy is untouched.
#undef BSD_KERNEL_PRIVATE
#undef XNU_KERNEL_PRIVATE
#undef CONFIG_PROTECT
#undef CONFIG_SEARCHFS
#undef CONFIG_HFS_DIRLINK
#undef CONFIG_SECLUDED_RENAME
#undef CONFIG_MACF
#undef CONFIG_HFS_RBTREE
#undef QUOTA
#undef NAMEDSTREAMS
#undef FIFO
#undef HFS_COMPRESSION
#include "core/kext-config.h"
// AppleKeyStore is unavailable. The source adaptation refuses CP volumes.
#undef CONFIG_PROTECT
#define CONFIG_PROTECT 0
#undef CONFIG_SECLUDED_RENAME
#define CONFIG_SECLUDED_RENAME 0
