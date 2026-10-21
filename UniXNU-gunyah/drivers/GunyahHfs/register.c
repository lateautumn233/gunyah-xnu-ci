// SPDX-License-Identifier: BSD-2-Clause-Patent
// Built-in registration using the pinned HFS IOService::start API sequence.
#include <pexpert/pexpert.h>
#include <sys/sysctl.h>
#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_iokit.h"

#ifndef panic_on_assert
bool panic_on_assert;
#endif
#if DEBUG
bool hfs_corruption_panics = true;
#endif
extern struct vnodeopv_desc hfs_vnodeop_opv_desc, hfs_specop_opv_desc, hfs_fifoop_opv_desc;
extern struct vfsops hfs_vfsops;
static vfstable_t handle;

void gunyah_hfs_register(void);
void gunyah_hfs_register(void)
{
    if (handle) return;
#ifndef panic_on_assert
    panic_on_assert = PE_i_can_has_kernel_configuration() & kPEICanHasAssertions;
#endif
    struct vnodeopv_desc *operations[] = {
        &hfs_vnodeop_opv_desc, &hfs_specop_opv_desc,
#if FIFO
        &hfs_fifoop_opv_desc,
#endif
    };
    struct vfs_fsentry entry = {
        .vfe_vfsops = &hfs_vfsops,
        .vfe_vopcnt = sizeof(operations) / sizeof(operations[0]),
        .vfe_opvdescs = operations,
        .vfe_fsname = "hfs",
        .vfe_flags = VFS_TBLNOTYPENUM | VFS_TBLLOCALVOL | VFS_TBLREADDIR_EXTENDED |
            VFS_TBL64BITREADY | VFS_TBLVNOP_PAGEOUTV2 | VFS_TBLVNOP_PAGEINV2 |
            VFS_TBLTHREADSAFE | VFS_TBLCANMOUNTROOT | VFS_TBLNATIVEXATTR,
    };
    int error = vfs_fsadd(&entry, &handle);
    if (error) panic("GunyahHfs: vfs_fsadd failed: %d", error);
    hfs_init_zones();
    hfs_sysctl_register();
    printf("GUNYAH-HFS: registered version=650.140.2 content_protection=unsupported\n");
}

// The dedicated virtual test disk is fixed media, with no external journal
// discovery service. An external-journal mount cannot be satisfied here.
int hfs_is_ejectable(const char *name __unused) { return 0; }
void hfs_iterate_media_with_content(const char *uuid __unused,
    int (*callback)(const char *, const char *, void *) __unused, void *arg __unused) {}
kern_return_t hfs_get_platform_serial_number(char *serial, uint32_t length)
{
    if (length) serial[0] = 0;
    return KERN_NOT_SUPPORTED;
}
