#ifndef __ASM_X86_BOOT_H__
#define __ASM_X86_BOOT_H__

#include <xen/bootinfo.h>
#include <xen/multiboot.h>

#include <asm/setup.h>

static inline unsigned long bootmodule_index(
    const struct boot_info *info, bootmod_type_t bootmod_type,
    unsigned long start)
{
    for ( ; start < info->nr_mods; start++ )
        if ( info->mods[start].bootmod_type == bootmod_type )
            return start;

    return info->nr_mods + 1;
}

static inline struct boot_module *bootmodule_next(
    const struct boot_info *info, bootmod_type_t bootmod_type)
{
    unsigned long i;

    for ( i = 0; i < info->nr_mods; i++ )
        if ( info->mods[i].bootmod_type == bootmod_type )
            return &info->mods[i];

    return NULL;
}

static inline void bootmodule_update_start(struct boot_module *bm,
    paddr_t new_start)
{
    bm->start = new_start;
    bm->mfn = maddr_to_mfn(new_start);
}

static inline void bootmodule_update_mfn(struct boot_module *bm, mfn_t new_mfn)
{
    bm->mfn = new_mfn;
    bm->start = mfn_to_maddr(new_mfn);
}

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
