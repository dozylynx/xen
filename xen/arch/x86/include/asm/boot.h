#ifndef __ASM_X86_BOOT_H__
#define __ASM_X86_BOOT_H__

#include <xen/bootinfo.h>
#include <xen/multiboot.h>

#include <asm/setup.h>

static inline void *bootstrap_map_multiboot(const module_t *mod)
{
    struct boot_module bm;

    if ( !mod )
        return bootstrap_map(NULL);

    bm.start = mod->mod_start << PAGE_SHIFT;
    bm.size = mod->mod_end;

    return bootstrap_map(&bm);
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
