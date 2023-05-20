#ifndef __XEN_BOOTINFO_H__
#define __XEN_BOOTINFO_H__

#include <xen/types.h>

#ifdef CONFIG_X86
#include <asm/bootinfo.h>
#else
    struct arch_bootmodule { };
#endif

struct boot_module {
    struct arch_bootmodule *arch;
};

struct boot_info {
    unsigned int nr_mods;
    struct boot_module *mods;
};

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
