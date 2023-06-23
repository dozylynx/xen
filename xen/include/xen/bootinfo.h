#ifndef __XEN_BOOTINFO_H__
#define __XEN_BOOTINFO_H__

#include <xen/types.h>
#include <xen/compiler.h>
#include <xen/mm-frame.h>

#ifdef CONFIG_X86
#include <asm/bootinfo.h>
#else
    struct arch_bootmodule { };
    struct arch_boot_info { };
#endif

/* Boot module binary type / purpose */
#define BOOTMOD_UNKNOWN     0
#define BOOTMOD_XEN         1
#define BOOTMOD_FDT         2
#define BOOTMOD_KERNEL      3
#define BOOTMOD_RAMDISK     4
#define BOOTMOD_XSM         5
#define BOOTMOD_UCODE       6
#define BOOTMOD_GUEST_DTB   7
typedef unsigned int bootmod_type_t;

#define BOOTMOD_STRING_MAX_LEN 1024
struct boot_string {
    char bytes[BOOTMOD_STRING_MAX_LEN];
    size_t len;
};

struct boot_module {
    bootmod_type_t bootmod_type;
    paddr_t start;
    mfn_t mfn;
    size_t size;

    struct arch_bootmodule *arch;
    struct boot_string string;
};

struct boot_info {
    char *cmdline;

    unsigned int nr_mods;
    struct boot_module *mods;

    struct arch_boot_info *arch;
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
