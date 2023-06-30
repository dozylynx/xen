#ifndef __XEN_BOOTINFO_H__
#define __XEN_BOOTINFO_H__

#include <xen/types.h>
#include <xen/compiler.h>
#include <xen/mm-frame.h>

#if defined CONFIG_X86 || CONFIG_ARM || CONFIG_RISCV
# include <asm/bootinfo.h>
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

/* Max number of boot modules a bootloader can provide in addition to Xen */
#define MAX_NR_BOOTMODS 63

#define BOOTMOD_STRING_MAX_LEN 1024
struct __packed boot_string {
    char bytes[BOOTMOD_STRING_MAX_LEN];
    size_t len;
};

struct __packed boot_module {
    bootmod_type_t bootmod_type;
    paddr_t start;
    mfn_t mfn;
    size_t size;

    arch_bootmodule_ptr_t arch;
    struct boot_string string;
};
DEFINE_STRUCT_PTR_TYPE(boot_module);

struct __packed boot_info {
    char_ptr_t cmdline;

    unsigned int nr_mods;
    boot_module_ptr_t mods;

    arch_boot_info_ptr_t arch;
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
