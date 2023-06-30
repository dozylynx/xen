#ifndef __ARCH_X86_BOOTINFO_H__
#define __ARCH_X86_BOOTINFO_H__

struct arch_bootmodule {
#define BOOTMOD_FLAG_X86_RELOCATED     1U << 0
    uint32_t flags;
    unsigned headroom;
};
DEFINE_STRUCT_PTR_TYPE(arch_bootmodule);

struct arch_boot_info {
    uint32_t flags;
#define BOOTINFO_FLAG_X86_CMDLINE      1U << 2
#define BOOTINFO_FLAG_X86_MODULES      1U << 3
#define BOOTINFO_FLAG_X86_MEMMAP       1U << 6
#define BOOTINFO_FLAG_X86_LOADERNAME   1U << 9

    char_ptr_t boot_loader_name;

    uint32_t mmap_length;
    paddr_t mmap_addr;
};
DEFINE_STRUCT_PTR_TYPE(arch_boot_info);

struct __packed mb_memmap {
    uint32_t size;
    uint32_t base_addr_low;
    uint32_t base_addr_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;
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
