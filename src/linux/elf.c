/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018 Kubo Takehiro <kubo@jiubao.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include "injector_internal.h"

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#endif

static int open_libc(FILE **fp_out, pid_t pid, size_t *addr);
static int read_elf_ehdr(FILE *fp, Elf_Ehdr *ehdr);
static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size);
static int read_elf_sym(FILE *fp, Elf_Sym *sym, size_t sym_size);
static size_t find_strtab_offset(FILE *fp, size_t offset, size_t size, const char *name);

int injector__collect_libc_information(injector_t *injector)
{
    pid_t pid = injector->pid;
    FILE *fp;
    size_t libc_addr;
    Elf_Ehdr ehdr;
    Elf_Shdr shdr;
    size_t shstrtab_offset;
    size_t str_offset = 0;
    size_t str_size = 0;
    size_t sym_offset = 0;
    size_t sym_num = 0;
    size_t sym_entsize = 0;
    size_t dlopen_st_name;
    size_t dlopen_offset;
    Elf_Sym sym;
    int idx;
    int rv;

    rv = open_libc(&fp, pid, &libc_addr);
    if (rv != 0) {
        return rv;
    }
    rv = read_elf_ehdr(fp, &ehdr);
    if (rv != 0) {
        goto cleanup;
    }
    fseek(fp, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    rv = read_elf_shdr(fp, &shdr, ehdr.e_shentsize);
    if (rv != 0) {
        goto cleanup;
    }
    shstrtab_offset = shdr.sh_offset;

    fseek(fp, ehdr.e_shoff, SEEK_SET);
    for (idx = 0; idx < ehdr.e_shnum; idx++) {
        fpos_t pos;
        char buf[8];

        rv = read_elf_shdr(fp, &shdr, ehdr.e_shentsize);
        if (rv != 0) {
            goto cleanup;
        }
        switch (shdr.sh_type) {
        case SHT_STRTAB:
            fgetpos(fp, &pos);
            fseek(fp, shstrtab_offset + shdr.sh_name, SEEK_SET);
            fgets(buf, sizeof(buf), fp);
            fsetpos(fp, &pos);
            if (strcmp(buf, ".dynstr") == 0) {
                str_offset = shdr.sh_offset;
                str_size = shdr.sh_size;
            }
            break;
        case SHT_DYNSYM:
            fgetpos(fp, &pos);
            fseek(fp, shstrtab_offset + shdr.sh_name, SEEK_SET);
            fgets(buf, sizeof(buf), fp);
            fsetpos(fp, &pos);
            if (strcmp(buf, ".dynsym") == 0) {
                sym_offset = shdr.sh_offset;
                sym_entsize = shdr.sh_entsize;
                sym_num = shdr.sh_size / shdr.sh_entsize;
            }
            break;
        }
        if (sym_offset != 0 && str_offset != 0) {
            break;
        }
    }
    if (idx == ehdr.e_shnum) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    dlopen_st_name = find_strtab_offset(fp, str_offset, str_size, "__libc_dlopen_mode");
    if (dlopen_st_name == 0) {
        injector__set_errmsg("failed to find __libc_dlopen_mode in the .dynstr section.");
        rv = INJERR_NO_FUNCTION;
        goto cleanup;
    }

    fseek(fp, sym_offset, SEEK_SET);
    for (idx = 0; idx < sym_num; idx++) {
        rv = read_elf_sym(fp, &sym, sym_entsize);
        if (rv != 0) {
            goto cleanup;
        }
        if (sym.st_name == dlopen_st_name) {
            dlopen_offset = sym.st_value;
            break;
        }
    }

    injector->dlopen_addr = libc_addr + dlopen_offset;
    injector->code_addr = libc_addr + ehdr.e_entry;

    switch (ehdr.e_machine) {
    case EM_X86_64:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            /* LP64 */
            injector->arch = ARCH_X86_64;
            injector->sys_mmap = 9;
            injector->sys_mprotect = 10;
            injector->sys_munmap = 11;
        } else {
            /* ILP32 */
            injector->arch = ARCH_X86_64_X32;
            injector->sys_mmap = 0x40000000 + 9;
            injector->sys_mprotect = 0x40000000 + 10;
            injector->sys_munmap = 0x40000000 + 11;
        }
        break;
    case EM_386:
        injector->arch = ARCH_I386;
        injector->sys_mmap = 192;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    case EM_AARCH64:
        injector->arch = ARCH_ARM64;
        injector->sys_mmap = 222;
        injector->sys_mprotect = 226;
        injector->sys_munmap = 215;
        break;
    case EM_ARM:
        if (EF_ARM_EABI_VERSION(ehdr.e_flags) == 0) {
            injector__set_errmsg("ARM OABI target process isn't supported.");
            rv = INJERR_UNSUPPORTED_TARGET;
            goto cleanup;
        }
        if (injector->code_addr & 1u) {
            injector->code_addr &= ~1u;
            injector->arch = ARCH_ARM_EABI_THUMB;
        } else {
            injector->arch = ARCH_ARM_EABI;
        }
        injector->sys_mmap = 192;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    default:
        injector__set_errmsg("Unknown target process architecture: 0x%04x", ehdr.e_machine);
        rv = INJERR_UNSUPPORTED_TARGET;
        goto cleanup;
    }
    rv = 0;
cleanup:
    fclose(fp);
    return rv;
}

static int open_libc(FILE **fp_out, pid_t pid, size_t *addr)
{
    char buf[512];
    FILE *fp = NULL;

    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", buf, strerror(errno));
        return INJERR_OTHER;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        unsigned long saddr, eaddr;
        if (sscanf(buf, "%lx-%lx r-xp", &saddr, &eaddr) == 2) {
            char *p = strstr(buf, "/libc-2.");
            if (p != NULL) {
                char *endptr;
                p += strlen("/libc-2.");
                strtol(p, &endptr, 10);
                if (strcmp(endptr, ".so\n") == 0) {
                    fclose(fp);
                    p = strchr(buf, '/');
                    p[strlen(p) - 1] = '\0';
                    fp = fopen(p, "r");
                    if (fp == NULL) {
                        injector__set_errmsg("failed to open %s. (error: %s)", p, strerror(errno));
                        return INJERR_NO_LIBRARY;
                    }
                    *addr = saddr;
                    *fp_out = fp;
                    return 0;
                } else if (strcmp(endptr, ".so (deleted)\n") == 0) {
                    injector__set_errmsg("The C library when the process started was removed");
                    fclose(fp);
                    return INJERR_NO_LIBRARY;
                }
            }
        }
    }
    fclose(fp);
    injector__set_errmsg("Could not find libc");
    return INJERR_NO_LIBRARY;
}

static int read_elf_ehdr(FILE *fp, Elf_Ehdr *ehdr)
{
    if (fread(ehdr, sizeof(*ehdr), 1, fp) != 1) {
        injector__set_errmsg("failed to read ELF header. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        injector__set_errmsg("Invalid ELF header: 0x%02x,0x%02x,0x%02x,0x%02x",
                           ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
        return INJERR_INVALID_ELF_FORMAT;
    }
    switch (ehdr->e_ident[EI_CLASS]) {
    case ELFCLASS32:
#ifdef __LP64__
        {
            Elf32_Ehdr *ehdr32 = (Elf32_Ehdr *)ehdr;
            /* copy from last */
            ehdr->e_shstrndx = ehdr32->e_shstrndx;
            ehdr->e_shnum = ehdr32->e_shnum;
            ehdr->e_shentsize = ehdr32->e_shentsize;
            ehdr->e_phnum = ehdr32->e_phnum;
            ehdr->e_phentsize = ehdr32->e_phentsize;
            ehdr->e_ehsize = ehdr32->e_ehsize;
            ehdr->e_flags = ehdr32->e_flags;
            ehdr->e_shoff = ehdr32->e_shoff;
            ehdr->e_phoff = ehdr32->e_phoff;
            ehdr->e_entry = ehdr32->e_entry;
            ehdr->e_version = ehdr32->e_version;
            ehdr->e_machine = ehdr32->e_machine;
            ehdr->e_type = ehdr32->e_type;
        }
#endif
        break;
    case ELFCLASS64:
#ifndef __LP64__
        injector__set_errmsg("64-bit target process isn't supported by 32-bit process.");
        return INJERR_UNSUPPORTED_TARGET;
#endif
        break;
    default:
        injector__set_errmsg("Invalid ELF class: 0x%x", ehdr->e_ident[EI_CLASS]);
        return INJERR_UNSUPPORTED_TARGET;
    }
    return 0;
}

static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size)
{
    if (fread(shdr, shdr_size, 1, fp) != 1) {
        injector__set_errmsg("failed to read a section header. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
#ifdef __LP64__
    if (shdr_size == sizeof(Elf32_Shdr)) {
        Elf32_Shdr shdr32 = *(Elf32_Shdr *)shdr;
        shdr->sh_name = shdr32.sh_name;
        shdr->sh_type = shdr32.sh_type;
        shdr->sh_flags = shdr32.sh_flags;
        shdr->sh_addr = shdr32.sh_addr;
        shdr->sh_offset = shdr32.sh_offset;
        shdr->sh_size = shdr32.sh_size;
        shdr->sh_link = shdr32.sh_link;
        shdr->sh_info = shdr32.sh_info;
        shdr->sh_addralign = shdr32.sh_addralign;
        shdr->sh_entsize = shdr32.sh_entsize;
    }
#endif
    return 0;
}

static int read_elf_sym(FILE *fp, Elf_Sym *sym, size_t sym_size)
{
    if (fread(sym, sym_size, 1, fp) != 1) {
        injector__set_errmsg("failed to read a symbol table entry. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
#ifdef __LP64__
    if (sym_size == sizeof(Elf32_Sym)) {
        Elf32_Sym sym32 = *(Elf32_Sym *)sym;
        sym->st_name = sym32.st_name;
        sym->st_value = sym32.st_value;
        sym->st_size = sym32.st_size;
        sym->st_info = sym32.st_info;
        sym->st_other = sym32.st_other;
        sym->st_shndx = sym32.st_shndx;
    }
#endif
    return 0;
}

static size_t find_strtab_offset(FILE *fp, size_t offset, size_t size, const char *name)
{
    size_t off;
    size_t idx = 0;

    fseek(fp, offset, SEEK_SET);
    for (off = 0; off < size; off++) {
        int c = fgetc(fp);
        if (c == EOF) {
            return 0;
        }
        if (c == name[idx]) {
            if (c == 0) {
                return off - idx;
            }
            idx++;
        } else {
            idx = 0;
        }
    }
    return 0;
}
