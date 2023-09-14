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
#include <inttypes.h>
#include <regex.h>
#include <elf.h>
#include <glob.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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

typedef struct {
    int dlfunc_type; /* -1, DLFUNC_POSIX or DLFUNC_INTERNAL */
    FILE *fp;
    size_t libc_addr;
    size_t str_offset;
    size_t str_size;
    size_t sym_offset;
    size_t sym_num;
    size_t sym_entsize;
} param_t;

static int search_and_open_libc(FILE **fp_out, pid_t pid, size_t *addr);
static int open_libc(FILE **fp_out, const char *path, dev_t dev, ino_t ino);
static int read_elf_ehdr(FILE *fp, Elf_Ehdr *ehdr);
static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size);
static int read_elf_sym(FILE *fp, Elf_Sym *sym, size_t sym_size);
static int find_symbol_addr(size_t *addr, param_t *prm, const char *posix_name, const char *internal_name);
static size_t find_strtab_offset(const param_t *prm, const char *name);

int injector__collect_libc_information(injector_t *injector)
{
    pid_t pid = injector->pid;
    FILE *fp;
    Elf_Ehdr ehdr;
    Elf_Shdr shdr;
    param_t prm = {-1, };
    size_t shstrtab_offset;
    int idx;
    int rv;

    rv = search_and_open_libc(&fp, pid, &prm.libc_addr);
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
                prm.str_offset = shdr.sh_offset;
                prm.str_size = shdr.sh_size;
            }
            break;
        case SHT_DYNSYM:
            fgetpos(fp, &pos);
            fseek(fp, shstrtab_offset + shdr.sh_name, SEEK_SET);
            fgets(buf, sizeof(buf), fp);
            fsetpos(fp, &pos);
            if (strcmp(buf, ".dynsym") == 0) {
                prm.sym_offset = shdr.sh_offset;
                prm.sym_entsize = shdr.sh_entsize;
                prm.sym_num = shdr.sh_size / shdr.sh_entsize;
            }
            break;
        }
        if (prm.sym_offset != 0 && prm.str_offset != 0) {
            break;
        }
    }
    if (idx == ehdr.e_shnum) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    prm.fp = fp;

    rv = find_symbol_addr(&injector->dlopen_addr, &prm, "dlopen", "__libc_dlopen_mode");
    if (rv != 0) {
        goto cleanup;
    }

    rv = find_symbol_addr(&injector->dlclose_addr, &prm, "dlclose", "__libc_dlclose");
    if (rv != 0) {
        goto cleanup;
    }

    rv = find_symbol_addr(&injector->dlsym_addr, &prm, "dlsym", "__libc_dlsym");
    if (rv != 0) {
        goto cleanup;
    }

    if (prm.dlfunc_type != DLFUNC_INTERNAL) {
        rv = find_symbol_addr(&injector->dlerror_addr, &prm, "dlerror", NULL);
        if (rv != 0) {
            goto cleanup;
        }
    } else {
        injector->dlerror_addr = 0;
    }

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    rv = find_symbol_addr(&injector->clone_addr, &prm, "clone", "clone");
    if (rv != 0) {
        goto cleanup;
    }
#endif

    injector->dlfunc_type = prm.dlfunc_type;
    injector->code_addr = prm.libc_addr + ehdr.e_entry;

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
    case EM_MIPS:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            /* MIPS 64 */
            injector->arch = ARCH_MIPS_64;
            injector->sys_mmap = 5000 + 9;
            injector->sys_mprotect = 5000 + 10;
            injector->sys_munmap = 5000 + 11;
        } else if (ehdr.e_flags & EF_MIPS_ABI2) {
            /* MIPS N32 */
            injector->arch = ARCH_MIPS_N32;
            injector->sys_mmap = 6000 + 9;
            injector->sys_mprotect = 6000 + 10;
            injector->sys_munmap = 6000 + 11;
        } else {
            /* MIPS O32 */
            injector->arch = ARCH_MIPS_O32;
            injector->sys_mmap = 4000 + 90;
            injector->sys_mprotect = 4000 + 125;
            injector->sys_munmap = 4000 + 91;
        }
        break;
    case EM_PPC64:
        injector->arch = ARCH_POWERPC_64;
        injector->sys_mmap = 90;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    case EM_PPC:
        injector->arch = ARCH_POWERPC;
        injector->sys_mmap = 90;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
#ifdef EM_RISCV
    case EM_RISCV:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            injector->arch = ARCH_RISCV_64;
        } else {
            injector->arch = ARCH_RISCV_32;
        }
        injector->sys_mmap = 222;
        injector->sys_mprotect = 226;
        injector->sys_munmap = 215;
        break;
#endif
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

static int search_and_open_libc(FILE **fp_out, pid_t pid, size_t *addr)
{
    char buf[512];
    FILE *fp = NULL;
    regex_t reg;
    regmatch_t match;

    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", buf, strerror(errno));
        return INJERR_OTHER;
    }
    /* /libc.so.6 or /libc-2.{DIGITS}.so or /lib/ld-musl-{arch}.so.1 */
    if (regcomp(&reg, "/libc(\\.so\\.6|-2\\.[0-9]+\\.so)|/ld-musl-.+?\\.so\\.1", REG_EXTENDED) != 0) {
        injector__set_errmsg("regcomp failed!");
        return INJERR_OTHER;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        unsigned long saddr, eaddr;
        unsigned long long offset, inode;
        unsigned int dev_major, dev_minor;
        if (sscanf(buf, "%lx-%lx %*s %llx %x:%x %llu", &saddr, &eaddr, &offset, &dev_major, &dev_minor, &inode) != 6) {
            continue;
        }
        if (offset != 0) {
            continue;
        }
        if (regexec(&reg, buf, 1, &match, 0) != 0) {
            continue;
        }
        char *p = buf + match.rm_eo;
        if (strcmp(p, " (deleted)\n") == 0) {
            injector__set_errmsg("The C library when the process started was removed");
            fclose(fp);
            regfree(&reg);
            return INJERR_NO_LIBRARY;
        }
        if (strcmp(p, "\n") != 0) {
            continue;
        }
        fclose(fp);
        *addr = saddr;
        regfree(&reg);
        *p = '\0';
        return open_libc(fp_out, strchr(buf, '/'), makedev(dev_major, dev_minor), inode);
    }
    fclose(fp);
    injector__set_errmsg("Could not find libc");
    regfree(&reg);
    return INJERR_NO_LIBRARY;
}

static int open_libc(FILE **fp_out, const char *path, dev_t dev, ino_t ino)
{
    struct stat sbuf;
    glob_t globbuf;
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        const char *p = strstr(path, "/rootfs/"); /* under LXD */
        if (p != NULL) {
            fp = fopen(p + 7, "r");
        }
    }
    if (fp != NULL) {
        if (fstat(fileno(fp), &sbuf) == 0 && sbuf.st_dev == dev && sbuf.st_ino == ino) {
            // Found
            *fp_out = fp;
            return 0;
        }
        fclose(fp);
    }
    // Could not find the valid libc in the specified path.

    // Search libc in base snaps. (https://snapcraft.io/docs/base-snaps)
    if (glob("/snap/core*/*", GLOB_NOSORT, NULL, &globbuf) == 0) {
        size_t idx;
        for (idx = 0; idx < globbuf.gl_pathc; idx++) {
            char buf[512];
            snprintf(buf, sizeof(buf), "%s%s", globbuf.gl_pathv[idx], path);
            buf[sizeof(buf) - 1] = '\0';
            fp = fopen(buf, "r");
            if (fp != NULL) {
                if (fstat(fileno(fp), &sbuf) == 0 && sbuf.st_dev == dev && sbuf.st_ino == ino) {
                    // Found
                    *fp_out = fp;
                    globfree(&globbuf);
                    return 0;
                }
                fclose(fp);
            }
        }
        globfree(&globbuf);
    }
    injector__set_errmsg("failed to open %s. (dev:0x%" PRIx64 ", ino:%lu)", path, dev, ino);
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

static int find_symbol_addr(size_t *addr, param_t *prm, const char *posix_name, const char *internal_name)
{
    size_t st_name;

    switch (prm->dlfunc_type) {
    case -1:
        st_name = find_strtab_offset(prm, posix_name);
        if (st_name != 0) {
            prm->dlfunc_type = DLFUNC_POSIX;
        } else {
            prm->dlfunc_type = DLFUNC_INTERNAL;
            st_name = find_strtab_offset(prm, internal_name);
        }
        break;
    case DLFUNC_POSIX:
        st_name = find_strtab_offset(prm, posix_name);
        break;
    case DLFUNC_INTERNAL:
        st_name = find_strtab_offset(prm, internal_name);
        break;
    }

    if (st_name != 0) {
        Elf_Sym sym;
        int idx;
        int rv;

        fseek(prm->fp, prm->sym_offset, SEEK_SET);
        for (idx = 0; idx < prm->sym_num; idx++) {
            rv = read_elf_sym(prm->fp, &sym, prm->sym_entsize);
            if (rv != 0) {
                return rv;
            }
            if (sym.st_name == st_name) {
                *addr = prm->libc_addr + sym.st_value;
                return 0;
            }
        }
    }
    injector__set_errmsg("failed to find %s%s%s in the .dynstr section.",
                         posix_name, internal_name ? "/" : "",
                         internal_name ? internal_name : "");
    return INJERR_NO_FUNCTION;
}

static size_t find_strtab_offset(const param_t *prm, const char *name)
{
    size_t off;
    size_t idx = 0;

    fseek(prm->fp, prm->str_offset, SEEK_SET);
    for (off = 0; off < prm->str_size; off++) {
        int c = fgetc(prm->fp);
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
