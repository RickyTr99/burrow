/*
 * Maps the guest program (cfg.host_exe) and its ELF interpreter into this
 * process, as the kernel's execve() would, and starts it on the stack the
 * kernel built for Burrow.
 */

#include "burrow.h"

#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6
#define ET_EXEC 2
#define ET_DYN 3
#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_EXECFN 31

struct ehdr {
    unsigned char ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};

struct phdr {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};

struct image {
    uint64_t base, entry, phdr, phnum;
};

extern void burrow_jump(uint64_t entry, long* sp) __attribute__((noreturn));

static uint64_t page_size = 4096;

static uint64_t down(uint64_t v) { return v & ~(page_size - 1); }
static uint64_t up(uint64_t v) { return (v + page_size - 1) & ~(page_size - 1); }

static int is_error(long r) { return r < 0 && r > -4096; }

/* Maps the ELF file @host; its PT_INTERP into @interp (guest path) if any. */
static void map_elf(const char* host, struct image* out, char* interp) {
    long fd = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot open ", host);
    struct ehdr eh;
    struct phdr ph[64];
    if (sys(NR_pread64, fd, &eh, sizeof(eh), 0) != sizeof(eh) || eh.ident[0] != 0x7f || eh.ident[1] != 'E' ||
        eh.ident[4] != 2 || eh.machine != 183 || (eh.type != ET_EXEC && eh.type != ET_DYN) ||
        eh.phentsize != sizeof(struct phdr) || eh.phnum == 0 || eh.phnum > 64)
        die("not an arm64 ELF program: ", host);
    long size = eh.phnum * (long) sizeof(struct phdr);
    if (sys(NR_pread64, fd, ph, size, eh.phoff) != size) die("cannot read ", host);

    uint64_t low = ~0ull, high = 0;
    for (int i = 0; i < eh.phnum; i++) {
        if (ph[i].type != PT_LOAD) continue;
        if (down(ph[i].vaddr) < low) low = down(ph[i].vaddr);
        if (up(ph[i].vaddr + ph[i].memsz) > high) high = up(ph[i].vaddr + ph[i].memsz);
    }
    if (low >= high) die("no segment in ", host);

    uint64_t bias = 0;
    if (eh.type == ET_DYN) {
        long at = sys6(NR_mmap, 0, (long) (high - low), 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (is_error(at)) die("no room for ", host);
        bias = (uint64_t) at - low;
    }
    out->phdr = 0;
    if (interp) interp[0] = 0;
    for (int i = 0; i < eh.phnum; i++) {
        const struct phdr* p = &ph[i];
        if (p->type == PT_INTERP && interp) {
            if (p->filesz == 0 || p->filesz >= PATH_MAX ||
                sys(NR_pread64, fd, interp, p->filesz, p->offset) != (long) p->filesz)
                die("bad interpreter in ", host);
            interp[p->filesz] = 0;
        }
        if (p->type == PT_PHDR) out->phdr = bias + p->vaddr;
        if (p->type != PT_LOAD) continue;
        if (!out->phdr && eh.phoff >= p->offset && eh.phoff + size <= p->offset + p->filesz)
            out->phdr = bias + p->vaddr + (eh.phoff - p->offset);
        int prot = (p->flags & 4 ? PROT_READ : 0) | (p->flags & 2 ? PROT_WRITE : 0) | (p->flags & 1 ? PROT_EXEC : 0);
        uint64_t start = bias + down(p->vaddr);
        uint64_t file_end = bias + p->vaddr + p->filesz;
        uint64_t mem_end = bias + p->vaddr + p->memsz;
        if (p->filesz > 0) {
            long r = sys6(NR_mmap, (long) start, (long) (up(file_end) - start), prot | (p->memsz > p->filesz ? PROT_WRITE : 0),
                          MAP_PRIVATE | MAP_FIXED, fd, (long) down(p->offset));
            if (is_error(r)) die("cannot map ", host);
            /* The start of the bss shares the last file page: zero it. */
            if (p->memsz > p->filesz && up(file_end) > file_end) memset((void*) file_end, 0, up(file_end) - file_end);
            if (p->memsz > p->filesz && !(prot & PROT_WRITE))
                sys(NR_mprotect, start, up(file_end) - start, prot, 0);
        }
        uint64_t anon = p->filesz > 0 ? up(file_end) : start;
        if (mem_end > anon) {
            long r = sys6(NR_mmap, (long) anon, (long) (up(mem_end) - anon), prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                          -1, 0);
            if (is_error(r)) die("cannot map the bss of ", host);
        }
    }
    sys(NR_close, fd, 0, 0, 0);
    out->base = bias;
    out->entry = bias + eh.entry;
    out->phnum = eh.phnum;
}

void load_and_run(long* sp) {
    long argc = sp[0];
    char** envp = (char**) (sp + 1 + argc + 1);
    long e = 0;
    while (envp[e]) e++;
    uint64_t* auxv = (uint64_t*) (envp + e + 1);
    for (uint64_t* a = auxv; a[0] != AT_NULL; a += 2)
        if (a[0] == AT_PAGESZ) page_size = a[1];

    struct image program, interpreter = {0, 0, 0, 0};
    char interp[PATH_MAX], host[PATH_MAX];
    map_elf(cfg.host_exe, &program, interp);
    uint64_t entry = program.entry;
    if (interp[0]) {
        long r = to_host(interp, 1, host, 0);
        if (r < 0) die("cannot find the interpreter ", interp);
        map_elf(host, &interpreter, 0);
        entry = interpreter.entry;
    }
    for (uint64_t* a = auxv; a[0] != AT_NULL; a += 2) {
        switch (a[0]) {
        case AT_PHDR: a[1] = program.phdr; break;
        case AT_PHENT: a[1] = sizeof(struct phdr); break;
        case AT_PHNUM: a[1] = program.phnum; break;
        case AT_BASE: a[1] = interpreter.base; break;
        case AT_ENTRY: a[1] = program.entry; break;
        case AT_EXECFN: a[1] = (uint64_t) cfg.exe; break;
        }
    }
    sys(NR_prctl, 15 /* PR_SET_NAME */, cfg.name, 0, 0);
    burrow_jump(entry, sp);
}
