#define SYS_read     0
#define SYS_write    1
#define SYS_open     2
#define SYS_close    3
#define SYS_access   21
#define SYS_fork     57
#define SYS_execve   59
#define SYS_wait4    61
#define SYS_lseek    8
#define SYS_exit     60
#define SYS_unlink   87
#define SYS_rename   82
#define SYS_symlink  88
#define SYS_getcwd   79
#define SYS_getpid   39
#define SYS_mkdir    83
#define SYS_fstat    5
#define SYS_openat   257

static inline long syscall1(long num, long arg1) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall0(long num) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long num, long arg1, long arg2) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1), "S"(arg2) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall4(long num, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static unsigned long my_strlen(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    return len;
}

static int my_starts_with(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++; prefix++;
    }
    return 1;
}

static void my_strcpy(char *dst, const char *src) {
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

static void my_strcat(char *dst, const char *src) {
    while (*dst) dst++;
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

static int my_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void print_msg(const char *msg) {
    syscall3(SYS_write, 1, (long)msg, my_strlen(msg));
}

static void print_err(const char *msg) {
    syscall3(SYS_write, 2, (long)msg, my_strlen(msg));
}

static int file_exists(const char *path) {
    long ret = syscall2(SYS_access, (long)path, 0);
    return ret == 0;
}

static char g_patched_bin[4096];
static char g_interp_bin[4096];

static int is_elf(const char *path) {
    char header[4];
    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return 0;
    long n = syscall3(SYS_read, fd, (long)header, 4);
    syscall1(SYS_close, fd);  // close fd
    if (n != 4) return 0;
    return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
}

static int uint_to_str(long value, char *buf, int bufsz) {
    if (value < 0 || bufsz < 2) return 0;
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value > 0 && n < 22);
    int i = 0;
    while (n > 0) {
        if (i + 1 >= bufsz) return 0;
        buf[i++] = tmp[--n];
    }
    buf[i] = '\0';
    return i;
}

/* Reads the 16-byte ELF e_ident. Returns 0 on failure. */
static int read_eident(const char *path, char *eident) {
    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return 0;
    long n = syscall3(SYS_read, fd, (long)eident, 16);
    syscall1(SYS_close, fd);
    return n == 16;
}

/* Copies src to an empty file dst(already opened for write) in chunks of
   CHUNK bytes starting from the file's current offset. */
#define COPY_CHUNK 65536
static char copy_buf[COPY_CHUNK];

static long copy_file_contents(long srcfd, long dstfd) {
    long total = 0;
    for (;;) {
        long n = syscall3(SYS_read, srcfd, (long)copy_buf, COPY_CHUNK);
        if (n <= 0) break;
        syscall3(SYS_write, dstfd, (long)copy_buf, n);
        total += n;
    }
    return total;
}

/* AppImage/type-2 ELFs carry a non-zero EI_ABIVERSION (byte 8 of e_ident) AND
   often non-zero padding bytes (e.g. the "AI\x02" signature at bytes 8-10). The
   glibc loader rejects either with "ELF file ABI version invalid" / "nonzero
   padding in e_ident" — before any NEEDED/lib logic. Detect a non-zero byte 8
   and create a patched copy in /tmp/nrld-<pid>/ with bytes 8..15 zeroed so the
   loader accepts the ELF. The AppImage runtime finds its payload via the
   squashfs magic, not these e_ident bytes, so zeroing them is safe. */
static const char *maybe_patch_abi_version(const char *path) {
    char eident[16];
    if (!read_eident(path, eident)) return path;
    if (eident[8] == 0) return path;   /* ABI version fine, load as-is */

    /* Build /tmp/nrld-<pid>/path -> dir + a copy of the file. */
    char tmpdir[4096];
    char pidbuf[24];
    uint_to_str(syscall0(SYS_getpid), pidbuf, sizeof(pidbuf));
    my_strcpy(tmpdir, "/tmp/nrld-");
    my_strcat(tmpdir, pidbuf);
    syscall2(SYS_mkdir, (long)tmpdir, 0700);

    /* Derive the basename of the target to keep a recognizable name. */
    const char *base = path;
    for (const char *p = path; *p; p++) if (*p == '/') base = p + 1;
    my_strcpy(g_patched_bin, tmpdir);
    my_strcat(g_patched_bin, "/");
    my_strcat(g_patched_bin, base);

    long srcfd = syscall2(SYS_open, (long)path, 0);
    if (srcfd < 0) return path;
    /* O_CREAT|O_WRONLY|O_TRUNC = 0100|1|01000 */
    long dstfd = syscall3(SYS_open, (long)g_patched_bin, 0100 | 1 | 01000, 0755);
    if (dstfd < 0) { syscall1(SYS_close, srcfd); return path; }

    copy_file_contents(srcfd, dstfd);

    /* Zero bytes 8..15 (EI_ABIVERSION + EI_PAD) of the e_ident. */
    char zeros[8];
    for (int i = 0; i < 8; i++) zeros[i] = 0;
    syscall3(SYS_lseek, dstfd, 8, 0);
    syscall3(SYS_write, dstfd, (long)zeros, 8);

    syscall1(SYS_close, srcfd);
    syscall1(SYS_close, dstfd);

    print_msg("[ADV] ELF con e_ident no estandar (AppImage/type-2); creada copia parcheada: ");
    print_msg(g_patched_bin);
    print_msg("\n");
    return g_patched_bin;
}

static int can_write_dir(const char *path) {
    return syscall2(SYS_access, (long)path, 2) == 0;
}

/* ------------------------------------------------------------------ */
/*  Pre-flight DT_NEEDED coverage check.                                */
/*  A glibc binary's NEEDED libs must be resolvable within the sysroot  */
/*  (bin_dir + /usr/lib/glibc6/...). If one is missing there, glibc's   */
/*  loader falls back to its compiled-in /usr/lib and pulls a MUSL      */
/*  build in (two libcs in one process -> strtod_l ABI crash, as seen   */
/*  in Firefox over musl Pango/GTK). We surface that here so an app     */
/*  fails with a readable message instead of a confusing SIGSEGV.       */
/* ------------------------------------------------------------------ */
#define SYS_mmap   9
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define DT_NEEDED  1
#define DT_STRTAB  5
#define DT_STRSZ   10
#define DT_SONAME  14

static long read_at(long fd, unsigned long off, char *buf, unsigned long want) {
    if (syscall3(SYS_lseek, fd, off, 0) < 0) return -1;   /* SEEK_SET */
    unsigned long got = 0;
    while (got < want) {
        long n = syscall3(SYS_read, fd, (long)(buf + got), want - got);
        if (n <= 0) break;
        got += (unsigned long)n;
    }
    return (long)got;
}

/* ------------------------------------------------------------------ */
/*  AppImage state. These globals live in nrld.c BEFORE resolve_lib_path
/*  (which searches g_extra_libdirs) and before appimages.c is #included.  */
/* ------------------------------------------------------------------ */
#define MAX_EXTRA_DIRS 16
static char g_appimage_root[4096];
static char g_appimage_bin[4096];
static int  g_appimage_extracted = 0;
static char g_extra_libdirs[MAX_EXTRA_DIRS][4096];
static int  g_extra_libdirs_n = 0;
static char g_qt_plugin_path[4096];

/* extralibfinder (defined in appimages.c, #included later): recursively
   locate a soname inside the glibc sysroot subdirs when it is not at any
   standard dir. Fills `out_dir` with the containing dir; 1 on hit. Only
   sysroot dirs are scanned (never musl /usr) to preserve ABI isolation. */
static int find_lib_in_sysroot(const char *soname, char *out_dir);

/* Resolve a soname to a real file path searching, in order: the lib root
   itself (bin dir / extracted AppImage root), the standard subdirs under it
   (lib, lib64, usr/lib, usr/lib64, usr/lib/<triplet>), the AppImage-internal
   extra lib dirs, and finally the glibc sysroot dirs. Returns 1 and fills
   `out` on success, 0 (and out[0]=0) otherwise. */
static int resolve_lib_path(const char *soname, const char *lib_root, char *out) {
    static const char *subs[] = {
        "", "/bin", "/usr/bin", "/bin/lib", "/bin/lib64", "/usr/bin/lib64", "/usr/bin/lib",
        "/lib", "/lib64", "/usr/lib", "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu", "/usr/lib/i386-linux-gnu"
    };
    for (unsigned int i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        my_strcpy(out, lib_root); my_strcat(out, subs[i]);
        my_strcat(out, "/"); my_strcat(out, soname);
        if (file_exists(out)) return 1;
    }
    for (int i = 0; i < g_extra_libdirs_n; i++) {
        my_strcpy(out, g_extra_libdirs[i]); my_strcat(out, "/"); my_strcat(out, soname);
        if (file_exists(out)) return 1;
    }
    const char *dirs[] = { "/usr/lib/glibc6/usr/lib", "/usr/lib/glibc6/lib" };
    for (int i = 0; i < 2; i++) {
        my_strcpy(out, dirs[i]); my_strcat(out, "/"); my_strcat(out, soname);
        if (file_exists(out)) return 1;
    }

    /* Extralibfinder: a NEEDED lib absent from every standard sysroot dir may
       still live in a non-standard subdir (gvfs/, pulseaudio/, plugin trees).
       Locate it recursively and register its dir, so both this guard and the
       runtime loader (LD_LIBRARY_PATH / --library-path) can resolve it. */
    {
        char extra_dir[4096];
        if (find_lib_in_sysroot(soname, extra_dir)) {
            int already = 0;
            for (int e = 0; e < g_extra_libdirs_n; e++)
                if (my_strcmp(g_extra_libdirs[e], extra_dir) == 0) { already = 1; break; }
            if (!already && g_extra_libdirs_n < MAX_EXTRA_DIRS) {
                my_strcpy(g_extra_libdirs[g_extra_libdirs_n], extra_dir);
                g_extra_libdirs_n++;
            }
            my_strcpy(out, extra_dir);
            my_strcat(out, "/");
            my_strcat(out, soname);
            print_msg("[ADV] Libreria faltante hallada en subdir del sysroot: ");
            print_msg(out);
            print_msg("\n");
            return 1;
        }
    }

    out[0] = '\0';
    return 0;
}

/* Collect the DT_NEEDED sonames of `path` into `names` (up to `max`).
   `offs[i]` (optional) receives the FILE offset of the dynstr string of
   names[i] (for runtime patching); `self_soname` (optional) receives the
   object's own DT_SONAME. Returns the count; returns -1 if the file is not a
   parseable 64-bit ELF with a DT_NEEDED table (treated as "nothing missing"). */
static int get_needed_names(const char *path, char names[][256], int max,
                            long *offs, char *self_soname) {
    char ehdr[64];
    char phdr_buf[16384];
    static char dyn_buf[65536];
    static char str_buf[262144];
    static long needed_off[256];

    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return -1;
    if (read_at(fd, 0, ehdr, 64) < 64) { syscall1(SYS_close, fd); return -1; }
    if (ehdr[4] != 2) { syscall1(SYS_close, fd); return -1; }   /* ELFCLASS64 */

    unsigned long phoff = *(unsigned long *)(ehdr + 32);
    unsigned int phentsize = *(unsigned short *)(ehdr + 54);
    unsigned int phnum = *(unsigned short *)(ehdr + 56);
    if (phentsize < 56 || phnum == 0 || phnum > 256) { syscall1(SYS_close, fd); return -1; }

    unsigned long phsz = (unsigned long)phnum * 56;
    if (phsz > sizeof(phdr_buf)) { syscall1(SYS_close, fd); return -1; }
    if (read_at(fd, phoff, phdr_buf, phsz) < (long)phsz) { syscall1(SYS_close, fd); return -1; }

    unsigned long dyn_off = 0, dyn_sz = 0;
    unsigned long strtab_vaddr = 0, strtab_sz = 0;
    int found_dynamic = 0;
    for (unsigned int i = 0; i < phnum; i++) {
        char *ph = phdr_buf + (long)i * 56;
        if (*(unsigned int *)(ph + 0) == PT_DYNAMIC) {
            dyn_off = *(unsigned long *)(ph + 8);
            dyn_sz  = *(unsigned long *)(ph + 32);
            found_dynamic = 1;
        }
    }
    if (!found_dynamic) { syscall1(SYS_close, fd); return -1; }
    if (dyn_sz > sizeof(dyn_buf)) dyn_sz = sizeof(dyn_buf);
    if (read_at(fd, dyn_off, dyn_buf, dyn_sz) < (long)dyn_sz) { syscall1(SYS_close, fd); return -1; }

    int nneed = 0;
    long soname_idx = -1;
    for (unsigned long off = 0; off + 16 <= dyn_sz; off += 16) {
        long tag = *(long *)(dyn_buf + off);
        long val = *(long *)(dyn_buf + off + 8);
        if (tag == DT_NEEDED) {
            if (nneed < 256) needed_off[nneed++] = val;
        } else if (tag == DT_STRTAB) {
            strtab_vaddr = (unsigned long)val;
        } else if (tag == DT_STRSZ) {
            strtab_sz = (unsigned long)val;
        } else if (tag == DT_SONAME) {
            soname_idx = val;
        } else if (tag == 0) {
            break;
        }
    }
    if (nneed == 0 || strtab_vaddr == 0) { syscall1(SYS_close, fd); return nneed; }

    unsigned long str_off = 0;
    int mapped = 0;
    for (unsigned int i = 0; i < phnum; i++) {
        char *ph = phdr_buf + (long)i * 56;
        if (*(unsigned int *)(ph + 0) != PT_LOAD) continue;
        unsigned long p_off   = *(unsigned long *)(ph + 8);
        unsigned long p_vaddr = *(unsigned long *)(ph + 16);
        unsigned long p_fsz   = *(unsigned long *)(ph + 32);
        if (strtab_vaddr >= p_vaddr && strtab_vaddr < p_vaddr + p_fsz) {
            str_off = p_off + (strtab_vaddr - p_vaddr);
            mapped = 1;
            break;
        }
    }
    syscall1(SYS_close, fd);
    if (!mapped) return -1;
    if (strtab_sz > sizeof(str_buf)) strtab_sz = sizeof(str_buf);
    fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return -1;
    if (read_at(fd, str_off, str_buf, strtab_sz) < (long)strtab_sz) { syscall1(SYS_close, fd); return -1; }
    syscall1(SYS_close, fd);

    int count = 0;
    for (int i = 0; i < nneed && count < max; i++) {
        long o = needed_off[i];
        if (o < 0 || o >= (long)strtab_sz) continue;
        char *sn = str_buf + o;
        if (!sn[0]) continue;
        int slen = 0;
        while (sn[slen] && slen < 255) slen++;
        for (int c = 0; c < slen; c++) names[count][c] = sn[c];
        names[count][slen] = '\0';
        if (offs) offs[count] = (long)(str_off + (unsigned long)o);
        count++;
    }
    if (self_soname) {
        self_soname[0] = '\0';
        if (soname_idx >= 0 && soname_idx < (long)strtab_sz) {
            char *sn = str_buf + soname_idx;
            int j = 0;
            while (j < 255 && sn[j]) { self_soname[j] = sn[j]; j++; }
            self_soname[j] = '\0';
        }
    }
    return count;
}

#define MAX_VISITED 512
#define MAX_NAMES   256
#define MAX_SHADOW  8

/* Runtime fix for DT_NEEDED entries that hard-code an ABSOLUTE path (e.g.
   libtinysparql -> "/usr/lib/libsqlite3.so"). The glibc loader takes such an
   entry literally (it never goes through --library-path / LD_LIBRARY_PATH), so
   it would load the musl /usr/lib build and pull musl libc into the process.
   When the *basename* resolves inside the sysroot, stage a patched copy of the
   CONTAINING object in /tmp/nrld-patch-<pid>/ (named by its SONAME so depended
   objects pick it up first from the search path) with that dynstr string
   rewritten to the resolvable basename. Returns 1 and fills `shadow_out` on
   success, 0 otherwise. */
static char g_patch_dir[4096];
static int  g_patch_dir_set = 0;
static char g_shadow_paths[MAX_SHADOW][4096];
static int  g_shadow_n = 0;
static char g_top_patch[4096];
static char g_patch_env[4096];

static int create_shadow_copy(const char *file, char names[][256],
                              const long *offs, int n, const char *soname,
                              const char *lib_root, char *shadow_out) {
    char pidbuf[24];
    if (!g_patch_dir_set) {
        uint_to_str(syscall0(SYS_getpid), pidbuf, sizeof(pidbuf));
        my_strcpy(g_patch_dir, "/tmp/nrld-patch-");
        my_strcat(g_patch_dir, pidbuf);
        syscall2(SYS_mkdir, (long)g_patch_dir, 0700);
        g_patch_dir_set = 1;
    }
    /* Name the shadow by the object's SONAME, or its basename if it has none
       (executables usually don't). Dependents reference the SONAME. */
    char shadow_base[256];
    if (soname && soname[0]) {
        my_strcpy(shadow_base, soname);
    } else {
        const char *base = file;
        for (const char *p = file; *p; p++) if (*p == '/') base = p + 1;
        my_strcpy(shadow_base, base);
    }
    char dst[4096];
    my_strcpy(dst, g_patch_dir);
    my_strcat(dst, "/");
    my_strcat(dst, shadow_base);
    for (int i = 0; i < g_shadow_n; i++)
        if (my_strcmp(g_shadow_paths[i], dst) == 0) {
            my_strcpy(shadow_out, dst);
            return 1;
        }

    long srcfd = syscall2(SYS_open, (long)file, 0);
    if (srcfd < 0) return 0;
    /* O_CREAT|O_WRONLY|O_TRUNC = 0100|1|01000 */
    long dstfd = syscall3(SYS_open, (long)dst, 0100 | 1 | 01000, 0755);
    if (dstfd < 0) { syscall1(SYS_close, srcfd); return 0; }
    copy_file_contents(srcfd, dstfd);
    syscall1(SYS_close, srcfd);

    /* Zero bytes 8..15 of e_ident so the loader always accepts the copy. */
    char zeros[8];
    for (int i = 0; i < 8; i++) zeros[i] = 0;
    syscall3(SYS_lseek, dstfd, 8, 0);
    syscall3(SYS_write, dstfd, (long)zeros, 8);

    int rewrote = 0;
    for (int i = 0; i < n; i++) {
        if (names[i][0] != '/' || offs[i] <= 0) continue;
        const char *bn = names[i];
        for (const char *p = names[i]; *p; p++) if (*p == '/') bn = p + 1;
        char resolved[4096];
        if (!resolve_lib_path(bn, lib_root, resolved)) continue;
        const char *rb = resolved;
        for (const char *p = resolved; *p; p++) if (*p == '/') rb = p + 1;
        int orig_len = 0;
        while (names[i][orig_len]) orig_len++;
        int rb_len = 0;
        while (rb[rb_len]) rb_len++;
        if (rb_len > orig_len) continue;      /* cannot grow the string */
        syscall3(SYS_lseek, dstfd, (unsigned long)offs[i], 0);
        syscall3(SYS_write, dstfd, (long)rb, (unsigned long)rb_len);
        syscall3(SYS_write, dstfd, (long)zeros, (unsigned long)(orig_len - rb_len));
        rewrote++;
    }
    syscall1(SYS_close, dstfd);
    if (rewrote == 0) {
        syscall2(SYS_unlink, (long)dst, 0);
        return 0;
    }
    if (g_shadow_n < MAX_SHADOW) my_strcpy(g_shadow_paths[g_shadow_n++], dst);
    my_strcpy(shadow_out, dst);
    print_msg("[ADV] NEEDED absoluto resuelto; copia parcheada en: ");
    print_msg(dst);
    print_msg("\n");
    return 1;
}

/* Transitive-closure NEEDED coverage guard. Walks the dependency tree:
   for every shared library resolvable inside the sysroot (bin_dir +
   glibc dirs) it also inspects that library's own DT_NEEDED, so a missing
   musl-only dependency hidden one level down (e.g. libxul.so pulling in
   musl GTK/ICU) is reported too. Returns the number of missing sonames. */
static int scan_missing_libs(const char *top_path, const char *bin_dir) {
    static char queue[256][4096];
    static char visited[MAX_VISITED][256];
    static char names_buf[MAX_NAMES][256];
    static long  offs_buf[MAX_NAMES];
    char self_soname[256];
    int qhead = 0, qtail = 0;
    int visited_n = 0;
    int missing = 0;

    my_strcpy(queue[qtail++], top_path);

    while (qhead < qtail) {
        char *file = queue[qhead++];
        int n = get_needed_names(file, names_buf, MAX_NAMES, offs_buf, self_soname);
        if (n < 0) continue;

        /* Pre-scan: if any absolute NEEDED entry has a basename resolvable
           inside the sysroot, stage a patched shadow copy of this object
           (one copy covers every fixable absolute entry in it). */
        char shadow[4096];
        shadow[0] = '\0';
        for (int i = 0; i < n && shadow[0] == '\0'; i++) {
            if (names_buf[i][0] != '/') continue;
            const char *bn = names_buf[i];
            for (const char *p = names_buf[i]; *p; p++) if (*p == '/') bn = p + 1;
            char r[4096];
            if (resolve_lib_path(bn, bin_dir, r))
                create_shadow_copy(file, names_buf, offs_buf, n, self_soname, bin_dir, shadow);
        }
        /* When the top binary itself needed the fix, the shadow is the patched
           binary to exec (kept for the run_path selection after the guard). */
        if (shadow[0] && my_strcmp(file, top_path) == 0) my_strcpy(g_top_patch, shadow);

        for (int i = 0; i < n; i++) {
            char *soname = names_buf[i];
            int slen = 0;
            while (soname[slen]) slen++;
            if (slen == 0) continue;

            int is_abs = (soname[0] == '/');
            char base_buf[256];
            if (is_abs) {
                /* Absolute REQUIRE + shadow staged -> translate to the basename
                   (rewritten inside the shadow). Without a shadow it is a real
                   hole that no search path can close. */
                const char *bn = soname;
                for (const char *p = soname; *p; p++) if (*p == '/') bn = p + 1;
                int bl = 0;
                while (bn[bl]) bl++;
                for (int c = 0; c <= bl; c++) base_buf[c] = bn[c];
                soname = base_buf;
                slen = bl;
                if (!shadow[0]) {
                    missing++;
                    print_msg("[ADV] Falta la libreria glibc: ");
                    print_msg(soname);
                    print_msg(" (NEEDED absoluto no resoluble)\n");
                    continue;
                }
            }

            char resolved[4096];
            if (!resolve_lib_path(soname, bin_dir, resolved)) {
                missing++;
                print_msg("[ADV] Falta la libreria glibc: ");
                print_msg(soname);
                if (is_abs) print_msg(" (NEEDED absoluto no resoluble)\n");
                else        print_msg(" (caeria a /usr/lib como musl)\n");
                continue;
            }

            /* Skip already-visited sonames (cycle/dedup guard): same length
               and same bytes. */
            int seen = 0;
            for (int v = 0; v < visited_n; v++) {
                int vl = 0;
                while (visited[v][vl]) vl++;
                if (vl != slen) continue;
                int same = 1;
                for (int c = 0; c < slen; c++)
                    if (visited[v][c] != soname[c]) { same = 0; break; }
                if (same) { seen = 1; break; }
            }
            if (seen) continue;

            if (visited_n < MAX_VISITED) {
                for (int c = 0; c <= slen; c++) visited[visited_n][c] = soname[c];
                visited_n++;
            }

            /* Resolves inside the sysroot: inspect its own NEEDED too. */
            if (qtail < 256) my_strcpy(queue[qtail++], resolved);
        }
    }
    return missing;
}

static int check_needed_libs(const char *path, const char *bin_dir) {
    return scan_missing_libs(path, bin_dir);
}


/* Config file for `nrld` default behaviour. If it exists and contains the
   token "strict", strict sysroot mode is enabled so plain `./firefox`
   behaves as NEONATOX_STRICT_SYSROOT=1. Path: /usr/lib/glibc6/etc/nrld.conf */
#define NRLCONF_PATH "/usr/lib/glibc6/etc/nrld.conf"

static int config_enforces_strict(void) {
    if (!file_exists(NRLCONF_PATH)) return 0;
    long fd = syscall2(SYS_open, (long)NRLCONF_PATH, 0);
    if (fd < 0) return 0;
    char buf[1024];
    long n = read_at(fd, 0, buf, sizeof(buf));
    syscall1(SYS_close, fd);
    if (n <= 0) return 0;
    for (long i = 0; i < n; i++) {
        if ((buf[i] == 's' || buf[i] == 'S') &&
            i + 6 < n &&
            (buf[i+1] == 't' || buf[i+1] == 'T') &&
            (buf[i+2] == 'r' || buf[i+2] == 'R') &&
            (buf[i+3] == 'i' || buf[i+3] == 'I') &&
            (buf[i+4] == 'c' || buf[i+4] == 'C') &&
            (buf[i+5] == 't' || buf[i+5] == 'T'))
            return 1;
    }
    return 0;
}

static int resolve_path(const char *relative, char *absolute, int max_len) {
    if (relative[0] == '/') {
        my_strcpy(absolute, relative);
        return 1;
    }
    long ret = syscall2(SYS_getcwd, (long)absolute, max_len);
    if (ret < 0) return 0;
    my_strcat(absolute, "/");
    my_strcat(absolute, relative);
    return 1;
}

static void get_directory(const char *path, char *dir, int max_len) {
    my_strcpy(dir, path);
    char *last_slash = 0;
    for (char *p = dir; *p; p++) {
        if (*p == '/') last_slash = p;
    }
    if (last_slash) *last_slash = '\0';
    else my_strcpy(dir, ".");
}

typedef struct { long a_type; long a_val; } Elf64_auxv_t;
#define AT_NULL    0
#define AT_EXECFN  31

#define REAL_LOADER   "/usr/lib/glibc6/usr/lib/ld-linux-x86-64.so.2"
#define FAKE_LOADER   "/usr/lib/glibc6/usr/bin/nrld"
#define INTERP_PATH   "/lib64/ld-linux-x86-64.so.2"
#define INTERP_TMP    "/lib64/ld-linux-x86-64.so.2.tmp"
#define SYSROOT_LIBS  "/usr/lib/glibc6/usr/lib:/usr/lib/glibc6/lib"
#define GCONV_DIR     "/usr/lib/glibc6/usr/lib/gconv"
#define PROXY_LIB     "/usr/lib/glibc6/lib/libnrld-proxy.so"

/* ------------------------------------------------------------------ */
/*  Interp-patched copy (fixes /proc/self/exe for app-spawned kids).   */
/*  If the real loader is exec'd as the MAIN executable (old user-mode  */
/*  scheme: execve(REAL_LOADER, [--library-path, ...]), the kernel      */
/*  sets /proc/self/exe to the loader. Apps that re-exec their own      */
/*  binary from /proc/self/exe (Firefox/Chromium content processes do   */
/*  this via open+read or a raw readlink syscall, bypassing our inter-  */
/*  posed libc readlink) then re-run the loader AS the program: glibc   */
/*  treats the first non-option argv as the app, fails and exits 1      */
/*  (exactly the "process N exited with status 1" tab storm observed).  */
/*  Fix: produce a COPY of the app in its own directory whose PT_INTERP */
/*  is rewritten to REAL_LOADER (string embedded at EOF, so no length   */
/*  limit). execve the copy: the kernel loads the real loader          */
/*  IN-PROCESS as a normal interp, /proc/self/exe stays the copy (same  */
/*  dir as the app -> omni.ja/icudtl.dat/resources still resolve), and  */
/*  kids re-exec it successfully through any mechanism. Environment     */
/*  (LD_LIBRARY_PATH/LD_PRELOAD/GCONV_PATH/NEONATOX_*) is inherited,    */
/*  so the in-process loader configures itself identically.             */
/*                                                                      */
/*  Each run leaves <dir>/<base>.nrld-<pid> behind (children keep re-   */
/*  exec'ing that exact path). To avoid garbage piling up, the next run */
/*  for the same <base> sweeps old copies: a copy is kept only while    */
/*  some live process still has it as /proc/self/exe (its app tree is   */
/*  running), the rest are unlinked.                                    */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  appimages.c is #included later (line ~866): define the tiny bits   */
/*  needed here so this sweep doesn't depend on it.                    */
/* ------------------------------------------------------------------ */
#ifndef SYS_getdents64
#define SYS_getdents64     217
#endif
#ifndef SYS_readlink
#define SYS_readlink       89
#endif
struct nrl_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

static int nrld_copy_in_use(const char *path) {
    long dfd = syscall2(SYS_open, (long)"/proc", 0);
    if (dfd < 0) return 1;               /* can't check: be conservative */
    char buf[8192];
    int in_use = 0;
    for (;;) {
        long n = syscall3(SYS_getdents64, dfd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (*nm < '0' || *nm > '9') { off += de->d_reclen; continue; }
            char ep[64];
            my_strcpy(ep, "/proc/");
            my_strcat(ep, nm);
            my_strcat(ep, "/exe");
            char rl[4096];
            long m = syscall3(SYS_readlink, (long)ep, (long)rl, sizeof(rl) - 1);
            if (m > 0) {
                rl[m] = '\0';
                if (my_strcmp(rl, path) == 0) { in_use = 1; break; }
            }
            off += de->d_reclen;
        }
        if (in_use) break;
    }
    syscall1(SYS_close, dfd);
    return in_use;
}

static void sweep_stale_interp_copies(const char *src) {
    const char *base = src;
    for (const char *p = src; *p; p++) if (*p == '/') base = p + 1;
    unsigned long base_len = my_strlen(base);
    unsigned long dir_len = (unsigned long)(base - src);
    if (dir_len >= 4096) return;
    char dirbuf[4096];
    for (unsigned long i = 0; i < dir_len; i++) dirbuf[i] = src[i];
    dirbuf[dir_len] = '\0';
    long fd = syscall2(SYS_open, (long)dirbuf, 0);
    if (fd < 0) return;
    char buf[8192];
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (!my_starts_with(nm, base) || !my_starts_with(nm + base_len, ".nrld-")) {
                off += de->d_reclen;
                continue;
            }
            const char *d = nm + base_len + 6;
            int digits = (*d != 0);
            for (const char *q = d; *q; q++) if (*q < '0' || *q > '9') { digits = 0; break; }
            if (!digits) { off += de->d_reclen; continue; }
            char full[4096];
            my_strcpy(full, dirbuf);
            my_strcat(full, "/");
            my_strcat(full, nm);
            if (!nrld_copy_in_use(full)) syscall1(SYS_unlink, (long)full);
            off += de->d_reclen;
        }
    }
    syscall1(SYS_close, fd);
}

static const char *make_interp_patched_copy(const char *src) {
    sweep_stale_interp_copies(src);
    char header[64];
    long fd = syscall2(SYS_open, (long)src, 0);
    if (fd < 0) return 0;
    if (syscall3(SYS_read, fd, (long)header, 64) != 64) {
        syscall1(SYS_close, fd);
        return 0;
    }
    unsigned long e_phoff = *(unsigned long *)(header + 32);
    unsigned long e_phentsize = *(unsigned short *)(header + 54);
    unsigned long e_phnum = *(unsigned short *)(header + 56);
    if (e_phentsize < 56 || e_phnum == 0) { syscall1(SYS_close, fd); return 0; }

    /* Output path: same dir as src -> "<dir>/<base>.nrld-<pid>". */
    const char *base = src;
    for (const char *p = src; *p; p++) if (*p == '/') base = p + 1;
    unsigned long dir_len = (unsigned long)(base - src);
    if (dir_len + my_strlen(base) + 24 >= 4096) { syscall1(SYS_close, fd); return 0; }
    char pidbuf[24];
    uint_to_str(syscall0(SYS_getpid), pidbuf, sizeof(pidbuf));
    unsigned long i;
    for (i = 0; i < dir_len; i++) g_interp_bin[i] = src[i];
    g_interp_bin[dir_len] = '\0';
    my_strcat(g_interp_bin, base);
    my_strcat(g_interp_bin, ".nrld-");
    my_strcat(g_interp_bin, pidbuf);

    long srcfd = syscall2(SYS_open, (long)src, 0);
    if (srcfd < 0) { syscall1(SYS_close, fd); return 0; }
    syscall1(SYS_close, fd);
    long dstfd = syscall3(SYS_open, (long)g_interp_bin, 0100 | 2 | 01000, 0755);
    if (dstfd < 0) { syscall1(SYS_close, srcfd); return 0; }
    long total = copy_file_contents(srcfd, dstfd);
    syscall1(SYS_close, srcfd);
    if (total <= 0) {
        syscall1(SYS_close, dstfd);
        syscall1(SYS_unlink, (long)g_interp_bin);
        return 0;
    }

    /* Find PT_INTERP in the copy and rewrite p_offset/p_filesz/p_memsz to
       point at REAL_LOADER embedded at EOF. */
    long interp_off = -1;
    for (i = 0; i < e_phnum; i++) {
        long off = (long)e_phoff + (long)i * (long)e_phentsize;
        if (syscall3(SYS_lseek, dstfd, off, 0) < 0) break;
        char phdr[56];
        if (syscall3(SYS_read, dstfd, (long)phdr, 56) != 56) break;
        if (*(unsigned int *)phdr == PT_INTERP) { interp_off = off; break; }
    }
    if (interp_off < 0) {
        print_msg("[ADV] Binario sin PT_INTERP (estatico/musl?); se ejecuta via loader como principal\n");
        syscall1(SYS_close, dstfd);
        syscall1(SYS_unlink, (long)g_interp_bin);
        return 0;   /* no PT_INTERP (static binary): fall back to loader-as-main */
    }

    long append_off = total;
    unsigned long ilen = my_strlen(REAL_LOADER) + 1;
    syscall3(SYS_lseek, dstfd, append_off, 0);
    syscall3(SYS_write, dstfd, (long)REAL_LOADER, ilen);

    char w8[8];
    for (int b = 0; b < 8; b++) w8[b] = (char)(((unsigned long)append_off >> (b * 8)) & 0xff);
    syscall3(SYS_lseek, dstfd, interp_off + 8, 0);       /* p_offset */
    syscall3(SYS_write, dstfd, (long)w8, 8);
    for (int b = 0; b < 8; b++) w8[b] = (char)((ilen >> (b * 8)) & 0xff);
    syscall3(SYS_lseek, dstfd, interp_off + 32, 0);      /* p_filesz */
    syscall3(SYS_write, dstfd, (long)w8, 8);
    syscall3(SYS_lseek, dstfd, interp_off + 40, 0);      /* p_memsz */
    syscall3(SYS_write, dstfd, (long)w8, 8);

    syscall1(SYS_close, dstfd);

    print_msg("[ADV] Copia con PT_INTERP -> loader real (exec in-process): ");
    print_msg(g_interp_bin);
    print_msg("\n");
    return g_interp_bin;
}

static char g_new_ld_path[16384];
static char g_gconv[256];
static char g_lib_paths[16384];
static char g_real_exe[4096];
static char g_ld_preload[512];
static char g_strict_env[64];
static char g_appdir_env[512];
static char g_qt_env[1024];

/* AppImage type-2 native handling (detection, unsquashfs extraction to /tmp,
   internal binary discovery, lib-subdir collection). Uses the syscall/string
   helpers above and the g_appimage_* / g_extra_libdirs globals. */
#include "appimages.c"

static void print_usage_help(void) {
    print_msg("NeonatoX RLDispatcher (nrld) -- fake glibc linker para hosts musl\n");
    print_msg("\n");
    print_msg("Aisla binarios glibc de las librerias musl de /usr/lib, ejecutandolos\n");
    print_msg("con un glibc real y autosuficiente dentro de /usr/lib/glibc6 (sysroot).\n");
    print_msg("\n");
    print_msg("Uso:\n");
    print_msg("  nrld --help                        Muestra esta ayuda (modo verboso)\n");
    print_msg("  nrld BIN [ARGOS...]                Ejecuta BIN glibc sobre el sysroot\n");
    print_msg("  (instalado como /lib64/ld-linux-x86-64.so.2: los binarios con ese\n");
    print_msg("   PT_INTERP se ejecutan solos con ./BIN, sin invocar nrld a mano)\n");
    print_msg("\n");
    print_msg("Que hace con BIN:\n");
    print_msg("  1. Detecta el binario real (AT_EXECFN o argv[1]) y exige que sea ELF.\n");
    print_msg("  2. AppImage type-2: extrae el squashfs a /tmp/nrld-appimage-<pid>/\n");
    print_msg("     (sin FUSE, nunca escribe fuera de /tmp) y usa el binario interno\n");
    print_msg("     mas sus dirs de librerias internas (lib/, usr/lib/<triplet>, ...).\n");
    print_msg("  3. Guard transitivo de DT_NEEDED: verifica que cada libreria necesitada\n");
    print_msg("     (y las de sus dependencias) resuelve dentro del sysroot glibc.\n");
    print_msg("  4. Extralibfinder: si un soname falta en los dirs estandar, lo busca\n");
    print_msg("     en subdirectorios no estandar del sysroot (gvfs/, pulseaudio/, ...)\n");
    print_msg("     y anade ese dir a LD_LIBRARY_PATH / --library-path.\n");
    print_msg("  5. Corrige DT_NEEDED absolutos creando copias parcheadas en\n");
    print_msg("     /tmp/nrld-<pid>/ (traducidos a soname resoluble por --library-path).\n");
    print_msg("  6. Executa una copia parcheada de BIN en su propio directorio cuyo\n");
    print_msg("     PT_INTERP apunta al loader glibc real (cargado in-process por el\n");
    print_msg("     kernel): /proc/self/exe queda en el dir de la app, los hijos que\n");
    print_msg("     re-ejecutan su propio binario funcionan. LD_PRELOAD con el proxy\n");
    print_msg("     libnrld-proxy.so (scan strict de dlopen).\n");
    print_msg("\n");
    print_msg("Modo estricto del sysroot (aislacion musl<->glibc):\n");
    print_msg("  NEONATOX_STRICT_SYSROOT=1 ./BIN    falla limpio si falta algo\n");
    print_msg("  echo strict > /etc/nrld.conf       hace estricto todo (sin env)\n");
    print_msg("  (evita la mezcla de dos libcs en un proceso -> el SIGSEGV de strtod_l)\n");
    print_msg("\n");
    print_msg("Variables de entorno que nrld importa/exporta:\n");
    print_msg("  NEONATOX_STRICT_SYSROOT   strict por env (0/1)\n");
    print_msg("  NEONATOX_REAL_EXE         ruta real del binario (la lee el proxy)\n");
    print_msg("  NEONATOX_APPDIR           raiz extraida de un AppImage\n");
    print_msg("  NEONATOX_DUMPENV          dump del entorno del hijo a /tmp (debug)\n");
    print_msg("  QT_PLUGIN_PATH            dir del plugin de plataforma Qt (si aplica)\n");
    print_msg("\n");
    print_msg("Salida (modo verboso por defecto):\n");
    print_msg("  [DEBUG] razonamiento interno      [ADV] avisos (faltantes/extraccion)\n");
    print_msg("  [INFO]  cambios de config         [OK]  todas las NEEDED en el sysroot\n");
    print_msg("  [ERROR] fallo (solo en strict)    [neonatox] mensajes del proxy\n");
    print_msg("\n");
    print_msg("Copyright (C) 2026 Carlos Sanchez. Licencia GPL v3.\n");
}

void _start_main(long *sp) {
    long argc = sp[0];
    char **argv = (char **)&sp[1];
    char **envp = &argv[argc + 1];

    /* El Parent de Firefox avisa con el PID de cada hijo que muere; poner el
       pid aqui permite correlacionar los warnings con la instancia de nrld. */
    char pidb[16];
    uint_to_str(syscall0(SYS_getpid), pidb, sizeof(pidb));
    print_msg("[DEBUG] NeonatoX iniciado (pid ");
    print_msg(pidb);
    print_msg(")\n");

    char **envp_end = envp;
    while (*envp_end) envp_end++;
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)(envp_end + 1);

    char *execfn = 0;
    for (Elf64_auxv_t *a = auxv; a->a_type != AT_NULL; a++) {
        if (a->a_type == AT_EXECFN) {
            execfn = (char *)a->a_val;
            break;
        }
    }

    char *target_bin;
    int orig_args_start;
    /* As an ELF PT_INTERP, the kernel replaces argv[0] with our path and leaves
       argv[1] as the user's FIRST app argument, NOT the target binary. The real
       binary is always available via AT_EXECFN. Manual mode only applies when
       nrld itself was invoked directly (`nrld BIN ARGS...`) and argv[1] is not a
       flag. Distinguish by AT_EXECFN: loading us as PT_INTERP means execfn names
       the app binary (e.g. firefox-bin); launching nrld directly means execfn is
       nrld itself. Without this, a plain numeric argv[1] (Firefox passes a
       parent PID) was mistaken for a target path -> "Binario no existe". */;
    int nrld_launched = 0;
    if (execfn) {
        const char *b = execfn;
        for (const char *p = execfn; *p; p++) if (*p == '/') b = p + 1;
        nrld_launched = my_starts_with(b, "nrld");
    }
    int manual = (argc >= 2 && argv[1][0] != '-' && nrld_launched);
    if (nrld_launched && argc >= 2 &&
        (my_strcmp(argv[1], "--help") == 0 || my_strcmp(argv[1], "-h") == 0)) {
        print_usage_help();
        syscall1(SYS_exit, 0);
        return;
    }
    if (manual) {
        target_bin = argv[1];
        orig_args_start = 2;
        print_msg("[DEBUG] Modo manual (argv[1] es path)\n");
    } else if (execfn) {
        target_bin = execfn;
        orig_args_start = 1;
        print_msg("[DEBUG] Modo directo (usando AT_EXECFN)\n");
    } else {
        print_err("[DEBUG] ERROR: No se pudo determinar el binario\n");
        syscall1(SYS_exit, 1);
        return;
    }

    print_msg("[DEBUG] Target original: ");
    print_msg(target_bin);
    print_msg("\n");

    char target_bin_abs[4096];
    if (!resolve_path(target_bin, target_bin_abs, sizeof(target_bin_abs))) {
        print_err("[DEBUG] ERROR: No se pudo resolver ruta\n");
        syscall1(SYS_exit, 1);
        return;
    }

    print_msg("[DEBUG] Ruta absoluta: ");
    print_msg(target_bin_abs);
    print_msg("\n");

    // DEBUG: Verificar si el archivo existe antes de llamar file_exists
    long access_ret = syscall2(SYS_access, (long)target_bin_abs, 0);
    print_msg("[DEBUG] access() retornó: ");
    char ret_buf[32];
    int ret_len = 0;
    long temp = access_ret;
    if (temp < 0) {
        print_msg("-");
        temp = -temp;
    }
    if (temp == 0) {
        ret_buf[ret_len++] = '0';
    } else {
        char digits[20];
        int dlen = 0;
        while (temp > 0) {
            digits[dlen++] = '0' + (temp % 10);
            temp /= 10;
        }
        for (int i = dlen - 1; i >= 0; i--) {
            ret_buf[ret_len++] = digits[i];
        }
    }
    ret_buf[ret_len] = '\0';
    print_msg(ret_buf);
    print_msg("\n");

    if (!file_exists(target_bin_abs)) {
        print_err("[DEBUG] ERROR: Binario no existe: ");
        print_err(target_bin_abs);
        print_err("\n");
        syscall1(SYS_exit, 1);
        return;
    }

    print_msg("[DEBUG] Binario existe, continuando...\n");

    if (!is_elf(target_bin_abs)) {
        print_msg("[DEBUG] No es un ELF, no es nuestro: ");
        print_msg(target_bin_abs);
        print_msg("\n");
        syscall1(SYS_exit, 0);
        return;
    }

    char bin_dir[4096];
    get_directory(target_bin_abs, bin_dir, sizeof(bin_dir));

    print_msg("[DEBUG] Directorio: ");
    print_msg(bin_dir);
    print_msg("\n");

    /* Pre-flight NEEDED coverage: warn (or hard-fail in strict mode) if a
       NEEDED lib cannot be satisfied from the sysroot and would fall back
       to a musl /usr/lib copy (the ABI-mixing root cause of the crashes). */
    int sysroot_strict = 0;
    int strict_in_env = 0;
    for (char **e = envp; *e; e++) {
        if (my_starts_with(*e, "NEONATOX_STRICT_SYSROOT=1")) { sysroot_strict = 1; strict_in_env = 1; break; }
    }
    if (!sysroot_strict && config_enforces_strict()) {
        sysroot_strict = 1;
        print_msg("[INFO] Modo estricto activado por " NRLCONF_PATH "\n");
    }
    /* When strict came from the config file (not the inherited env), the proxy
       reads NEONATOX_STRICT_SYSROOT to enable its dlopen interposition. Without
       it the child would run the proxy in non-strict mode -> musl ABI mixing.
       Build the string now; it's appended to new_envp only if not already
       inherited (the generic env-copy loop already carries an inherited copy). */
    my_strcpy(g_strict_env, "NEONATOX_STRICT_SYSROOT=1");

    /* AppImage type-2 native handling: extract the embedded squashfs to /tmp
       with the host's musl `unsquashfs` and run the internal binary instead of
       the AppImage stub. No FUSE, never writes outside /tmp, musl host tools
       are not contaminated. If extraction is impossible we fall back to the
       bare-ELF path (ABI patch) below. */
    const char *lib_root = bin_dir;
    const char *guard_bin = target_bin_abs;
    const char *real_exe = target_bin_abs;
    if (is_appimage(target_bin_abs)) {
        print_msg("[ADV] AppImage detectada; extrayendo con unsquashfs...\n");
        if (extract_appimage(target_bin_abs)) {
            lib_root = g_appimage_root;
            guard_bin = g_appimage_bin;
            real_exe = g_appimage_bin;
            print_msg("[ADV] Extraida en: ");
            print_msg(g_appimage_root);
            print_msg("\n[ADV] Binario interno: ");
            print_msg(g_appimage_bin);
            print_msg("\n");
            if (g_extra_libdirs_n > 0) {
                print_msg("[ADV] Libs internas en: ");
                for (int i = 0; i < g_extra_libdirs_n; i++) {
                    if (i) print_msg(", ");
                    print_msg(g_extra_libdirs[i]);
                }
                print_msg("\n");
            }
        } else {
            print_msg("[ADV] No se pudo extraer; intento con el ELF como esta\n");
        }
    }

    {
        int missing = check_needed_libs(guard_bin, lib_root);
        if (missing > 0 && sysroot_strict) {
            print_err("[ERROR] Sysroot glibc incompleto: faltan librerias que caerian a /usr/lib (musl)\n");
            print_err("[ERROR] Instala las librerias glibc faltantes en /usr/lib/glibc6/usr/lib\n");
            syscall1(SYS_exit, 1);
            return;
        }
        if (sysroot_strict && !missing) {
            print_msg("[OK] Todas las NEEDED del binario estan en el sysroot glibc\n");
        }
    }

    /* If the ELF to run still carries EI_ABIVERSION != 0 (only reached when
       extraction fell back, or for odd internal binaries), the glibc loader
       rejects it ("ELF file ABI version invalid"). Produce a patched copy to
       run instead. Keep the real path for NEONATOX_REAL_EXE. */
    const char *run_path = maybe_patch_abi_version(g_top_patch[0] ? g_top_patch : real_exe);

    char *existing_ld_path = 0;
    int clean_count = 0;

    for (char **e = envp; *e; e++) {
        if (my_starts_with(*e, "LD_LIBRARY_PATH=")) {
            existing_ld_path = *e + 16;
        } else if (!my_starts_with(*e, "LD_PRELOAD=") &&
                   !my_starts_with(*e, "LD_AUDIT=") &&
                   !my_starts_with(*e, "LD_BIND_NOW=") &&
                   !my_starts_with(*e, "LD_DEBUG=") &&
                   !my_starts_with(*e, "LD_TRACE_LOADED_OBJECTS=") &&
                   !my_starts_with(*e, "LD_USE_LOAD_BIAS=")) {
            clean_count++;
        }
    }

    my_strcpy(g_new_ld_path, "LD_LIBRARY_PATH=");
    if (g_patch_dir_set) {
        /* Patched shadows must win over the sysroot copies. */
        my_strcat(g_new_ld_path, g_patch_dir);
        my_strcat(g_new_ld_path, ":");
    }
    my_strcat(g_new_ld_path, lib_root);
    append_lib_subdirs(g_new_ld_path, lib_root);
    my_strcat(g_new_ld_path, ":");
    my_strcat(g_new_ld_path, SYSROOT_LIBS);
    if (existing_ld_path) {
        my_strcat(g_new_ld_path, ":");
        my_strcat(g_new_ld_path, existing_ld_path);
    }

    my_strcpy(g_gconv, "GCONV_PATH=");
    my_strcat(g_gconv, GCONV_DIR);

    my_strcpy(g_lib_paths, "");
    if (g_patch_dir_set) {
        my_strcpy(g_lib_paths, g_patch_dir);
        my_strcat(g_lib_paths, ":");
    }
    my_strcat(g_lib_paths, lib_root);
    append_lib_subdirs(g_lib_paths, lib_root);
    my_strcat(g_lib_paths, ":");
    my_strcat(g_lib_paths, SYSROOT_LIBS);

    my_strcpy(g_real_exe, "NEONATOX_REAL_EXE=");
    my_strcat(g_real_exe, real_exe);

    if (g_patch_dir_set) {
        /* Allow the proxy (which enforces the sysroot dlopen allowlist) to
           accept objects loaded from the patch dir too. */
        my_strcpy(g_patch_env, "NEONATOX_PATCH_DIR=");
        my_strcat(g_patch_env, g_patch_dir);
    }

    if (g_appimage_extracted) {
        /* Allow the proxy to accept objects loaded from the extracted
           AppImage tree (/tmp/nrld-appimage-<pid>/). */
        my_strcpy(g_appdir_env, "NEONATOX_APPDIR=");
        my_strcat(g_appdir_env, g_appimage_root);
        if (g_qt_plugin_path[0]) {
            /* Qt: tell the app where its platform/imageformats plugins live
               (<QT_PLUGIN_PATH>/platforms/libqxcb.so). */
            my_strcpy(g_qt_env, "QT_PLUGIN_PATH=");
            my_strcat(g_qt_env, g_qt_plugin_path);
        }
    }

    my_strcpy(g_ld_preload, "LD_PRELOAD=");
    my_strcat(g_ld_preload, PROXY_LIB);

    char *new_envp[clean_count + 9];
    int env_idx = 0;

    for (char **e = envp; *e; e++) {
        if (!my_starts_with(*e, "LD_PRELOAD=") &&
            !my_starts_with(*e, "LD_AUDIT=") &&
            !my_starts_with(*e, "LD_BIND_NOW=") &&
            !my_starts_with(*e, "LD_DEBUG=") &&
            !my_starts_with(*e, "LD_TRACE_LOADED_OBJECTS=") &&
            !my_starts_with(*e, "LD_USE_LOAD_BIAS=") &&
            !my_starts_with(*e, "LD_LIBRARY_PATH=") &&
            !my_starts_with(*e, "LOCPATH=")) {
            new_envp[env_idx++] = *e;
        }
    }
    new_envp[env_idx++] = g_new_ld_path;
    new_envp[env_idx++] = g_gconv;
    new_envp[env_idx++] = g_real_exe;
    new_envp[env_idx++] = g_ld_preload;
    if (sysroot_strict && !strict_in_env) {
        new_envp[env_idx++] = g_strict_env;
    }
    if (g_patch_env[0]) {
        new_envp[env_idx++] = g_patch_env;
    }
    if (g_appdir_env[0]) {
        new_envp[env_idx++] = g_appdir_env;
    }
    if (g_qt_env[0]) {
        new_envp[env_idx++] = g_qt_env;
    }
    new_envp[env_idx] = (char *)0;

    int orig_argc = argc - orig_args_start;

    int have_root = can_write_dir("/lib64");
    
    print_msg("[DEBUG] Permisos root: ");
    print_msg(have_root ? "SI\n" : "NO\n");

    if (have_root) {
        print_msg("[DEBUG] Modo ROOT: fork + swap symlink\n");
        long pid = syscall1(SYS_fork, 0);

        if (pid < 0) {
            print_err("[DEBUG] ERROR: fork falló\n");
            syscall1(SYS_exit, 1);
            return;
        }

        if (pid == 0) {
            syscall2(SYS_unlink, (long)INTERP_TMP, 0);
            if (syscall2(SYS_symlink, (long)REAL_LOADER, (long)INTERP_TMP) < 0) {
                print_err("[DEBUG] HIJO ERROR: symlink falló\n");
                syscall1(SYS_exit, 1);
                return;
            }
            if (syscall2(SYS_rename, (long)INTERP_TMP, (long)INTERP_PATH) < 0) {
                print_err("[DEBUG] HIJO ERROR: rename falló\n");
                syscall1(SYS_exit, 1);
                return;
            }

            char *bin_argv[orig_argc + 2];
            bin_argv[0] = (char *)run_path;
            for (int i = 0; i < orig_argc; i++) {
                bin_argv[1 + i] = argv[orig_args_start + i];
            }
            bin_argv[orig_argc + 1] = (char *)0;

            print_msg("[DEBUG] HIJO: execve a ");
            print_msg(bin_argv[0]);
            print_msg("\n");

            syscall3(SYS_execve, (long)bin_argv[0], (long)bin_argv, (long)new_envp);
            
            print_err("[DEBUG] HIJO ERROR: execve falló\n");
            syscall2(SYS_unlink, (long)INTERP_TMP, 0);
            syscall2(SYS_symlink, (long)FAKE_LOADER, (long)INTERP_TMP);
            syscall2(SYS_rename, (long)INTERP_TMP, (long)INTERP_PATH);
            syscall1(SYS_exit, 1);
            return;
        }

        int status = 0;
        syscall4(SYS_wait4, pid, (long)&status, 0, 0);

        syscall2(SYS_unlink, (long)INTERP_TMP, 0);
        syscall2(SYS_symlink, (long)FAKE_LOADER, (long)INTERP_TMP);
        syscall2(SYS_rename, (long)INTERP_TMP, (long)INTERP_PATH);

        int exit_code = (status >> 8) & 0xFF;
        syscall1(SYS_exit, exit_code);
        return;
    }

    print_msg("[DEBUG] Modo USUARIO: exec de copia con PT_INTERP -> loader real in-process\n");

    const char *interp_run = make_interp_patched_copy(run_path);
    if (interp_run) {
        char *bin_argv[orig_argc + 4];
        bin_argv[0] = (char *)run_path;
        for (int i = 0; i < orig_argc; i++) {
            bin_argv[1 + i] = argv[orig_args_start + i];
        }
        bin_argv[orig_argc + 1] = (char *)0;

        print_msg("[DEBUG] Ejecutando copia parcheada: ");
        print_msg(interp_run);
        print_msg("\n");

        long ret = syscall3(SYS_execve, (long)interp_run, (long)bin_argv, (long)new_envp);
        if (ret >= 0) return;

        print_err("[DEBUG] ERROR: execve de la copia falló; reintento con el loader real\n");
        syscall1(SYS_unlink, (long)interp_run);
    } else {
        print_msg("[DEBUG] No se pudo crear la copia (dir no escribible?); loader como principal\n");
    }

    print_msg("[DEBUG] Modo USUARIO: execve directo al loader real con LD_PRELOAD\n");
    
    char *loader_argv[orig_argc + 5];
    loader_argv[0] = REAL_LOADER;
    loader_argv[1] = "--library-path";
    loader_argv[2] = g_lib_paths;
    loader_argv[3] = (char *)run_path;
    for (int i = 0; i < orig_argc; i++) {
        loader_argv[4 + i] = argv[orig_args_start + i];
    }
    loader_argv[orig_argc + 4] = (char *)0;

    print_msg("[DEBUG] Ejecutando: ");
    print_msg(REAL_LOADER);
    print_msg(" --library-path ");
    print_msg(g_lib_paths);
    print_msg(" ");
    print_msg(run_path);
    print_msg("\n");

    long ret = syscall3(SYS_execve, (long)loader_argv[0], (long)loader_argv, (long)new_envp);

    print_err("[DEBUG] ERROR: execve falló con código ");
    char err_buf[32];
    int err_len = 0;
    temp = -ret;
    if (temp == 0) {
        err_buf[err_len++] = '0';
    } else {
        char digits[20];
        int dlen = 0;
        while (temp > 0) {
            digits[dlen++] = '0' + (temp % 10);
            temp /= 10;
        }
        for (int i = dlen - 1; i >= 0; i--) {
            err_buf[err_len++] = digits[i];
        }
    }
    err_buf[err_len] = '\0';
    print_err(err_buf);
    print_err("\n");

    syscall1(SYS_exit, 1);
}

__asm__(
    ".global _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "    mov %rsp, %rdi\n"
    "    and $0xfffffffffffffff0, %rsp\n"
    "    call _start_main\n"
    "    mov $60, %rax\n"
    "    xor %rdi, %rdi\n"
    "    syscall\n"
);
