/* appimages.c -- AppImage type-2 native handling for nrld.
   Included from nrld.c (freestanding mode, -nostdlib). Detects a type-2
   AppImage (non-zero EI_ABIVERSION + embedded squashfs), extracts it to
   /tmp/nrld-appimage-<pid>/ using the host's musl `unsquashfs` (never
   writes outside /tmp), locates the real internal ELF binary and collects
   the internal library dirs (lib/, usr/lib/, usr/lib/<triplet>, plugins/ ...)
   so the loader can resolve the app's own libs without touching musl /usr. */

#define APPDIR_PREFIX      "/tmp/nrld-appimage-"
#define MAX_SCAN_DIRS      512
#define HUNT_CHUNK         65536

/* The AppImage globals themselves live in nrld.c (before resolve_lib_path);
   this module is #included after them and only uses them. */

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

#define SYS_getdents64     217
#define SYS_readlink       89

static char scan_path_buf[4096];

/* Scan the file backward for the rightmost "hsqs" (squashfs) magic. */
static long get_squashfs_offset(const char *path) {
    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return -1;
    long end = syscall3(SYS_lseek, fd, 0, 2);
    if (end < 0) { syscall1(SYS_close, fd); return -1; }
    long found = -1;
    long pos = end;
    static char chunk[HUNT_CHUNK];
    while (pos > 0) {
        long want = (pos >= HUNT_CHUNK) ? HUNT_CHUNK : pos;
        long start = pos - want;
        if (syscall3(SYS_lseek, fd, start, 0) < 0) break;
        long got = syscall3(SYS_read, fd, (long)chunk, want);
        if (got <= 0) break;
        long best = -1;
        for (long i = 0; i + 4 <= got; i++) {
            if (chunk[i] == 'h' && chunk[i+1] == 's' &&
                chunk[i+2] == 'q' && chunk[i+3] == 's')
                best = i;
        }
        if (best >= 0) { found = start + best; break; }
        pos = start;
    }
    syscall1(SYS_close, fd);
    return found;
}

/* AppImage type-2: non-standard e_ident + an embedded squashfs. */
static int is_appimage(const char *path) {
    char eid[16];
    if (!read_eident(path, eid)) return 0;
    if (eid[8] == 0) return 0;
    return get_squashfs_offset(path) >= 0;
}

static int name_is_so(const char *name) {
    unsigned int len = 0;
    while (name[len] && len < 200) len++;
    for (unsigned int i = 0; i + 3 <= len; i++) {
        if (name[i] == '.' && name[i+1] == 's' && name[i+2] == 'o') {
            unsigned int j = i + 3;
            int ok = 1;
            for (; j < len; j++) {
                char c = name[j];
                if (!((c >= '0' && c <= '9') || c == '.')) { ok = 0; break; }
            }
            if (ok) return 1;
        }
    }
    return 0;
}

static int dir_has_so(const char *dir) {
    long fd = syscall2(SYS_open, (long)dir, 0);
    if (fd < 0) return 0;
    char buf[8192];
    int found = 0;
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            if ((de->d_type & 0xf) == 8 && name_is_so(de->d_name)) { found = 1; break; }
            off += de->d_reclen;
        }
        if (found) break;
    }
    syscall1(SYS_close, fd);
    return found;
}

/* Recursively collect (to depth 3) every dir under `root` that contains a
   shared object, bounded by MAX_EXTRA_DIRS / MAX_SCAN_DIRS. */
static int collect_scan_count = 0;

static void collect_libdirs_rec(const char *dir, int depth) {
    if (depth > 3) return;
    if (g_extra_libdirs_n >= MAX_EXTRA_DIRS) return;
    if (collect_scan_count++ >= MAX_SCAN_DIRS) return;
    long fd = syscall2(SYS_open, (long)dir, 0);
    if (fd < 0) return;
    char buf[8192];
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            if ((de->d_type & 0xf) == 4) {          /* DT_DIR */
                my_strcpy(scan_path_buf, dir);
                my_strcat(scan_path_buf, "/");
                my_strcat(scan_path_buf, nm);
                if (dir_has_so(scan_path_buf) && g_extra_libdirs_n < MAX_EXTRA_DIRS) {
                    my_strcpy(g_extra_libdirs[g_extra_libdirs_n], scan_path_buf);
                    g_extra_libdirs_n++;
                }
                collect_libdirs_rec(scan_path_buf, depth + 1);
            }
            off += de->d_reclen;
        }
        if (g_extra_libdirs_n >= MAX_EXTRA_DIRS) break;
    }
    syscall1(SYS_close, fd);
}

/* Find a Qt "platforms" plugin dir (a subdir literally named 'platforms'
   containing a shared object) below `root`, depth <= 3. Qt searches for
   platform plugins at <QT_PLUGIN_PATH>/platforms/, so g_qt_plugin_path must
   receive the PLUGIN PARENT (the dir that contains 'platforms'). First hit
   wins (loosest binding comes first at the top level). */
static void collect_qt_plugins_rec(const char *dir, int depth) {
    if (g_qt_plugin_path[0] || depth > 3) return;
    long fd = syscall2(SYS_open, (long)dir, 0);
    if (fd < 0) return;
    char buf[8192];
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            if ((de->d_type & 0xf) == 4) {
                /* Local buffer per call: the recursion must not overwrite the
                   path the caller is still iterating (a shared static buffer
                   broke sibling entries after a deep call, so /usr/bin was
                   never reached and QT_PLUGIN_PATH stayed empty). */
                char child[4096];
                my_strcpy(child, dir);
                my_strcat(child, "/");
                my_strcat(child, nm);
                if (my_strcmp(nm, "platforms") == 0 && dir_has_so(child)) {
                    my_strcpy(g_qt_plugin_path, dir);
                    syscall1(SYS_close, fd);
                    return;
                }
                collect_qt_plugins_rec(child, depth + 1);
                if (g_qt_plugin_path[0]) { syscall1(SYS_close, fd); return; }
            }
            off += de->d_reclen;
        }
    }
    syscall1(SYS_close, fd);
}

static void collect_qt_plugin_dir(const char *root) {
    g_qt_plugin_path[0] = '\0';
    collect_qt_plugins_rec(root, 0);
}

/* extralibfinder (forward-declared in nrld.c): depth-bounded search for a
   file named exactly `want` under `root`, preferring the shallowest hit.
   Only true ELF files count; symlinks (dev packages) are followed. Local
   buffer per call so an entry name never aliases a deeper frame's path. */
static int find_lib_under(const char *root, const char *want, char *dir_out, int depth) {
    if (depth > 3) return 0;
    long fd = syscall2(SYS_open, (long)root, 0);
    if (fd < 0) return 0;
    char buf[8192];
    int hit = 0;
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            int t = de->d_type & 0xf;
            if (t == 8 || t == 10) {                 /* DT_REG / DT_LNK */
                if (my_strcmp(nm, want) == 0) {
                    char fp[4096];
                    my_strcpy(fp, root);
                    my_strcat(fp, "/");
                    my_strcat(fp, nm);
                    if (is_elf(fp)) { my_strcpy(dir_out, root); hit = 1; break; }
                }
            } else if (t == 4) {                     /* DT_DIR */
                char child[4096];
                my_strcpy(child, root);
                my_strcat(child, "/");
                my_strcat(child, nm);
                if (find_lib_under(child, want, dir_out, depth + 1)) { hit = 1; break; }
            }
            off += de->d_reclen;
        }
        if (hit) break;
    }
    syscall1(SYS_close, fd);
    return hit;
}

static int find_lib_in_sysroot(const char *want, char *dir_out) {
    const char *roots[] = { "/usr/lib/glibc6/usr/lib", "/usr/lib/glibc6/lib" };
    for (int i = 0; i < 2; i++)
        if (find_lib_under(roots[i], want, dir_out, 0)) return 1;
    return 0;
}

static int ends_with(const char *s, const char *suf) {
    unsigned int sl = 0, fl = 0;
    while (s[sl]) sl++;
    while (suf[fl]) fl++;
    if (fl > sl) return 0;
    for (unsigned int i = 0; i < fl; i++)
        if (s[sl - fl + i] != suf[i]) return 0;
    return 1;
}

/* First ELF executable file inside `dir`; optional `.bin` suffix match. */
static int find_elf_exec_in(const char *dir, const char *suffix, char *out) {
    long fd = syscall2(SYS_open, (long)dir, 0);
    if (fd < 0) return 0;
    char buf[8192];
    int found = 0;
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            if ((de->d_type & 0xf) == 8) {          /* DT_REG */
                if (suffix && !ends_with(nm, suffix)) {
                    off += de->d_reclen; continue;
                }
                my_strcpy(scan_path_buf, dir);
                my_strcat(scan_path_buf, "/");
                my_strcat(scan_path_buf, nm);
                if (is_elf(scan_path_buf) &&
                    syscall2(SYS_access, (long)scan_path_buf, 1) == 0) { /* X_OK */
                    my_strcpy(out, scan_path_buf);
                    found = 1;
                    break;
                }
            }
            off += de->d_reclen;
        }
        if (found) break;
    }
    syscall1(SYS_close, fd);
    return found;
}

/* Determine the real internal binary to exec:
   1. AppRun symlink -> ELF target (OCAT-style)
   2. top-level *.bin (Electron-style, e.g. balena-etcher.bin)
   3. usr/bin or other standard bin dirs
   4. any top-level ELF executable */
static int find_internal_bin(const char *root, char *out) {
    char p[4096], target[4096];
    my_strcpy(p, root); my_strcat(p, "/AppRun");
    {
        char link[4096];
        long rn = syscall3(SYS_readlink, (long)p, (long)link, sizeof(link) - 1);
        if (rn > 0) {
            link[rn] = '\0';
            if (link[0] == '/') my_strcpy(target, link);
            else { my_strcpy(target, root); my_strcat(target, "/"); my_strcat(target, link); }
            if (is_elf(target)) { my_strcpy(out, target); return 1; }
        }
    }
    if (find_elf_exec_in(root, ".bin", out)) return 1;
    static const char *dirs[] = { "usr/bin", "bin", "sbin", "usr/libexec", "usr/sbin" };
    for (int i = 0; i < 5; i++) {
        my_strcpy(p, root); my_strcat(p, "/"); my_strcat(p, dirs[i]);
        if (find_elf_exec_in(p, 0, out)) return 1;
    }
    return find_elf_exec_in(root, 0, out);
}

/* Extract the AppImage squashfs to /tmp via the host's unsquashfs and locate
   the internal binary + lib dirs. Returns 1 on success (g_appimage_bin set). */
static int extract_appimage(const char *path) {
    long off = get_squashfs_offset(path);
    if (off < 0) return 0;

    char pidbuf[24];
    uint_to_str(syscall0(SYS_getpid), pidbuf, sizeof(pidbuf));
    my_strcpy(g_appimage_root, APPDIR_PREFIX);
    my_strcat(g_appimage_root, pidbuf);
    syscall2(SYS_mkdir, (long)g_appimage_root, 0700);

    char offbuf[24];
    uint_to_str(off, offbuf, sizeof(offbuf));

    long pid = syscall1(SYS_fork, 0);
    if (pid < 0) return 0;

    if (pid == 0) {
        char *argv[] = {
            (char *)"/usr/bin/unsquashfs", (char *)"-f", (char *)"-d",
            g_appimage_root, (char *)"-o", offbuf, (char *)path, (char *)0
        };
        char *envp[] = { (char *)"PATH=/usr/bin:/bin", (char *)0 };
        syscall3(SYS_execve, (long)"/usr/bin/unsquashfs", (long)argv, (long)envp);
        syscall1(SYS_exit, 127);
        return 0; /* unreachable */
    }

    int status = 0;
    syscall4(SYS_wait4, pid, (long)&status, 0, 0);
    if (((status >> 8) & 0xFF) != 0) return 0;

    if (!find_internal_bin(g_appimage_root, g_appimage_bin)) {
        /* Last resort: try the AppRun itself (must be a real ELF). */
        my_strcpy(g_appimage_bin, g_appimage_root);
        my_strcat(g_appimage_bin, "/AppRun");
    }

    collect_scan_count = 0;
    g_extra_libdirs_n = 0;
    collect_libdirs_rec(g_appimage_root, 0);
    collect_qt_plugin_dir(g_appimage_root);

    g_appimage_extracted = 1;
    return 1;
}

/* Append the internal lib dirs of `root` (standard subdirs that exist +
   the collected g_extra_libdirs) to a ':'-separated path buffer. */
static void append_lib_subdirs(char *buf, const char *root) {
    static const char *subs[] = {
        "/bin", "/usr/bin", "/bin/lib", "/bin/lib64", "/usr/bin/lib64", "/usr/bin/lib",
        "/lib", "/lib64", "/usr/lib", "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu", "/usr/lib/i386-linux-gnu"
    };
    char d[4096];
    for (unsigned int i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        my_strcpy(d, root); my_strcat(d, subs[i]);
        if (!file_exists(d)) continue;
        my_strcat(buf, ":");
        my_strcat(buf, d);
    }
    for (int i = 0; i < g_extra_libdirs_n; i++) {
        my_strcat(buf, ":");
        my_strcat(buf, g_extra_libdirs[i]);
    }
}
