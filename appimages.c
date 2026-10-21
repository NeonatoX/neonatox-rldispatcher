/* ================================================================== */
/*  appimages.c -- soporte AppImage type-2 para nrld.                  */
/*                                                                     */
/*  Detecta un AppImage type-2 (EI_ABIVERSION no estandar + squashfs  */
/*  embebido), lo extrae a /tmp/nrld-appimage-<pid>/ con el           */
/*  `unsquashfs` del host (musl; nunca escribe fuera de /tmp),        */
/*  localiza el binario ELF interno real y recoge los directorios de  */
/*  librerias internas (lib/, usr/lib/, usr/lib/<triplet>, plugins/)   */
/*  para que el loader resuelva las libs propias de la app sin tocar  */
/*  el /usr de musl.                                                   */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h,                   */
/*               sysroot_manager.h (registro de dirs extra).            */
/*                                                                     */
/*  Conceptos clave:                                                  */
/*    - Descubrimiento del binario interno: AppRun symlink->ELF y      */
/*      AppRun script '#!' son las entradas canonicas. Un AppRun ELF    */
/*      plano NO se prioriza (los launchers tipo OpenShot rompen al  */
/*      correr pelados: TUI de ncurses + check de .desktop).           */
/*    - Higiene de /tmp: cada AppImage deja ~600 MB, asi que antes de  */
/*      extraer se barren las extracciones viejas que ningun proceso  */
/*      vivo referencia (exe/cwd en /proc/<pid>).                      */
/*    - Plugin Qt: se busca el dir 'platforms/' con .so ->            */
/*      QT_PLUGIN_PATH (buffer local por llamada: un buffer           */
/*      compartido rompia los hermanos tras una recursion profunda).   */
/* ================================================================== */

#include "utils.h"
#include "nrld_paths.h"
#include "elf_parser.h"
#include "sysroot_manager.h"
#include "appimages.h"

#define APPDIR_PREFIX      "/tmp/nrld-appimage-"
#define MAX_SCAN_DIRS      512
#define HUNT_CHUNK         65536

/* Estado de la extraccion. */
static char g_appimage_root[4096];
static char g_appimage_bin[4096];
static int  g_appimage_extracted = 0;
static int  g_appimage_script = 0;   /* AppRun es un script #!, se exec directo */
static char g_qt_plugin_path[4096];

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
int is_appimage(const char *path) {
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
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
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
    if (sysroot_extra_libdir_count() >= MAX_EXTRA_DIRS) return;
    if (collect_scan_count++ >= MAX_SCAN_DIRS) return;
    long fd = syscall2(SYS_open, (long)dir, 0);
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
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            if ((de->d_type & 0xf) == 4) {          /* DT_DIR */
                my_strcpy(scan_path_buf, dir);
                my_strcat(scan_path_buf, "/");
                my_strcat(scan_path_buf, nm);
                if (dir_has_so(scan_path_buf)) sysroot_add_extra_libdir(scan_path_buf);
                collect_libdirs_rec(scan_path_buf, depth + 1);
            }
            off += de->d_reclen;
        }
        if (sysroot_extra_libdir_count() >= MAX_EXTRA_DIRS) break;
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
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
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
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) {
                off += de->d_reclen; continue;
            }
            if ((de->d_type & 0xf) == 8) {          /* DT_REG */
                if (name_is_so(nm)) { off += de->d_reclen; continue; }
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
   1. AppRun symlink -> that target (OCAT-style, symlink pointing at an ELF).
      A plain-ELF AppRun is NOT preferred here: those launchers (OpenShot)
      break when run naked instead of the real app binary (their bundled
      ncurses TUI + .desktop requirements). The script AppRun IS run as-is
      because a #! script always re-execs the real ELF (Heroic, balena).
   2. AppRun as a #! script: exec it directly; the shell loads the ELF real.
   3. top-level *.bin (Electron-style, e.g. balena-etcher.bin)
   4. usr/bin or other standard bin dirs
   5. any other top-level ELF executable (never a .so) */
static int find_internal_bin(const char *root, char *out) {
    g_appimage_script = 0;
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
    if (!is_elf(p)) {
        long fd = syscall2(SYS_open, (long)p, 0);
        if (fd >= 0) {
            char head[2];
            long got = syscall3(SYS_read, fd, (long)head, 2);
            syscall1(SYS_close, fd);
            if (got == 2 && head[0] == '#' && head[1] == '!' &&
                syscall2(SYS_access, (long)p, 1) == 0) {
                my_strcpy(out, p);
                g_appimage_script = 1;
                return 1;
            }
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

/* Un AppImage en marcha vive dentro de /tmp/nrld-appimage-<pid>/: el exe del
   proceso principal (y los hijos que re-ejecutan su copia) apuntan a ese dir,
   y el cwd de los hijos suele estar ahi dentro. Un dir sin ninguna referencia
   viva en /proc es basura de una corrida anterior (cada lanzamiento deja ~600MB
   de extraccion + copia; sin esto /tmp se llena). */
static int appimage_dir_in_use(const char *dir) {
    long dfd = syscall2(SYS_open, (long)"/proc", 0);
    if (dfd < 0) return 1;               /* can't check: be conservative */
    char exe_prefix[4096];
    my_strcpy(exe_prefix, dir);
    my_strcat(exe_prefix, "/");
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
            char ep[64], rl[4096];
            long m;
            my_strcpy(ep, "/proc/"); my_strcat(ep, nm); my_strcat(ep, "/exe");
            m = syscall3(SYS_readlink, (long)ep, (long)rl, sizeof(rl) - 1);
            if (m > 0) {
                rl[m] = '\0';
                if (my_starts_with(rl, exe_prefix)) { in_use = 1; break; }
            }
            my_strcpy(ep, "/proc/"); my_strcat(ep, nm); my_strcat(ep, "/cwd");
            m = syscall3(SYS_readlink, (long)ep, (long)rl, sizeof(rl) - 1);
            if (m > 0) {
                rl[m] = '\0';
                if (my_strcmp(rl, dir) == 0) { in_use = 1; break; }
            }
            off += de->d_reclen;
        }
        if (in_use) break;
    }
    syscall1(SYS_close, dfd);
    return in_use;
}

static void sweep_stale_appimage_dirs(void) {
    long fd = syscall2(SYS_open, (long)"/tmp", 0);
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
            unsigned int nl = 0;
            while (nm[nl]) nl++;
            if (nl < 15 || !my_starts_with(nm, "nrld-appimage-")) {
                off += de->d_reclen; continue;
            }
            const char *d = nm + 14;
            int digits = (*d != 0);
            for (const char *q = d; *q; q++) if (*q < '0' || *q > '9') { digits = 0; break; }
            if (!digits) { off += de->d_reclen; continue; }
            char full[4096];
            my_strcpy(full, "/tmp/"); my_strcat(full, nm);
            if (!appimage_dir_in_use(full)) {
                print_msg("[ADV] Limpiando extraccion AppImage vieja: ");
                print_msg(full);
                print_msg("\n");
                rm_rf(full);
            }
            off += de->d_reclen;
        }
    }
    syscall1(SYS_close, fd);
}

/* Extract the AppImage squashfs to /tmp via the host's unsquashfs and locate
   the internal binary + lib dirs. Returns 1 on success (g_appimage_bin set). */
int extract_appimage(const char *path) {
    long off = get_squashfs_offset(path);
    if (off < 0) return 0;

    sweep_stale_appimage_dirs();

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
    sysroot_reset_extra_libdirs();
    collect_libdirs_rec(g_appimage_root, 0);
    collect_qt_plugin_dir(g_appimage_root);

    g_appimage_extracted = 1;
    return 1;
}

const char *appimage_root(void)         { return g_appimage_root; }
const char *appimage_bin(void)          { return g_appimage_bin; }
int         appimage_extracted(void)   { return g_appimage_extracted; }
int         appimage_is_script(void)   { return g_appimage_script; }
const char *appimage_qt_plugin_path(void) { return g_qt_plugin_path; }
