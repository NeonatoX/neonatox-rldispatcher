/* ================================================================== */
/*  sysroot_manager.c -- resolucion de librerias en el sysroot glibc  */
/*  y configuracion de nrld (/etc/nrld.conf).                          */
/*                                                                     */
/*  Aqui vive la politica de aislamiento musl<->glibc: que sonames se  */
/*  pueden resolver, cuales faltan (y por tanto caerian a /usr/lib     */
/*  musl) y como se parchean los DT_NEEDED absolutos.                  */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h.                   */
/*                                                                     */
/*  Conceptos clave:                                                  */
/*    - resolve_lib_path: soname -> ruta (dir del binario + subdirs   */
/*      estandar + dirs extra + sysroot). Nunca mira musl /usr/lib.    */
/*    - extralibfinder (find_lib_under/find_lib_in_sysroot): localiza  */
/*      un soname en subdirectorios no estandar del sysroot (gvfs/,   */
/*      pulseaudio/, engines-3/, dri/...) y registra el dir.           */
/*    - shadow copies: un DT_NEEDED con ruta absoluta (p.ej.          */
/*      /opt/foo/libxul.so) se traduce a soname en una copia parcheada */
/*      que el loader si sabe resolver.                                */
/*    - guard transitivo (scan_missing_libs): recorre el arbol de      */
/*      NEEDED de cada lib que resuelve dentro del sysroot, para      */
/*      detectar deps musl escondidas a un nivel mas abajo.            */
/* ================================================================== */

#include "utils.h"
#include "nrld_paths.h"
#include "elf_parser.h"
#include "sysroot_manager.h"

#define MAX_VISITED 512
#define MAX_NAMES   256
#define MAX_SHADOW  8

/* Config file for nrld default behaviour, installed on the HOST at /etc
   (NOT inside the sysroot, so it can point at any sysroot/proxy path). It is
   written by the installer. Format: one "key = value" per line; the bare
   token "strict" enables strict mode for all apps (same as setting
   NEONATOX_STRICT_SYSROOT=1). Keys currently honored:
     library_path  -> sent as LD_LIBRARY_PATH (default: NEO_SYSROOT dirs)
     proxy         -> sent as LD_PRELOAD (default: NEO_BINDIR/libnrld-proxy.so)
   The sysroot root itself is NOT runtime-configurable by design: it stays as
   the build-time NEO_SYSROOT default (overridable with a recompile/Meson). */

static char g_conf_libpath[4096];
static char g_conf_proxy[256];
static int  g_conf_strict = 0;
static int  g_conf_log_level = 0;

/* Directorios extra donde pueden vivir librerias (AppImage interno,
   subdirs no estandar del sysroot). */
static char g_extra_libdirs[MAX_EXTRA_DIRS][4096];
static int  g_extra_libdirs_n = 0;

/* Copias parcheadas de DT_NEEDED absolutos en /tmp/nrld-patch-<pid>. */
static char g_patch_dir[4096];
static int  g_patch_dir_set = 0;
static char g_shadow_paths[MAX_SHADOW][4096];
static int  g_shadow_n = 0;
static char g_top_patch[4096];

/* ------------------------------------------------------------------ */
/*  Configuracion (/etc/nrld.conf)                                      */
/* ------------------------------------------------------------------ */

static int conf_token_is(const char *tok, long tlen, const char *word) {
    long wl = 0;
    while (word[wl]) wl++;
    if (tlen != wl) return 0;
    for (long i = 0; i < wl; i++) if (tok[i] != word[i]) return 0;
    return 1;
}

void sysroot_load_conf(void) {
    g_conf_libpath[0] = '\0';
    g_conf_proxy[0] = '\0';
    g_conf_strict = 0;
    g_conf_log_level = 0;
    if (!file_exists(NRLCONF_PATH)) return;
    long fd = syscall2(SYS_open, (long)NRLCONF_PATH, 0);
    if (fd < 0) return;
    char buf[4096];
    long n = read_at(fd, 0, buf, sizeof(buf) - 1);
    syscall1(SYS_close, fd);
    if (n <= 0) return;
    buf[n] = '\0';
    long p = 0;
    while (p < n) {
        if (buf[p] == '#') {               /* comment to end of line */
            while (p < n && buf[p] != '\n') p++;
            continue;
        }
        if (buf[p] == ' ' || buf[p] == '\t' ||
            buf[p] == '\n' || buf[p] == '\r') { p++; continue; }
        long start = p;
        while (p < n && buf[p] != ' ' && buf[p] != '\t' &&
               buf[p] != '\n' && buf[p] != '\r') p++;
        long tlen = p - start;
        long eq = -1;
        for (long i = 0; i < tlen; i++)
            if (buf[start + i] == '=') { eq = i; break; }
        if (eq < 0) {
            if (conf_token_is(buf + start, tlen, "strict")) g_conf_strict = 1;
            continue;
        }
        long klen = eq, vlen = tlen - eq - 1;
        const char *val = buf + start + eq + 1;
        if (conf_token_is(buf + start, klen, "library_path") &&
            vlen > 0 && vlen < (long)sizeof(g_conf_libpath)) {
            for (long i = 0; i < vlen; i++) g_conf_libpath[i] = val[i];
            g_conf_libpath[vlen] = '\0';
        } else if (conf_token_is(buf + start, klen, "proxy") &&
                   vlen > 0 && vlen < (long)sizeof(g_conf_proxy)) {
            for (long i = 0; i < vlen; i++) g_conf_proxy[i] = val[i];
            g_conf_proxy[vlen] = '\0';
        } else if (conf_token_is(buf + start, klen, "log_level") &&
                   vlen == 1 && val[0] >= '0' && val[0] <= '3') {
            g_conf_log_level = val[0] - '0';
        }
    }
}

int         sysroot_conf_strict(void)    { return g_conf_strict; }
int         sysroot_conf_log_level(void) { return g_conf_log_level; }
const char *sysroot_conf_libpath(void)   { return g_conf_libpath; }
const char *sysroot_conf_proxy(void)     { return g_conf_proxy; }

/* ------------------------------------------------------------------ */
/*  Directorios extra de librerias                                      */
/* ------------------------------------------------------------------ */

void sysroot_reset_extra_libdirs(void) {
    g_extra_libdirs_n = 0;
}

void sysroot_add_extra_libdir(const char *dir) {
    if (g_extra_libdirs_n >= MAX_EXTRA_DIRS) return;
    my_strcpy(g_extra_libdirs[g_extra_libdirs_n], dir);
    g_extra_libdirs_n++;
}

int sysroot_extra_libdir_count(void) {
    return g_extra_libdirs_n;
}

const char *sysroot_extra_libdir(int i) {
    if (i < 0 || i >= g_extra_libdirs_n) return "";
    return g_extra_libdirs[i];
}

const char *sysroot_patch_dir(void)     { return g_patch_dir; }
int         sysroot_patch_dir_set(void) { return g_patch_dir_set; }
const char *sysroot_top_patch(void)     { return g_top_patch; }

/* Append the internal lib dirs of `root` (standard subdirs that exist +
   the collected extra lib dirs) to a ':'-separated path buffer. */
void append_lib_subdirs(char *buf, const char *root) {
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

/* ------------------------------------------------------------------ */
/*  Resolucion de sonames dentro del sysroot                            */
/* ------------------------------------------------------------------ */

/* extralibfinder: depth-bounded search for a file named exactly `want`
   under `root`, preferring the shallowest hit. Only true ELF files count;
   symlinks (dev packages) are followed. Local buffer per call so an entry
   name never aliases a deeper frame's path. */
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
            struct nrl_dirent64 *de = (struct nrl_dirent64 *)(buf + off);
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

/* Locate a soname inside the glibc sysroot subdirs when it is not at any
   standard dir. Fills `out_dir` with the containing dir; 1 on hit. Only
   sysroot dirs are scanned (never musl /usr) to preserve ABI isolation. */
static int find_lib_in_sysroot(const char *soname, char *out_dir) {
    const char *roots[] = { NEO_SYSROOT "/usr/lib", NEO_SYSROOT "/lib" };
    for (int i = 0; i < 2; i++)
        if (find_lib_under(roots[i], soname, out_dir, 0)) return 1;
    return 0;
}

/* Resolve a soname to a real file path searching, in order: the lib root
   itself (bin dir / extracted AppImage root), the standard subdirs under it
   (lib, lib64, usr/lib, usr/lib64, usr/lib/<triplet>), the AppImage-internal
   extra lib dirs, and finally the glibc sysroot dirs. Returns 1 and fills
   `out` on success, 0 (and out[0]=0) otherwise. */
int resolve_lib_path(const char *soname, const char *lib_root, char *out) {
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
    const char *dirs[] = { NEO_SYSROOT "/usr/lib", NEO_SYSROOT "/lib" };
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
            if (!already) sysroot_add_extra_libdir(extra_dir);
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

/* ------------------------------------------------------------------ */
/*  Pre-flight DT_NEEDED coverage check.                                */
/*  A glibc binary's NEEDED libs must be resolvable within the sysroot  */
/*  (bin_dir + /usr/lib/glibc6/...). If one is missing there, glibc's   */
/*  loader falls back to its compiled-in /usr/lib and pulls a MUSL      */
/*  build in (two libcs in one process -> strtod_l ABI crash, as seen   */
/*  in Firefox over musl Pango/GTK). We surface that here so an app     */
/*  fails with a readable message instead of a confusing SIGSEGV.       */
/* ------------------------------------------------------------------ */

/* Runtime fix for DT_NEEDED entries that hard-code an ABSOLUTE path (e.g.
   libtinysparql -> "/usr/lib/libsqlite3.so"). The glibc loader takes such an
   entry literally (it never goes through --library-path / LD_LIBRARY_PATH), so
   it would load the musl /usr/lib build and pull musl libc into the process.
   When the *basename* resolves inside the sysroot, stage a patched copy of the
   CONTAINING object in /tmp/nrld-patch-<pid>/ (named by its SONAME so depended
   objects pick it up first from the search path) with that dynstr string
   rewritten to the resolvable basename. Returns 1 and fills `shadow_out` on
   success, 0 otherwise. */
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

int check_needed_libs(const char *path, const char *bin_dir) {
    return scan_missing_libs(path, bin_dir);
}
