// proxy_readlink.c
// Compilar con: gcc -nostdlib -shared -fPIC -o /usr/lib/neonatox/libnrld-proxy.so proxy_readlink.c

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <link.h>

/* Compile-time defaults (same knobs as nrld; Meson passes -D...). Overridable
   at runtime via NEONATOX_SYSROOT for the sysroot root. */
#ifndef NEO_SYSROOT
#define NEO_SYSROOT   "/usr/lib/glibc6"
#endif
#ifndef NEO_BINDIR
#define NEO_BINDIR    "/usr/lib/neonatox"
#endif

static int proxy_log_fd = -1;

/* glibc-host guard: this .so is LD_PRELOAD'd by EVERY dynamic binary started
   from a shell that sources the nrld profile, including musl ones. Under a
   musl loader it must be a completely transparent no-op: no /proc/self/exe
   rewrite, no redirect, no strict scan, no crash handlers. Detected once at
   init: glibc provides the libc.so.6 soname, musl does not. The interposers
   only act when this is 1. */
static int g_glibc_host = 1;

static char sysroot_root[4096];
static size_t sysroot_root_len = 0;

static int under_sysroot(const char *p) {
    if (!p || !*p) return 0;
    if (sysroot_root_len == 0) return 0;
    if (strncmp(p, sysroot_root, sysroot_root_len) != 0) return 0;
    return p[sysroot_root_len] == '/' || p[sysroot_root_len] == '\0';
}

static void proxy_logf(const char *msg) {
    /* Only appends to the NEONATOX_PROXY_LOG file (never to stderr). */
    if (proxy_log_fd >= 0) {
        ssize_t p = write(proxy_log_fd, msg, strlen(msg));
        (void)p;
    }
}

static void proxy_logf_u64(unsigned long long v) {
    char b[24]; int i = 0;
    if (v == 0) { proxy_logf("0"); return; }
    while (v && i < 22) { b[i++] = (char)('0' + v % 10); v /= 10; }
    while (i > 0) { char c = b[--i]; char s[2] = { c, 0 }; proxy_logf(s); }
}

static void proxy_err(const char *msg) {
    ssize_t len = (ssize_t)strlen(msg);
    ssize_t ign;
    do { ign = write(STDERR_FILENO, msg, (size_t)len); } while (0);
    (void)ign;
    /* NEONATOX_PROXY_LOG=<archivo>: espejo de todo lo que el proxy escribe
       a stderr a un archivo. Los procesos de contenido de Firefox capturan
       su stderr (pipe hacia el parent), que no lo reenvia a la terminal:
       sin esto, un rechazo del scan strict de una pestaña queda invisible. */
    proxy_logf(msg);
}

static const char *real_exe_path = NULL;
static int strict_sysroot = 0;
static char allow_dir[4096];
static size_t allow_dir_len = 0;
static char patched_dir[4096];
static size_t patched_dir_len = 0;
static char appdir[4096];
static size_t appdir_len = 0;
static int crashdump_on = 0;
static void install_crashdump(void);

/* Kernel-mode discriminator for the readlink("/proc/self/exe") rewrite.
   That rewrite is only a safety net for the loader-as-main fallback (no
   patched copy), where the kernel's /proc/self/exe IS the loader. In normal
   user mode the kernel /proc/self/exe is already the app (interp-patched
   copy in the app dir); rewriting it to NEONATOX_REAL_EXE makes Chromium's
   recursive self-exe resolution see a path that differs from the running
   binary and die with SIGTRAP/NOTREACHED in early startup (verified live:
   same clean-named Electron copy traps with NEONATOX_REAL_EXE set and runs
   when the rewrite is skipped). Mode is fixed per process; detect once via a
   raw readlink of /proc/self/exe (bypassing our interposed symbol). */
static int loader_as_main = 0;

static long raw_readlink(const char *path, char *out, size_t n) {
    long rc;
    __asm__ volatile("syscall"
                     : "=a"(rc)
                     : "a"(89 /* SYS_readlink */), "D"(path), "S"(out), "d"(n)
                     : "rcx", "r11", "memory");
    return rc;
}

static void detect_loader_main(void) {
    char selfbuf[4096];
    long n = raw_readlink("/proc/self/exe", selfbuf, sizeof(selfbuf));
    if (n <= 0) { loader_as_main = (real_exe_path != NULL); return; }
    if (n >= (long)sizeof(selfbuf)) n = (long)sizeof(selfbuf) - 1;
    selfbuf[n] = '\0';
    const char *b = selfbuf;
    for (const char *p = selfbuf; *p; p++) if (*p == '/') b = p + 1;
    loader_as_main = (strncmp(b, "ld-", 3) == 0);
}

static void pid_name(char *dst, size_t sz, const char *prefix, int pid) {
    size_t pl = strlen(prefix);
    if (pl >= sz - 4) return;
    memcpy(dst, prefix, pl);
    char *w = dst + pl;
    unsigned v = (unsigned)pid;
    char tmp[12]; int i = 0;
    do { tmp[i++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (i) *w++ = tmp[--i];
    *w++ = '.'; *w++ = 't'; *w++ = 'x'; *w++ = 't'; *w = '\0';
}

static void derive_allow_dir(void) {
    if (!real_exe_path) return;
    const char *p = real_exe_path;
    const char *last = p;
    for (const char *q = p; *q; q++) if (*q == '/') last = q;
    size_t n = (size_t)(last - p);
    if (n >= sizeof(allow_dir)) n = sizeof(allow_dir) - 1;
    memcpy(allow_dir, p, n);
    allow_dir[n] = '\0';
    allow_dir_len = (n == 0) ? 1 : n;
}

/* dlopen path redirection table, built from the runtime sysroot root so the
   mapping follows NEONATOX_SYSROOT (default: NEO_SYSROOT). Same semantics as
   before: most host prefixes map into <root>/usr/lib/ in the sysroot. */
static char g_rd[5][4096];
struct redirect_map { const char *host; char *sys; };
static struct redirect_map redirect_maps[8];

static void build_redirect_maps(void) {
    static const char *sufs[5] = { "/usr/lib/", "/usr/lib32/", "/usr/libx32/",
                                   "/lib/", "/lib64/" };
    size_t rl = sysroot_root_len;
    for (int i = 0; i < 5; i++) {
        size_t sl = strlen(sufs[i]);
        if (rl + sl + 1 > sizeof(g_rd[i])) { g_rd[i][0] = '\0'; continue; }
        memcpy(g_rd[i], sysroot_root, rl);
        memcpy(g_rd[i] + rl, sufs[i], sl);
        g_rd[i][rl + sl] = '\0';
    }
    static const char *hosts[8] = {
        "/usr/lib/", "/usr/lib64/", "/usr/lib32/", "/usr/libx32/",
        "/lib/", "/lib64/", "/usr/x86_64-linux-gnu/", "/usr/i386-linux-gnu/"
    };
    static const int targets[8] = { 0, 0, 1, 2, 3, 4, 0, 0 };
    for (int i = 0; i < 8; i++) {
        redirect_maps[i].host = hosts[i];
        redirect_maps[i].sys = g_rd[targets[i]];
    }
}

__attribute__((constructor))
void init_proxy(void) {
    /* glibc-host guard: la interposicion solo debe activarse bajo un glibc
       real. NO sirve dlopen("libc.so.6"): en hosts musl con libc6-compat
       (/usr/lib/libc.so.6 -> sysroot glibc) el dlopen tiene exito y el proxy
       creeria estar en glibc, reescribiendo dlopen de paths musl -> la ruta
       glibc del sysroot => musl roto. Discriminador robusto: gnu_get_libc_version
       solo lo exporta glibc (verificado: ni en musl puro ni en musl con la libc
       glibc dlopen'd en un namespace local). */
    void *(*glibc_ver)(void) = (void *(*)(void))dlsym(RTLD_DEFAULT, "gnu_get_libc_version");
    g_glibc_host = (glibc_ver != NULL);

    /* Sysroot root: NEONATOX_SYSROOT if set (nrld exports it), else the
       compile-time default. Every allowlist/redirect comparison derives from
       this. */
    const char *sr = getenv("NEONATOX_SYSROOT");
    if (!sr || !*sr) sr = NEO_SYSROOT;
    size_t rn = strlen(sr);
    if (rn >= sizeof(sysroot_root)) rn = sizeof(sysroot_root) - 1;
    memcpy(sysroot_root, sr, rn);
    sysroot_root[rn] = '\0';
    sysroot_root_len = rn;
    build_redirect_maps();

    // Leer la ruta real del binario desde una variable de entorno
    real_exe_path = getenv("NEONATOX_REAL_EXE");
    detect_loader_main();
    derive_allow_dir();
    const char *s = getenv("NEONATOX_STRICT_SYSROOT");
    strict_sysroot = s && *s == '1';
    const char *pd = getenv("NEONATOX_PATCH_DIR");
    if (pd && *pd) {
        size_t n = strlen(pd);
        if (n >= sizeof(patched_dir)) n = sizeof(patched_dir) - 1;
        memcpy(patched_dir, pd, n);
        patched_dir[n] = '\0';
        patched_dir_len = n;
    }
    const char *ad = getenv("NEONATOX_APPDIR");
    if (ad && *ad) {
        size_t n = strlen(ad);
        if (n >= sizeof(appdir)) n = sizeof(appdir) - 1;
        memcpy(appdir, ad, n);
        appdir[n] = '\0';
        appdir_len = n;
    }
    const char *cd = getenv("NEONATOX_CRASHDUMP");
    if (g_glibc_host && cd && *cd == '1') {
        crashdump_on = 1;
        install_crashdump();
    }
    const char *pl = getenv("NEONATOX_PROXY_LOG");
    if (pl && *pl) {
        proxy_log_fd = open(pl, O_WRONLY | O_CREAT | O_APPEND, 0644);
        /* heartbeat: si un proceso corre con LD_PRELOAD activo, aparece una
           linea por proceso aqui. Un ff-proxy.log con lineas "init" pero sin
           "Falta" prueba que el proxy cargo en los hijos y el scan paso. */
        proxy_logf("[nrld-proxy] init pid=");
        proxy_logf_u64((unsigned long long)getpid());
        proxy_logf("\n");
        (void)0;
    }
    const char *de = getenv("NEONATOX_DUMPENV");
    if (de && *de == '1') {
        char ep[64];
        pid_name(ep, sizeof(ep), "/tmp/neonatox-env-", (int)getpid());
        int f = open(ep, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (f >= 0) {
            for (char **e = environ; e && *e; e++) {
                size_t el = strlen(*e);
                write(f, *e, el);
                write(f, "\n", 1);
            }
            if (real_exe_path) {
                write(f, "NEONATOX_REAL_EXE=", 18);
                write(f, real_exe_path, strlen(real_exe_path));
                write(f, "\n", 1);
            }
            close(f);
        }
    }
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    // Solo reescribir /proc/self/exe cuando el kernel realmente apunta al
    // loader (modo cargador-as-main, sin copia parcheada). En modo usuario la
    // respuesta del kernel ya es la app: reescribirla rompe Chromium.
    if (g_glibc_host && real_exe_path && loader_as_main && pathname && strcmp(pathname, "/proc/self/exe") == 0) {
        size_t len = strlen(real_exe_path);
        if (len >= bufsiz) {
            len = bufsiz - 1;
        }
        memcpy(buf, real_exe_path, len);
        buf[len] = '\0';
        return len;
    }
    
    // Para cualquier otro caso, llamar al readlink real
    ssize_t (*original_readlink)(const char *, char *, size_t);
    original_readlink = dlsym(RTLD_NEXT, "readlink");
    
    if (original_readlink) {
        return original_readlink(pathname, buf, bufsiz);
    }
    
    return -1;
}

/* ------------------------------------------------------------------ */
/*  dlopen/dlclose interposition (glibc dlopen ABI isolation).         */
/*  Only active with NEONATOX_STRICT_SYSROOT=1. Any library that the   */
/*  loader would resolve OUTSIDE the glibc sysroot (i.e. a musl build  */
/*  from /usr/lib) is rejected -> the app fails cleanly with a null    */
/*  handle instead of mixing two libcs in one process and crashing.    */
/* ------------------------------------------------------------------ */
static int is_rtld_path(const char *p) {
    /* The running glibc dynamic linker. In the interp-patched user mode it
       appears in the link map as a normal object (dlpi_name = its interp
       path, e.g. /lib64/ld-linux-x86-64.so.2) instead of as the main
       program (empty name, always allowed). It can only ever be the
       sysroot's glibc build (musl's loader is ld-musl-x86-64.so.1), so a
       basename match is safe and covers any path variant. */
    static const char suf[] = "/ld-linux-x86-64.so.2";
    if (!p || !*p) return 0;
    size_t pl = strlen(p);
    if (pl >= sizeof(suf) - 1 && memcmp(p + pl - (sizeof(suf) - 1), suf, sizeof(suf) - 1) == 0)
        return 1;
    return 0;
}

static int is_allowed_path(const char *path) {
    if (!path) return 1;                      /* no resolved name: allow */
    if (is_rtld_path(path)) return 1;         /* the running glibc loader */
    if (under_sysroot(path)) return 1;        /* resolved inside the sysroot */
    if (strncmp(path, NEO_BINDIR, sizeof(NEO_BINDIR) - 1) == 0 &&
        path[sizeof(NEO_BINDIR) - 1] == '/') return 1;  /* our own install dir */
    if (patched_dir_len && strncmp(path, patched_dir, patched_dir_len) == 0) return 1; /* runtime patches */
    if (appdir_len && strncmp(path, appdir, appdir_len) == 0) return 1; /* extracted AppImage tree */
    if (allow_dir_len && strncmp(path, allow_dir, allow_dir_len) == 0) return 1;
    return 0;
}

static void reject_handle(void *h, const char *name) {
    void (*real_dlclose)(void *) = (void (*)(void *))dlsym(RTLD_NEXT, "dlclose");
    if (real_dlclose && h) real_dlclose(h);
    proxy_err("[neonatox] The following glibc library is missing to run the app: ");
    proxy_err(name ? name : "(sin nombre)");
    proxy_err(" (no existe en el sysroot ");
    proxy_err(sysroot_root);
    proxy_err("). Instala las librerias glibc faltantes.\n");
}

/* ------------------------------------------------------------------ */
/*  Crash diagnostics (env NEONATOX_CRASHDUMP=1, off by default).      */
/*  Installs signal handlers in every preloaded process; on SIGSEGV/   */
/*  SIGABRT/SIGBUS/SIGILL/SIGFPE it dumps (to stderr) the faulting     */
/*  module+offset (via /proc/self/maps) plus any mapped /usr/lib       */
/*  (musl) paths, then _exit()s.                                     */
/* ------------------------------------------------------------------ */

static void write_u64(unsigned long long v) {
    char b[24]; int i = 0;
    if (v == 0) { write(STDERR_FILENO, "0", 1); return; }
    while (v && i < 22) { b[i++] = (char)('0' + v % 10); v /= 10; }
    while (i > 0) { char c = b[--i]; write(STDERR_FILENO, &c, 1); }
}

static void write_hex(unsigned long long v) {
    char b[24]; int i = 0;
    if (v == 0) { write(STDERR_FILENO, "0", 1); return; }
    while (v && i < 22) { b[i++] = "0123456789abcdef"[v & 0xf]; v >>= 4; }
    while (i > 0) { char c = b[--i]; write(STDERR_FILENO, &c, 1); }
}

static unsigned long long hex_v(const char *s) {
    unsigned long long v = 0;
    while (*s) {
        char c = *s;
        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        s++;
    }
    return v;
}

static void crash_handler(int sig, siginfo_t *si, void *ucv) {
    (void)si;
    ucontext_t *uc = (ucontext_t *)ucv;
#if defined(__x86_64__)
    unsigned long long rip = uc->uc_mcontext.gregs[REG_RIP];
#endif
    proxy_err("[nrld-crash] pid=");
    write_u64((unsigned long long)getpid());
    proxy_err(" sig=");
    write_hex((unsigned long long)(unsigned)sig);
#if defined(__x86_64__)
    proxy_err(" rip=");
    write_hex(rip);
#endif
    proxy_err("\n");

    char comm[64];
    int n = 0;
    int cfd = open("/proc/self/comm", O_RDONLY);
    if (cfd >= 0) {
        n = (int)read(cfd, comm, sizeof(comm) - 1);
        close(cfd);
    }
    if (n > 0) {
        if (comm[n-1] == '\n') comm[n-1] = '\0';
        proxy_err("[nrld-crash] comm=");
        proxy_err(comm);
        proxy_err("\n");
    }

    char buf[262144];
    char *mf = "/proc/self/maps";
    ssize_t rd = 0;
    size_t used = 0;
    int mfd = open(mf, O_RDONLY);
    if (mfd < 0) {
        proxy_err("[nrld-crash] no maps\n");
        _exit(128 + sig);
    }
    while (used < sizeof(buf) - 1) {
        rd = read(mfd, buf + used, sizeof(buf) - 1 - used);
        if (rd <= 0) break;
        used += (size_t)rd;
    }
    close(mfd);
    buf[used] = '\0';

    char *ln = buf;
    int musl_shown = 0;
    while (*ln) {
        char *nl = strchr(ln, '\n');
        if (!nl) nl = ln + strlen(ln);
        char saved = *nl;
        *nl = '\0';
        unsigned long long a = 0, b = 0;
        char *cur = ln;
        int field = 0;
        const char *path = NULL;
        while (*cur) {
            while (*cur == ' ') cur++;
            if (!*cur) break;
            char *end = cur;
            while (*end && *end != ' ') end++;
            field++;
            if (field == 1) {
                const char *dsh = strchr(cur, '-');
                if (dsh) {
                    char tmp[32];
                    size_t l1 = (size_t)(dsh - cur);
                    if (l1 < 32) {
                        memcpy(tmp, cur, l1); tmp[l1] = '\0';
                        a = hex_v(tmp);
                        size_t l2 = 0;
                        const char *d2 = dsh + 1;
                        while (d2[l2] && d2[l2] != ' ' && l2 < 31) { tmp[l2] = d2[l2]; l2++; }
                        tmp[l2] = '\0';
                        b = hex_v(tmp);
                    }
                }
            } else if (field == 6) {
                path = cur;              /* 6th field: the pathname */
            }
            cur = end;
        }
#if defined(__x86_64__)
        int is_crashing = (rip >= a && rip < b);
#else
        int is_crashing = 0;
#endif
        if (is_crashing) {
            proxy_err("[nrld-crash] -> faul en ");
            proxy_err(path && *path ? path : "(anon/ejecutable)");
            proxy_err("+");
            write_hex(rip - a);
            proxy_err("\n");
        }
        if (path && *path && musl_shown < 32) {
            const char *q = path;
            int is_usl = 0;
            /* Host lib dirs (musl builds live here on this host), EXCLUDING
               anything under the resolved sysroot root. */
            if (strncmp(q, "/usr/lib/", 9) == 0 || strncmp(q, "/usr/lib64", 10) == 0 ||
                strncmp(q, "/usr/lib32", 10) == 0 || strncmp(q, "/usr/libx32", 11) == 0 ||
                strncmp(q, "/lib/", 5) == 0 || strncmp(q, "/lib64/", 7) == 0 ||
                strncmp(q, "/usr/x86_64-linux-gnu/", 21) == 0 ||
                strncmp(q, "/usr/i386-linux-gnu/", 19) == 0) {
                if (!under_sysroot(q)) is_usl = 1;
            }
            if (is_usl) {
                proxy_err("[nrld-crash]   musl-map: ");
                proxy_err(path);
                proxy_err("\n");
                musl_shown++;
            }
        }
        *nl = saved;
        ln = nl + 1;
    }
    _exit(128 + sig);
}

static void install_crashdump(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

static char bad_path[4096];
static int found_bad;

/* Verdict cache for the strict link-map scan. A path allowed once stays
   allowed for the whole process (the link map only grows), so Chromium-style
   apps that dlopen the same libs many times don't pay a full map walk per
   call. Bounded static array, FIFO eviction. */
#define VERDICT_CACHE_MAX 2048
#define VERDICT_PATH_MAX  320
static char verdict_cache[VERDICT_CACHE_MAX][VERDICT_PATH_MAX];
static unsigned verdict_cache_n = 0;
static unsigned verdict_cache_next = 0;

static int verdict_cached(const char *nm) {
    unsigned int n = 0;
    while (nm[n]) n++;
    if (n >= VERDICT_PATH_MAX) return 0;
    for (unsigned i = 0; i < verdict_cache_n; i++)
        if (memcmp(verdict_cache[i], nm, n + 1) == 0) return 1;
    return 0;
}

static void verdict_add(const char *nm) {
    unsigned int n = 0;
    while (nm[n]) n++;
    if (n >= VERDICT_PATH_MAX) return;
    unsigned slot;
    if (verdict_cache_n < VERDICT_CACHE_MAX) {
        slot = verdict_cache_n++;
    } else {
        slot = verdict_cache_next;
        verdict_cache_next = (verdict_cache_next + 1) % VERDICT_CACHE_MAX;
    }
    memcpy(verdict_cache[slot], nm, n + 1);
}

/* Visit every loaded shared object (main program + all NEEDED of every
   dlopen'd object). If any resolves outside the sysroot (a musl /usr/lib
   build), the process has mixed two libcs -> record it. */
/* Kernel pseudo-objects (VDSO, vsyscall) live only in process memory; dlpi_name
   is "[vdso]"/"[vvar]" or "linux-vdso.so.1"/"linux-gate.so.1". Never reject. */
static int is_kernel_pseudo(const char *p) {
    if (!p || !*p) return 0;
    if (p[0] == '[') return 1;
    if (strncmp(p, "linux-vdso.so.1", 15) == 0) return 1;
    if (strncmp(p, "linux-gate.so.1", 15) == 0) return 1;
    return 0;
}

static int ends_with(const char *s, const char *suf) {
    size_t sl = strlen(s), fl = strlen(suf);
    if (fl > sl) return 0;
    return memcmp(s + sl - fl, suf, fl) == 0;
}

static int scan_link_map_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    const char *nm = info->dlpi_name;
    if (!nm || !*nm) return 0;              /* main program: allow */
    if (verdict_cached(nm)) return 0;       /* already verified allowed */
    if (is_allowed_path(nm)) { verdict_add(nm); return 0; }
    if (is_kernel_pseudo(nm)) { verdict_add(nm); return 0; }
    /* Never flag the proxy itself, whatever path it was preloaded from
       (installed sysroot copy or a local build under test). */
    if (ends_with(nm, "/libnrld-proxy.so")) { verdict_add(nm); return 0; }
    if (!found_bad) {
        size_t n = strlen(nm);
        if (n >= sizeof(bad_path)) n = sizeof(bad_path) - 1;
        memcpy(bad_path, nm, n);
        bad_path[n] = '\0';
    }
    found_bad = 1;
    return 1;                                /* stop scanning */
}

/* After a dlopen, the object plus every library in its transitive NEEDED
   closure is already mapped. Return 1 if any of them is a musl /usr/lib
   build (ABI mix), 0 otherwise. */
static int dlopen_pulled_musl(void) {
    found_bad = 0;
    dl_iterate_phdr(scan_link_map_cb, NULL);
    return found_bad;
}

static void *verify_dlopen_handle(void *h, const char *filename) {
    if (!h || !strict_sysroot) return h;
    if (!dlopen_pulled_musl()) return h;
    reject_handle(h, bad_path[0] ? bad_path : (filename ? filename : "(sin nombre)"));
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  dlopen path redirection.                                           */
/*  Apps dlopen hard-coded HOST paths (/usr/lib/libpulse.so.0, gio's   */
/*  compiled-in /usr/lib64/gio/modules/..., GTK's /usr/lib/gtk-3.0/...)*/
/*  which name MUSL builds on this host. If the SAME relative path     */
/*  exists inside the glibc sysroot (a genuine glibc build), call the  */
/*  real dlopen on that instead; otherwise leave the path untouched so */
/*  the strict link-map scan below can still reject the musl fallback. */
/* ------------------------------------------------------------------ */
static const char *redirect_to_sysroot(const char *path) {
    static char out[4096];
    if (!path || !*path || path[0] != '/') return path;
    for (int i = 0; i < 8; i++) {
        size_t hl = strlen(redirect_maps[i].host);
        if (strncmp(path, redirect_maps[i].host, hl) != 0) continue;
        const char *rest = path + hl;
        size_t total = strlen(redirect_maps[i].sys) + strlen(rest) + 1;
        if (total > sizeof(out)) break;
        strcpy(out, redirect_maps[i].sys);
        strcat(out, rest);
        if (access(out, R_OK) == 0) return out;
        break;
    }
    return path;
}

void *dlopen(const char *filename, int flag) {
    void *(*real_dlopen)(const char *, int);
    real_dlopen = (void *(*)(const char *, int))dlsym(RTLD_NEXT, "dlopen");
    if (!g_glibc_host) return real_dlopen ? real_dlopen(filename, flag) : NULL;
    const char *use = redirect_to_sysroot(filename);
    void *h = real_dlopen ? real_dlopen(use, flag) : NULL;
    if (!h) return h;
    return verify_dlopen_handle(h, use);
}

void *dlmopen(Lmid_t lmid, const char *filename, int flag) {
    void *(*real_dlmopen)(Lmid_t, const char *, int);
    real_dlmopen = (void *(*)(Lmid_t, const char *, int))dlsym(RTLD_NEXT, "dlmopen");
    if (!g_glibc_host) return real_dlmopen ? real_dlmopen(lmid, filename, flag) : NULL;
    const char *use = redirect_to_sysroot(filename);
    void *h = real_dlmopen ? real_dlmopen(lmid, use, flag) : NULL;
    if (!h) return h;
    return verify_dlopen_handle(h, use);
}

