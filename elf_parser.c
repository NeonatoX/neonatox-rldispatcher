/* ================================================================== */
/*  elf_parser.c -- lectura y parcheo de ficheros ELF.                 */
/*                                                                     */
/*  Solo se ocupa del FORMATO: e_ident, DT_NEEDED, PT_INTERP y las     */
/*  copias parcheadas que nrld ejecuta en lugar del binario original.  */
/*  No decide nada sobre el sysroot (eso es sysroot_manager.c) ni     */
/*  sobre como se ejecuta (eso es executor.c).                         */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h.                                */
/*                                                                     */
/*  Conceptos clave:                                                  */
/*    - PT_INTERP reescrito: la copia <base>-nrld-<pid> se crea en el  */
/*      propio dir de la app (para que /proc/self/exe, recursos,      */
/*      omni.ja, etc. sigan resolviendo igual). El loader real se     */
/*      incrusta al EOF de la copia, asi que no hay limite de        */
/*      longitud del path.                                             */
/*    - EI_ABIVERSION != 0 (AppImage/type-2): el loader glibc         */
/*      rechaza el fichero antes de mirar los NEEDED, asi que se      */
/*      crea una copia con el byte a 0 en /tmp/nrld-<pid>/.           */
/*    - Self-sweep: al crear una copia se borran las copias viejas    */
/*      que ningun proceso vivo tiene como /proc/self/exe.            */
/* ================================================================== */

#include "utils.h"
#include "nrld_paths.h"
#include "elf_parser.h"

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define DT_NEEDED  1
#define DT_STRTAB  5
#define DT_STRSZ   10
#define DT_SONAME  14

/* Ruta de la copia con el e_ident parcheado ("" si no se creo ninguna). */
static char g_patched_bin[4096];

/* Ruta de la copia con el PT_INTERP reescrito. */
static char g_interp_bin[4096];

int read_eident(const char *path, char *eident) {
    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return 0;
    long n = syscall3(SYS_read, fd, (long)eident, 16);
    syscall1(SYS_close, fd);
    return n == 16;
}

int is_elf(const char *path) {
    char header[4];
    long fd = syscall2(SYS_open, (long)path, 0);
    if (fd < 0) return 0;
    long n = syscall3(SYS_read, fd, (long)header, 4);
    syscall1(SYS_close, fd);  // close fd
    if (n != 4) return 0;
    return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
}

/* Copies src to an empty file dst(already opened for write) in chunks of
   CHUNK bytes starting from the file's current offset. */
#define COPY_CHUNK 65536
static char copy_buf[COPY_CHUNK];

long copy_file_contents(long srcfd, long dstfd) {
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
const char *maybe_patch_abi_version(const char *path) {
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

const char *elf_abi_patch_path(void) {
    return g_patched_bin;
}

int get_needed_names(const char *path, char names[][256], int max,
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

/* ------------------------------------------------------------------ */
/*  Copia con PT_INTERP reescrito al loader glibc real.                */
/*                                                                      */
/*  Si el loader real se ejecuta como el programa PRINCIPAL (viejo      */
/*  esquema de modo usuario: execve(REAL_LOADER, [--library-path...])),*/
/*  el kernel pone /proc/self/exe = loader. Las apps que re-ejecutan   */
/*  su propio binario desde /proc/self/exe (los procesos de contenido   */
/*  de Firefox/Chromium lo hacen con open+read o un readlink crudo,     */
/*  saltandose nuestro readlink interposed) vuelven a ejecutar el      */
/*  loader COMO programa: glibc toma el primer argv no-opcion como la  */
/*  app, falla y sale con 1 (la tormenta de "process N exited with    */
/*  status 1" observada).                                             */
/*  Solucion: producir una COPIA de la app en su propio directorio cuyo */
/*  PT_INTERP se reescribe a REAL_LOADER (string incrustado al EOF,    */
/*  asi que no hay limite de longitud). Al hacer execve de la copia el  */
/*  kernel carga el loader real IN-PROCESS como un interp normal,      */
/*  /proc/self/exe sigue siendo la copia (mismo dir que la app ->       */
/*  omni.ja/icudtl.dat/resources siguen resolviendo) y los hijos que   */
/*  re-ejecutan su binario funcionan por cualquier mecanismo.          */
/*  El entorno (LD_LIBRARY_PATH/LD_PRELOAD/GCONV_PATH/NEONATOX_*) se   */
/*  hereda, asi que el loader in-process se configura igual.            */
/*                                                                      */
/*  Cada ejecucion deja <dir>/<base>-nrld-<pid> (los hijos siguen     */
/*  re-ejecutando esa ruta exacta). Para no acumular basura, la        */
/*  siguiente ejecucion para el mismo <base> barre las copias viejas:  */
/*  una copia se conserva solo mientras algun proceso vivo la tiene     */
/*  como /proc/self/exe (su arbol de la app sigue corriendo).          */
/* ------------------------------------------------------------------ */

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
            /* Match "<base>-nrld-<pid>" (kept copy from a previous run).
               Also sweep the legacy dotted format ".<base>.nrld-<pid>"
               (nomeclatura previa al cambio a guiones). */
            const char *suf;
            if (my_starts_with(nm, base) && my_starts_with(nm + base_len, "-nrld-")) {
                suf = nm + base_len + 6;
            } else if (nm[0] == '.' && my_starts_with(nm + 1, base) &&
                       my_starts_with(nm + 1 + base_len, ".nrld-")) {
                suf = nm + 1 + base_len + 6;
            } else {
                off += de->d_reclen;
                continue;
            }
            const char *d = suf;
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

const char *make_interp_patched_copy(const char *src) {
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

    /* Output path: same dir as src -> "<dir>/<base>-nrld-<pid>". Uses the
       base name unchanged, no leading dot and no dotted suffix, so the copy
       is a visible, plain-named file (cosmetic; the Chromium/Electron SIGTRAP
       was actually the proxy's /proc/self/exe rewrite, now gated to
       loader-as-main only). The "-nrld-<pid>" suffix keeps the per-run copy
       unique (multi-instance) so children that re-exec /proc/self/exe keep
       using their own copy, which the residue sweep still matches. */
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
    my_strcat(g_interp_bin, "-nrld-");
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
