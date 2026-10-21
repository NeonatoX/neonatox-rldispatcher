/* ================================================================== */
/*  utils.c -- capa base: syscalls, strings, logging y helpers.        */
/*                                                                     */
/*  Implementacion de utils.h. No depende de ningun otro modulo:      */
/*  es la hoja de la piramide (utils <- elf_parser <- sysroot_manager */
/*  <- appimages <- executor <- nrld).                                */
/*                                                                     */
/*  LOGGING: el diagnostico va SIEMPRE a stderr y es silencioso por    */
/*  defecto (nivel 0 = solo [ERROR]); print_out (stdout) se reserva   */
/*  para lo que el usuario pidio explicitamente (--help).             */
/* ================================================================== */

#include "utils.h"

long syscall1(long num, long arg1) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1) : "rcx", "r11", "memory");
    return ret;
}

long syscall0(long num) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num) : "rcx", "r11", "memory");
    return ret;
}

long syscall2(long num, long arg1, long arg2) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1), "S"(arg2) : "rcx", "r11", "memory");
    return ret;
}

long syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3) : "rcx", "r11", "memory");
    return ret;
}

long syscall4(long num, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(num), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

unsigned long my_strlen(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    return len;
}

int my_starts_with(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++; prefix++;
    }
    return 1;
}

void my_strcpy(char *dst, const char *src) {
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

void my_strcat(char *dst, const char *src) {
    while (*dst) dst++;
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

int my_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ------------------------------------------------------------------ */
/*  Log por niveles. Investigacion_05: nrld escribia TODO su           */
/*  diagnostico a stdout, rompiendo protocolos que capturan stdout     */
/*  (command substitution de make, lto-wrapper/collect2, pipes glibc): */
/*  las lineas [DEBUG]/[ADV] acababan como argumentos de ld. Ahora el  */
/*  diagnostico va SIEMPRE a stderr (fd 2), es SILENCIOSO por defecto  */
/*  (nivel 0: solo [ERROR]) y se reactiva via NRLD_DEBUG=<0-3>,        */
/*  log_level en /etc/nrld.conf o --verbose en modo manual.            */
/* ------------------------------------------------------------------ */

int      g_log_level = LOG_OFF;
char     g_log_buf[1024];
unsigned g_log_len = 0;

/* Nivel de una linea segun el prefijo. Las lineas sin prefijo
   reconocible (fragmentos de datos) se tratan como debug: solo visibles
   en el nivel mas alto, para que nunca contaminen por defecto. */
static int log_level_for_line(const char *line, unsigned long len) {
    if (len >= 7 && my_starts_with(line, "[ERROR]")) return LOG_OFF;
    if (len >= 5 && my_starts_with(line, "[ADV]"))   return LOG_WARN;
    if (len >= 6 && my_starts_with(line, "[INFO]"))  return LOG_INFO;
    if (len >= 4 && my_starts_with(line, "[OK]"))    return LOG_INFO;
    return LOG_DEBUG;
}

static void log_flush(void) {
    if (!g_log_len) return;
    int line_level = log_level_for_line(g_log_buf, g_log_len);
    if (line_level == LOG_OFF || g_log_level >= line_level) {
        syscall3(SYS_write, 2, (long)g_log_buf, g_log_len);
    }
    g_log_len = 0;
}

/* Diagnostico: stderr (fd 2), linea a linea, nivel derivado del prefijo
   de cada linea. NUNCA escribe a stdout: ahi vive la salida del programa. */
void print_msg(const char *msg) {
    unsigned long len = my_strlen(msg);
    for (unsigned long i = 0; i < len; i++) {
        if (g_log_len >= sizeof(g_log_buf) - 1) log_flush();
        g_log_buf[g_log_len++] = msg[i];
        if (msg[i] == '\n') log_flush();
    }
}

/* Salida pedida por el usuario (--help): stdout (fd 1). */
void print_out(const char *msg) {
    syscall3(SYS_write, 1, (long)msg, my_strlen(msg));
}

/* Errores duros: SIEMPRE a stderr, sin importar el nivel de log. */
void print_err(const char *msg) {
    syscall3(SYS_write, 2, (long)msg, my_strlen(msg));
}

int file_exists(const char *path) {
    long ret = syscall2(SYS_access, (long)path, 0);
    return ret == 0;
}

int uint_to_str(long value, char *buf, int bufsz) {
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

long read_at(long fd, unsigned long off, char *buf, unsigned long want) {
    if (syscall3(SYS_lseek, fd, off, 0) < 0) return -1;   /* SEEK_SET */
    unsigned long got = 0;
    while (got < want) {
        long n = syscall3(SYS_read, fd, (long)(buf + got), want - got);
        if (n <= 0) break;
        got += (unsigned long)n;
    }
    return (long)got;
}

int resolve_path(const char *relative, char *absolute, int max_len) {
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

int can_write_dir(const char *path) {
    return syscall2(SYS_access, (long)path, 2) == 0;   /* W_OK */
}

void get_directory(const char *path, char *dir, int max_len) {
    my_strcpy(dir, path);
    char *last_slash = 0;
    for (char *p = dir; *p; p++) {
        if (*p == '/') last_slash = p;
    }
    if (last_slash) *last_slash = '\0';
    else my_strcpy(dir, ".");
}

/* rm -rf: borra recursivamente un arbol (usado para limpiar extracciones
   de AppImage y dirs de parches en /tmp). */
void rm_rf(const char *path) {
    long fd = syscall2(SYS_open, (long)path, 0);
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
            char child[4096];
            my_strcpy(child, path); my_strcat(child, "/"); my_strcat(child, nm);
            if ((de->d_type & 0xf) == 4) {
                rm_rf(child);
            } else {
                syscall1(SYS_unlink, (long)child);
            }
            off += de->d_reclen;
        }
    }
    syscall1(SYS_close, fd);
    syscall1(SYS_rmdir, (long)path);
}
