#ifndef NRRLD_UTILS_H
#define NRRLD_UTILS_H

/* ================================================================== */
/*  utils.h -- capa base: syscalls, strings, logging y helpers.        */
/*                                                                     */
/*  Es la base de la piramide de modulos de nrld: NO depende de       */
/*  ningun otro modulo (ni de sus cabeceras). Solo ofrece primitivas  */
/*  freestanding que el resto reutiliza.                              */
/*                                                                     */
/*  Freestanding: no usa libc (ni malloc, ni printf). Todo el acceso */
/*  al sistema se hace con syscalls crudos x86-64 (instruccion        */
/*  `syscall`). Los buffers son del llamante: no hay asignacion de    */
/*  memoria dinamica en todo el proyecto.                             */
/*                                                                     */
/*  Contenido:                                                        */
/*    - numeros de syscall (SYS_*)                                    */
/*    - struct nrl_dirent64 (entrada de getdents64)                   */
/*    - syscall0..4: wrappers crudos                                  */
/*    - strings: my_strlen/my_starts_with/my_strcpy/my_strcat/...     */
/*    - logging por niveles (LOG_*, print_msg/print_out/print_err)    */
/*    - helpers de fichero: file_exists, uint_to_str, read_at         */
/*    - helpers de ruta: resolve_path, get_directory, can_write_dir   */
/*    - rm_rf: borrado recursivo de un arbol                          */
/* ================================================================== */

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
#define SYS_getppid  110
#define SYS_kill     62
#define SYS_nanosleep 35
#define SYS_mkdir    83
#define SYS_fstat    5
#define SYS_openat   257
#define SYS_mmap     9
#define SYS_getdents64 217
#define SYS_readlink   89
#define SYS_rmdir      84

/* Entrada de directorio (getdents64). Formato del kernel, igual para todos
   los recorridos de /proc y /tmp que hace nrld. */
struct nrl_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

/* syscalls crudos (x86-64) */
long syscall0(long num);
long syscall1(long num, long arg1);
long syscall2(long num, long arg1, long arg2);
long syscall3(long num, long arg1, long arg2, long arg3);
long syscall4(long num, long a1, long a2, long a3, long a4);

/* strings */
unsigned long my_strlen(const char *s);
int   my_starts_with(const char *str, const char *prefix);
void  my_strcpy(char *dst, const char *src);
void  my_strcat(char *dst, const char *src);
int   my_strcmp(const char *a, const char *b);

/* logging por niveles (Investigacion_05: siempre a stderr) */
#define LOG_OFF   0   /* solo [ERROR]                    */
#define LOG_WARN  1   /* + [ADV]                         */
#define LOG_INFO  2   /* + [INFO]/[OK]                   */
#define LOG_DEBUG 3   /* + [DEBUG] y lineas sin prefijo  */

extern int      g_log_level;
extern char     g_log_buf[1024];
extern unsigned g_log_len;

void print_msg(const char *msg);   /* diagnostico -> stderr, filtrado por nivel */
void print_out(const char *msg);   /* salida del usuario (--help) -> stdout */
void print_err(const char *msg);   /* errores duros -> stderr, siempre visible */

/* helpers de fichero */
int  file_exists(const char *path);
int  uint_to_str(long value, char *buf, int bufsz);
long read_at(long fd, unsigned long off, char *buf, unsigned long want);

/* helpers de rutas */
int  resolve_path(const char *relative, char *absolute, int max_len);
void get_directory(const char *path, char *dir, int max_len);

/* 1 si el proceso puede escribir en `path` (access W_OK). nrld lo usa para
   decidir si puede entrar en modo root (swap de symlink en /lib64). */
int  can_write_dir(const char *path);

/* borrado recursivo de un arbol de ficheros (rm -rf) */
void rm_rf(const char *path);

#endif /* NRRLD_UTILS_H */
