/* ================================================================== */
/*  executor.c -- flujo principal de nrld.                              */
/*                                                                     */
/*  Decide el modo (root / usuario), arma el entorno y lanza el        */
/*  binario. Es el unico modulo que conoce argv/envp/auxv.             */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h,                   */
/*               sysroot_manager.h, appimages.h.                       */
/*                                                                     */
/*  Conceptos clave:                                                  */
/*    - Como se sabe el binario real: como PT_INTERP el kernel        */
/*      reemplaza argv[0] por nuestro path y deja argv[1] como el    */
/*      primer argumento de la app; el binario real llega por         */
/*      AT_EXECFN (auxv). El modo manual (nrld BIN) es la excepcion.  */
/*    - Modo ROOT: fork + swap de symlinks en /lib64, se ejecuta con  */
/*      el loader real y luego se restauran los symlinks.              */
/*    - Modo USUARIO: copia parcheada <base>-nrld-<pid> en el dir de   */
/*      la app, con PT_INTERP = loader real. El kernel carga el       */
/*      loader glibc IN-PROCESS, /proc/self/exe sigue siendo la app   */
/*      y LD_LIBRARY_PATH/LD_PRELOAD se heredan del env.               */
/*    - Watchdog: antes del execve de la copia se fork un vigilante   */
/*      que espera a que la app muera y borra los residuos del run     */
/*      (copia, dir ABI, extraccion AppImage, parches NEEDED).        */
/* ================================================================== */

#include "utils.h"
#include "nrld_paths.h"
#include "elf_parser.h"
#include "sysroot_manager.h"
#include "appimages.h"
#include "executor.h"

typedef struct { long a_type; long a_val; } Elf64_auxv_t;
#define AT_NULL    0
#define AT_EXECFN  31

/* Buffers de variables de entorno que se inyectan al hijo. */
static char g_new_ld_path[16384];
static char g_gconv[256];
static char g_lib_paths[16384];
static char g_real_exe[4096];
static char g_ld_preload[512];
static char g_sysroot_env[512];
static char g_strict_env[64];
static char g_appdir_env[512];
static char g_qt_env[1024];
static char g_patch_env[4096];

/* Launcher estilo mozilla (firefox/firefox-bin, thunderbird/thunderbird-bin,
   ...): el target es un ELF pequeno cuyo main resuelve el binario real
   desde readlink("/proc/self/exe") y le anade "-bin". En modo usuario nrld
   ejecuta la copia parcheada <base>-nrld-<pid>; como /proc/self/exe es esa
   copia, la derivacion da <base>-nrld-<pid>-bin -> "Exec failed with error:
   No such file or directory" (regresion Firefox moderno + ESR). Si en el
   mismo dir existe el hermano <base>-bin (ELF), ejecutar directamente ese
   binario real evita el launcher y su derivacion. Solo aplica en modo
   usuario; en modo ROOT el launcher corre nativo y resuelve bien. */
static const char *launcher_bin_redirect(const char *run_path) {
    static char g_alt_bin[4096];
    const char *base = run_path;
    for (const char *p = run_path; *p; p++) {
        if (*p == '/') base = p + 1;
    }

    get_directory(run_path, g_alt_bin, sizeof(g_alt_bin));
    if (my_strlen(g_alt_bin) + my_strlen(base) + 6 >= sizeof(g_alt_bin)) {
        return 0;
    }
    my_strcat(g_alt_bin, "/");
    my_strcat(g_alt_bin, base);
    my_strcat(g_alt_bin, "-bin");

    if (!file_exists(g_alt_bin)) return 0;
    if (!is_elf(g_alt_bin)) return 0;
    return g_alt_bin;
}

/* Limpieza per-ejecucion tras la muerte de la app. nrld hace execve de la
   copia parcheada, asi que nrld ES la app y no puede borrarla al salir. Un
   watchdog fork antes del exec espera a que el proceso padre (mismo pid que
   la app tras el execve) muera y borra los residuos de este lanzamiento:
   la copia <base>-nrld-<pid>, el dir ABI /tmp/nrld-<pid>, la extraccion del
   AppImage y los parches de DT_NEEDED absolutos. El sweep de la siguiente
   ejecucion queda como red de seguridad para casos marginales (app muerta
   por kill/Ctrl-C: ambos procesos reciben la senal y el watchdog no llega a
   limpiar; hijo superviviente que re-ejecuta la copia tras el padre). */
static void cleanup_run_residue(const char *interp_copy) {
    if (interp_copy) {
        syscall2(SYS_unlink, (long)interp_copy, 0);
    }
    const char *abi = elf_abi_patch_path();
    if (abi[0]) {
        syscall2(SYS_unlink, (long)abi, 0);
        char abidir[4096];
        my_strcpy(abidir, abi);
        char *ls = abidir;
        for (char *p = abidir; *p; p++) if (*p == '/') ls = p;
        if (*ls == '/') {
            *ls = '\0';
            syscall1(SYS_rmdir, (long)abidir);
        }
    }
    if (appimage_root()[0]) rm_rf(appimage_root());
    if (sysroot_patch_dir()[0]) rm_rf(sysroot_patch_dir());
}

/* Espera a que el proceso padre (el pid que tras el execve es la app) ya no
   exista. Se usa kill(pid,0) (senal de prueba) por si el padre sigue como
   zombie antes de que el shell lo reapare; en ese caso se comprueba su
   estado en /proc/<pid>/stat. */
static void wait_parent_dead(void) {
    long parent = syscall0(SYS_getppid);
    for (;;) {
        if (syscall2(SYS_kill, parent, 0) < 0) return;
        char sp[40];
        my_strcpy(sp, "/proc/");
        char pb[24];
        uint_to_str(parent, pb, sizeof(pb));
        my_strcat(sp, pb);
        my_strcat(sp, "/stat");
        long fd = syscall2(SYS_open, (long)sp, 0);
        if (fd >= 0) {
            char buf[128];
            long n = syscall3(SYS_read, fd, (long)buf, sizeof(buf) - 1);
            syscall1(SYS_close, fd);
            if (n > 0) {
                buf[n] = '\0';
                for (long i = 0; i + 2 < n; i++) {
                    if (buf[i] == ')' && buf[i + 1] == ' ' && buf[i + 2] == 'Z') {
                        return;
                    }
                }
            }
        } else {
            return;
        }
        long ts[2] = { 0, 30000000 };   /* 30 ms */
        syscall2(SYS_nanosleep, (long)ts, 0);
    }
}

void print_usage_help(void) {
    print_out("NeonatoX RLDispatcher (nrld) -- fake glibc linker para hosts musl\n");
    print_out("\n");
    print_out("Aisla binarios glibc de las librerias musl de /usr/lib, ejecutandolos\n");
    print_out("con un glibc real y autosuficiente dentro de /usr/lib/glibc6 (sysroot).\n");
    print_out("\n");
    print_out("Uso:\n");
    print_out("  nrld --help                        Muestra esta ayuda\n");
    print_out("  nrld BIN [ARGOS...]                Ejecuta BIN glibc sobre el sysroot\n");
    print_out("  nrld [--verbose|--quiet] BIN ...   Ajusta el log de la ejecucion\n");
    print_out("  (instalado como /lib64/ld-linux-x86-64.so.2: los binarios con ese\n");
    print_out("   PT_INTERP se ejecutan solos con ./BIN, sin invocar nrld a mano)\n");
    print_out("\n");
    print_out("Que hace con BIN:\n");
    print_out("  1. Detecta el binario real (AT_EXECFN o argv[1]) y exige que sea ELF.\n");
    print_out("  2. AppImage type-2: extrae el squashfs a /tmp/nrld-appimage-<pid>/\n");
    print_out("     (sin FUSE, nunca escribe fuera de /tmp) y usa el binario interno\n");
    print_out("     mas sus dirs de librerias internas (lib/, usr/lib/<triplet>, ...).\n");
    print_out("  3. Guard transitivo de DT_NEEDED: verifica que cada libreria necesitada\n");
    print_out("     (y las de sus dependencias) resuelve dentro del sysroot glibc.\n");
    print_out("  4. Extralibfinder: si un soname falta en los dirs estandar, lo busca\n");
    print_out("     en subdirectorios no estandar del sysroot (gvfs/, pulseaudio/, ...)\n");
    print_out("     y anade ese dir a LD_LIBRARY_PATH / --library-path.\n");
    print_out("  5. Corrige DT_NEEDED absolutos creando copias parcheadas en\n");
    print_out("     /tmp/nrld-patch-<pid>/ (traducidos a soname resoluble por --library-path).\n");
    print_out("  6. Executa una copia parcheada (<base>-nrld-<pid>) de BIN en su\n");
    print_out("     propio directorio cuyo PT_INTERP apunta al loader glibc real (cargado\n");
    print_out("     in-process por el kernel): /proc/self/exe queda en el dir de la app,\n");
    print_out("     los hijos que re-ejecutan su propio binario funcionan. LD_PRELOAD con\n");
    print_out("     el proxy libnrld-proxy.so (scan strict de dlopen).\n");
    print_out("\n");
    print_out("Configuracion (/etc/nrld.conf, lo escribe el instalador; key = value):\n");
    print_out("  library_path = <dirs>      LD_LIBRARY_PATH (default: dirs del sysroot)\n");
    print_out("  proxy        = <ruta>      LD_PRELOAD (default: NEO_BINDIR/libnrld-proxy.so)\n");
    print_out("  strict                      modo estricto global (sin env)\n");
    print_out("  log_level    = <0-3>       nivel de log global (ver 'Salida')\n");
    print_out("\n");
    print_out("Modo estricto del sysroot (aislacion musl<->glibc):\n");
    print_out("  NEONATOX_STRICT_SYSROOT=1 ./BIN    falla limpio si falta algo\n");
    print_out("  echo strict > /etc/nrld.conf       hace estricto todo (sin env)\n");
    print_out("  (evita la mezcla de dos libcs en un proceso -> el SIGSEGV de strtod_l)\n");
    print_out("\n");
    print_out("Variables de entorno que nrld importa/exporta:\n");
    print_out("  NRLD_DEBUG=<0-3>           log de ESTE proceso (0=off,1=warn,2=info,3=debug)\n");
    print_out("  NEONATOX_STRICT_SYSROOT   strict por env (0/1)\n");
    print_out("  NEONATOX_REAL_EXE         ruta real del binario (la lee el proxy)\n");
    print_out("  NEONATOX_SYSROOT          root del sysroot (la lee el proxy)\n");
    print_out("  NEONATOX_PROXY            ruta del proxy a inyectar (test/avanzado)\n");
    print_out("  NEONATOX_APPDIR           raiz extraida de un AppImage\n");
    print_out("  NEONATOX_DUMPENV          dump del entorno del hijo a /tmp (debug)\n");
    print_out("  QT_PLUGIN_PATH            dir del plugin de plataforma Qt (si aplica)\n");
    print_out("\n");
    print_out("Salida (SILENCIO por defecto; diagnostico SOLO a stderr):\n");
    print_out("  nrld NO escribe a stdout: ahi vive la salida real del programa. Un\n");
    print_out("  loader real (ld.so) nunca escribe a stdout; re-escribirlo ahi rompia\n");
    print_out("  make $(shell ...), lto-wrapper/collect2 y los pipes glibc.\n");
    print_out("  Nivel 0: solo [ERROR] (default)   Nivel 1: + [ADV] avisos\n");
    print_out("  Nivel 2: + [INFO]/[OK]            Nivel 3: + [DEBUG] razonamiento\n");
    print_out("  Reactiva el log con NRLD_DEBUG=3 ./BIN, 'nrld --verbose BIN',\n");
    print_out("  o log_level = 3 en /etc/nrld.conf (global). --help si imprime (stdout).\n");
    print_out("\n");
    print_out("Copyright (C) 2026 Carlos Sanchez. Licencia GPL v3.\n");
}

void nrld_main(long *sp) {
    long argc = sp[0];
    char **argv = (char **)&sp[1];
    char **envp = &argv[argc + 1];

    /* Cargar /etc/nrld.conf (host): strict global + overrides library_path/
       proxy + log_level escritos por el instalador. Los defaults
       (NEO_SYSROOT dirs / NEO_BINDIR proxy) aplican si el archivo no
       existe. El nivel de log se fija ANTES de cualquier diagnostico:
       por defecto nrld es SILENCIOSO (nivel 0, solo [ERROR]). */
    sysroot_load_conf();
    g_log_level = sysroot_conf_log_level();
    for (char **e = envp; *e; e++) {
        if (my_starts_with(*e, "NRLD_DEBUG=")) {
            char lv = (*e)[11];
            if (lv >= '0' && lv <= '3') g_log_level = lv - '0';
            break;
        }
    }

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
    /* Flags solo cuando nrld fue invocado directamente (nunca como PT_INTERP,
       para no robarle flags a la app): --help, --verbose/-v (log al maximo),
       --quiet/-q (solo [ERROR]), antes de un BIN opcional. */
    int opt_idx = 1;
    if (nrld_launched) {
        while (opt_idx < argc && argv[opt_idx][0] == '-' &&
               argv[opt_idx][1] != '\0') {
            if (my_strcmp(argv[opt_idx], "--help") == 0 ||
                my_strcmp(argv[opt_idx], "-h") == 0) {
                print_usage_help();
                syscall1(SYS_exit, 0);
                return;
            }
            if (my_strcmp(argv[opt_idx], "--verbose") == 0 ||
                my_strcmp(argv[opt_idx], "-v") == 0) {
                g_log_level = LOG_DEBUG;
                opt_idx++;
                continue;
            }
            if (my_strcmp(argv[opt_idx], "--quiet") == 0 ||
                my_strcmp(argv[opt_idx], "-q") == 0) {
                g_log_level = LOG_OFF;
                opt_idx++;
                continue;
            }
            break;
        }
        if (opt_idx >= argc) {
            print_usage_help();
            syscall1(SYS_exit, 0);
            return;
        }
    }
    int manual = (opt_idx < argc && argv[opt_idx][0] != '-' && nrld_launched);

    /* El Parent de Firefox avisa con el PID de cada hijo que muere; poner el
       pid aqui permite correlacionar los warnings con la instancia de nrld. */
    {
        char pidb[16];
        uint_to_str(syscall0(SYS_getpid), pidb, sizeof(pidb));
        print_msg("[DEBUG] Starting RLDispatcher (pid ");
        print_msg(pidb);
        print_msg(")\n");
    }

    if (manual) {
        target_bin = argv[opt_idx];
        orig_args_start = opt_idx + 1;
        print_msg("[DEBUG] Manual mode (argv[");
        {
            char db[16];
            uint_to_str(opt_idx, db, sizeof(db));
            print_msg(db);
        }
        print_msg("] es path)\n");
    } else if (execfn) {
        target_bin = execfn;
        orig_args_start = 1;
        print_msg("[DEBUG] Direct mode (using AT_EXECFN)\n");
    } else {
        print_err("[ERROR] No se pudo determinar el binario\n");
        syscall1(SYS_exit, 1);
        return;
    }

    print_msg("[DEBUG] Target original: ");
    print_msg(target_bin);
    print_msg("\n");

    char target_bin_abs[4096];
    if (!resolve_path(target_bin, target_bin_abs, sizeof(target_bin_abs))) {
        print_err("[ERROR] No se pudo resolver ruta\n");
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
        print_err("[ERROR] Binario no existe: ");
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
    if (!sysroot_strict && sysroot_conf_strict()) {
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
            lib_root = appimage_root();
            guard_bin = appimage_bin();
            real_exe = appimage_bin();
            print_msg("[ADV] Extraida en: ");
            print_msg(appimage_root());
            print_msg("\n[ADV] Binario interno: ");
            print_msg(appimage_bin());
            print_msg("\n");
            if (sysroot_extra_libdir_count() > 0) {
                print_msg("[ADV] Libs internas en: ");
                for (int i = 0; i < sysroot_extra_libdir_count(); i++) {
                    if (i) print_msg(", ");
                    print_msg(sysroot_extra_libdir(i));
                }
                print_msg("\n");
            }
        } else {
            print_msg("[ADV] No se pudo extraer; intento con el ELF como esta\n");
        }
    }

    if (appimage_extracted() && appimage_is_script()) {
        /* AppRun es un script #! (entrada canonica del AppImage type-2: el
           runtime real solo execa AppRun). Ejecutarlo tal cual como haria ese
           runtime: bash (musl) del host corre el script y el script a su vez
           execa el ELF interno (heroic, etc.), que RE-entra a nrld como interp
           de un binario normal en este dir (modo usuario, copia parcheada).
           Con el env heredado + APPDIR=<raiz extraida> (que es lo que setea el
           runtime real y sin lo cual los scripts tipo Heroic no resuelven "$1").
           Nada de loader/copia de nrld aqui: meter el proxy glibc en el bash
           musl lo contaminaria; los LD_* correctos los construye la siguiente
           invocacion de nrld cuando el script execa el ELF interno. */
        print_msg("[ADV] AppRun es script (canonico): exec directo con APPDIR\n");
        char appdir_var[4100];
        my_strcpy(appdir_var, "APPDIR=");
        my_strcat(appdir_var, appimage_root());
        char appimage_var[4100];
        my_strcpy(appimage_var, "APPIMAGE=");
        my_strcat(appimage_var, target_bin_abs);
        int se_count = 0;
        for (char **e = envp; *e; e++) {
            if (!my_starts_with(*e, "APPDIR=") && !my_starts_with(*e, "APPIMAGE=")) se_count++;
        }
        char *script_envp[se_count + 3];
        int se_idx = 0;
        for (char **e = envp; *e; e++) {
            if (!my_starts_with(*e, "APPDIR=") && !my_starts_with(*e, "APPIMAGE=")) script_envp[se_idx++] = *e;
        }
        script_envp[se_idx++] = appdir_var;
        script_envp[se_idx++] = appimage_var;
        script_envp[se_idx] = (char *)0;
        int s_argc = argc - orig_args_start;
        char *sargv[s_argc + 2];
        sargv[0] = (char *)appimage_bin();
        for (int i = 0; i < s_argc; i++) {
            sargv[1 + i] = argv[orig_args_start + i];
        }
        sargv[s_argc + 1] = (char *)0;
        long sret = syscall3(SYS_execve, (long)sargv[0], (long)sargv, (long)script_envp);
        (void)sret;
        print_err("[ERROR] execve del AppRun script falló\n");
        syscall1(SYS_exit, 1);
        return;
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
    const char *top_patch = sysroot_top_patch();
    const char *run_path = maybe_patch_abi_version(top_patch[0] ? top_patch : real_exe);

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

    /* Receta verificada: ".:" (PWD) al inicio de LD_LIBRARY_PATH. Cada app
       glibc recibe este LD_LIBRARY_PATH aqui (el perfil global ya NO lo pone:
       esa via envenenaba los binarios musl). Los hijos heredan este env;
       los que lo pierdan (sandbox) resuelven via el cache ldconfig del
       sysroot. */
    my_strcpy(g_new_ld_path, "LD_LIBRARY_PATH=.:");
    if (sysroot_patch_dir_set()) {
        /* Patched shadows must win over the sysroot copies. */
        my_strcat(g_new_ld_path, sysroot_patch_dir());
        my_strcat(g_new_ld_path, ":");
    }
    my_strcat(g_new_ld_path, lib_root);
    append_lib_subdirs(g_new_ld_path, lib_root);
    my_strcat(g_new_ld_path, ":");
    my_strcat(g_new_ld_path, sysroot_conf_libpath()[0] ? sysroot_conf_libpath() : SYSROOT_LIBS);
    if (existing_ld_path) {
        my_strcat(g_new_ld_path, ":");
        my_strcat(g_new_ld_path, existing_ld_path);
    }

    my_strcpy(g_gconv, "GCONV_PATH=");
    my_strcat(g_gconv, GCONV_DIR);

    my_strcpy(g_lib_paths, "");
    if (sysroot_patch_dir_set()) {
        my_strcpy(g_lib_paths, sysroot_patch_dir());
        my_strcat(g_lib_paths, ":");
    }
    my_strcat(g_lib_paths, lib_root);
    append_lib_subdirs(g_lib_paths, lib_root);
    my_strcat(g_lib_paths, ":");
    my_strcat(g_lib_paths, sysroot_conf_libpath()[0] ? sysroot_conf_libpath() : SYSROOT_LIBS);

    my_strcpy(g_real_exe, "NEONATOX_REAL_EXE=");
    my_strcat(g_real_exe, real_exe);

    /* Root del sysroot para el proxy (allowlist de dlopen + redireccion): el
       proxy lo honra si esta seteada, con este default como compile-time. */
    my_strcpy(g_sysroot_env, "NEONATOX_SYSROOT=");
    my_strcat(g_sysroot_env, NEO_SYSROOT);

    if (sysroot_patch_dir_set()) {
        /* Allow the proxy (which enforces the sysroot dlopen allowlist) to
           accept objects loaded from the patch dir too. */
        my_strcpy(g_patch_env, "NEONATOX_PATCH_DIR=");
        my_strcat(g_patch_env, sysroot_patch_dir());
    }

    if (appimage_extracted()) {
        /* Allow the proxy to accept objects loaded from the extracted
           AppImage tree (/tmp/nrld-appimage-<pid>/). */
        my_strcpy(g_appdir_env, "NEONATOX_APPDIR=");
        my_strcat(g_appdir_env, appimage_root());
        if (appimage_qt_plugin_path()[0]) {
            /* Qt: tell the app where its platform/imageformats plugins live
               (<QT_PLUGIN_PATH>/platforms/libqxcb.so). */
            my_strcpy(g_qt_env, "QT_PLUGIN_PATH=");
            my_strcat(g_qt_env, appimage_qt_plugin_path());
        }
    }

    /* Override de LD_PRELOAD: NEONATOX_PROXY=<ruta> (simetrico a
       NEONATOX_SYSROOT que ya honra el proxy). Prioridad: env > conf >
       default NEO_BINDIR. Ademas de utilidad general (probar un proxy
       distinto sin reinstalar), es lo que usa el E2E para ejercitar el
       proxy recien compilado del build/ sin tocar la instalacion. */
    const char *env_proxy = 0;
    for (char **e = envp; *e; e++) {
        if (my_starts_with(*e, "NEONATOX_PROXY=")) { env_proxy = *e + 15; break; }
    }
    my_strcpy(g_ld_preload, "LD_PRELOAD=");
    if (env_proxy && *env_proxy) {
        my_strcat(g_ld_preload, env_proxy);
    } else {
        my_strcat(g_ld_preload, sysroot_conf_proxy()[0] ? sysroot_conf_proxy() : PROXY_LIB);
    }

    char *new_envp[clean_count + 10];
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
    new_envp[env_idx++] = g_sysroot_env;
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

    /* Launcher mozilla: en modo usuario el launcher deriva <base>-bin desde
       /proc/self/exe (la copia) y falla; usar el binario real directamente. */
    const char *exec_path = run_path;
    if (!have_root) {
        const char *alt_bin = launcher_bin_redirect(run_path);
        if (alt_bin) {
            print_msg("[ADV] Launcher con hermano -bin detectado: ejecutando el binario real\n");
            exec_path = alt_bin;
        }
    }

    if (have_root) {
        print_msg("[DEBUG] Modo ROOT: fork + swap symlink\n");
        long pid = syscall1(SYS_fork, 0);

        if (pid < 0) {
            print_err("[ERROR] fork falló\n");
            syscall1(SYS_exit, 1);
            return;
        }

        if (pid == 0) {
            syscall2(SYS_unlink, (long)INTERP_TMP, 0);
            if (syscall2(SYS_symlink, (long)REAL_LOADER, (long)INTERP_TMP) < 0) {
                print_err("[ERROR] HIJO: symlink falló\n");
                syscall1(SYS_exit, 1);
                return;
            }
            if (syscall2(SYS_rename, (long)INTERP_TMP, (long)INTERP_PATH) < 0) {
                print_err("[ERROR] HIJO: rename falló\n");
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

            print_err("[ERROR] HIJO: execve falló\n");
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

        cleanup_run_residue(0);

        int exit_code = (status >> 8) & 0xFF;
        syscall1(SYS_exit, exit_code);
        return;
    }

    print_msg("[DEBUG] Modo USUARIO: exec de copia con PT_INTERP -> loader real in-process\n");

    const char *interp_run = make_interp_patched_copy(exec_path);
    if (interp_run) {
        char *bin_argv[orig_argc + 4];
        bin_argv[0] = (char *)exec_path;
        for (int i = 0; i < orig_argc; i++) {
            bin_argv[1 + i] = argv[orig_args_start + i];
        }
        bin_argv[orig_argc + 1] = (char *)0;

        print_msg("[DEBUG] Ejecutando copia parcheada: ");
        print_msg(interp_run);
        print_msg("\n");

        /* Watchdog: hijo que espera a la app (su padre, mismo pid tras el
           execve) y borra la copia parcheada + residuos /tmp de este run. */
        long wpid = syscall1(SYS_fork, 0);
        if (wpid == 0) {
            wait_parent_dead();
            cleanup_run_residue(interp_run);
            syscall1(SYS_exit, 0);
        }

        long ret = syscall3(SYS_execve, (long)interp_run, (long)bin_argv, (long)new_envp);
        if (ret >= 0) return;

        print_err("[ERROR] execve de la copia falló; reintento con el loader real\n");
        syscall1(SYS_unlink, (long)interp_run);
    } else {
        print_msg("[DEBUG] No se pudo crear la copia (dir no escribible?); loader como principal\n");
    }

    print_msg("[DEBUG] Modo USUARIO: execve directo al loader real con LD_PRELOAD\n");

    char *loader_argv[orig_argc + 5];
    loader_argv[0] = REAL_LOADER;
    loader_argv[1] = "--library-path";
    loader_argv[2] = g_lib_paths;
    loader_argv[3] = (char *)exec_path;
    for (int i = 0; i < orig_argc; i++) {
        loader_argv[4 + i] = argv[orig_args_start + i];
    }
    loader_argv[orig_argc + 4] = (char *)0;

    print_msg("[DEBUG] Ejecutando: ");
    print_msg(REAL_LOADER);
    print_msg(" --library-path ");
    print_msg(g_lib_paths);
    print_msg(" ");
    print_msg(exec_path);
    print_msg("\n");

    long ret = syscall3(SYS_execve, (long)loader_argv[0], (long)loader_argv, (long)new_envp);

    print_err("[ERROR] execve falló con código ");
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
