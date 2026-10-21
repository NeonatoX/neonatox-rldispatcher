#ifndef NRRLD_PATHS_H
#define NRRLD_PATHS_H

/* ================================================================== */
/*  nrld_paths.h -- rutas y constantes de compilacion de nrld.         */
/*                                                                     */
/*  Defaults de instalacion, sobrescribibles en tiempo de compilacion  */
/*  (meson pasa -DNEO_SYSROOT/-DNEO_BINDIR). /usr/lib/glibc6 sigue    */
/*  siendo el sysroot por defecto.                                     */
/*                                                                     */
/*  Depende de: nada (cabecera de constantes puras).                   */
/* ================================================================== */

#ifndef NEO_SYSROOT
#define NEO_SYSROOT   "/usr/lib/glibc6"
#endif
#ifndef NEO_BINDIR
#define NEO_BINDIR    "/usr/lib/neonatox"
#endif

#define REAL_LOADER   NEO_SYSROOT "/usr/lib/ld-linux-x86-64.so.2"
#define FAKE_LOADER   NEO_BINDIR "/nrld"
#define INTERP_PATH   "/lib64/ld-linux-x86-64.so.2"
#define INTERP_TMP    "/lib64/ld-linux-x86-64.so.2.tmp"
#define SYSROOT_LIBS  NEO_SYSROOT "/usr/lib:" NEO_SYSROOT "/lib"
#define GCONV_DIR     NEO_SYSROOT "/usr/lib/gconv"
#define PROXY_LIB     NEO_BINDIR "/libnrld-proxy.so"

#endif /* NRRLD_PATHS_H */
