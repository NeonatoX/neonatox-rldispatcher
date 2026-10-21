#ifndef NRRLD_SYSROOT_MANAGER_H
#define NRRLD_SYSROOT_MANAGER_H

/* ================================================================== */
/*  sysroot_manager.h -- resolucion de librerias en el sysroot glibc  */
/*  y configuracion de nrld (/etc/nrld.conf).                          */
/*                                                                     */
/*  Aqui vive la politica de aislamiento musl<->glibc: que sonames se  */
/*  pueden resolver, cuales faltan (y por tanto caerian a /usr/lib     */
/*  musl) y como se parchean los DT_NEEDED absolutos.                  */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h.                   */
/*  El estado (config, shadow copies, dirs extra) es PRIVADO: se      */
/*  expone con funciones de acceso, nunca con globales abiertos.      */
/* ================================================================== */

/* Fichero de configuracion de nrld (instalado en el HOST, no en el
   sysroot, para que pueda apuntar a cualquier sysroot/proxy). */
#define NRLCONF_PATH "/etc/nrld.conf"

/* Config (/etc/nrld.conf) */
void        sysroot_load_conf(void);
int         sysroot_conf_strict(void);
int         sysroot_conf_log_level(void);
const char *sysroot_conf_libpath(void);
const char *sysroot_conf_proxy(void);

/* Resolucion de sonames. Devuelve 1 y rellena `out` con la ruta resuelta. */
int resolve_lib_path(const char *soname, const char *lib_root, char *out);

/* Guard transitivo de DT_NEEDED. Devuelve el numero de sonames que no
   se pueden resolver dentro del sysroot (0 = todo OK). */
int check_needed_libs(const char *path, const char *bin_dir);

/* Directorios extra donde buscar librerias (AppImage interno, subdirs
   no estandar del sysroot). */
#define MAX_EXTRA_DIRS 16
void        sysroot_reset_extra_libdirs(void);
void        sysroot_add_extra_libdir(const char *dir);
int         sysroot_extra_libdir_count(void);
const char *sysroot_extra_libdir(int i);

/* Anade a `buf` (separados por ':') los subdirectorios de librerias que
   existen bajo `root`, mas los directorios extra registrados. */
void append_lib_subdirs(char *buf, const char *root);

/* Directorio con las copias parcheadas de DT_NEEDED absolutos
   (/tmp/nrld-patch-<pid>), o "" si no se creo ninguno. */
const char *sysroot_patch_dir(void);
int         sysroot_patch_dir_set(void);

/* Copia parcheada del binario principal ("" si no hizo falta). */
const char *sysroot_top_patch(void);

#endif /* NRRLD_SYSROOT_MANAGER_H */
