#ifndef NRRLD_APPIMAGES_H
#define NRRLD_APPIMAGES_H

/* ================================================================== */
/*  appimages.h -- AppImage type-2 (squashfs embebido).                 */
/*                                                                     */
/*  Extrae el AppImage a /tmp con `unsquashfs` del host (musl) y      */
/*  localiza el binario interno mas sus directorios de librerias.     */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h,                   */
/*               sysroot_manager.h (para registrar los dirs extra).    */
/*  El estado (raiz de extraccion, binario interno, plugin Qt) es     */
/*  PRIVADO: se expone con funciones de acceso.                       */
/* ================================================================== */

/* 1 si el fichero es un AppImage type-2 (e_ident no estandar + squashfs). */
int is_appimage(const char *path);

/* Extrae el AppImage a /tmp/nrld-appimage-<pid>/ y localiza el binario
   interno. Devuelve 1 si la extraccion tuvo exito. */
int extract_appimage(const char *path);

/* Raiz de la extraccion ("" si no se extrajo nada). */
const char *appimage_root(void);

/* Binario interno a ejecutar ("" si no se determino). */
const char *appimage_bin(void);

/* 1 si la extraccion se completo. */
int appimage_extracted(void);

/* 1 si el AppRun es un script #! (se ejecuta tal cual). */
int appimage_is_script(void);

/* Path del directorio de plugins Qt ("" si no se encontro). */
const char *appimage_qt_plugin_path(void);

#endif /* NRRLD_APPIMAGES_H */
