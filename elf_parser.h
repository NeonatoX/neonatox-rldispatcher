#ifndef NRRLD_ELF_PARSER_H
#define NRRLD_ELF_PARSER_H

/* ================================================================== */
/*  elf_parser.h -- lectura y parcheo de ficheros ELF.                 */
/*                                                                     */
/*  Solo se ocupa del FORMATO binario: cabecera e_ident, tabla de     */
/*  NEEDED (DT_NEEDED/PT_DYNAMIC/PT_LOAD), PT_INTERP y las copias      */
/*  parcheadas que nrld ejecuta en lugar del binario original.         */
/*                                                                     */
/*  NO decide nada sobre el sysroot (eso es sysroot_manager.h) ni     */
/*  sobre como se ejecuta la app (eso es executor.h).                 */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h.                                */
/* ================================================================== */

/* Cabecera ELF de 16 bytes (e_ident). 0 si no se pudo leer. */
int read_eident(const char *path, char *eident);

/* El fichero empieza con la firma ELF. */
int is_elf(const char *path);

/* Copia el contenido de srcfd a dstfd (dstfd abierto para escritura).
   Devuelve los bytes copiados. */
long copy_file_contents(long srcfd, long dstfd);

/* Sonames DT_NEEDED del objeto. `offs` (opcional) recibe el offset de
   fichero de cada cadena (para parcheos en runtime), `self_soname`
   (opcional) el DT_SONAME del propio objeto. Devuelve el numero de
   NEEDED, o -1 si el fichero no es un ELF64 parseable. */
int get_needed_names(const char *path, char names[][256], int max,
                     long *offs, char *self_soname);

/* Si el ELF lleva EI_ABIVERSION != 0 (AppImage/type-2), crea una copia
   con el e_ident estandar en /tmp/nrld-<pid>/ y devuelve su ruta.
   Si el e_ident ya es valido devuelve `path` sin tocar nada. */
const char *maybe_patch_abi_version(const char *path);

/* Ruta de la copia parcheada de e_ident ("" si nunca se creo). */
const char *elf_abi_patch_path(void);

/* Crea una copia de `src` en su propio directorio (<base>-nrld-<pid>)
   con el PT_INTERP reescrito al loader glibc real (incrustado al EOF).
   Devuelve la ruta de la copia, o 0 si no se pudo (dir no escribible,
   binario estatico sin PT_INTERP, ...). */
const char *make_interp_patched_copy(const char *src);

#endif /* NRRLD_ELF_PARSER_H */
