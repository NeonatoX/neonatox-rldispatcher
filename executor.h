#ifndef NRRLD_EXECUTOR_H
#define NRRLD_EXECUTOR_H

/* ================================================================== */
/*  executor.h -- flujo principal de nrld.                               */
/*                                                                     */
/*  Decide el modo (root / usuario), arma el entorno y lanza el        */
/*  binario. Es el unico modulo que conoce argv/envp/auxv.             */
/*                                                                     */
/*  Depende de: utils.h, nrld_paths.h, elf_parser.h,                   */
/*               sysroot_manager.h, appimages.h.                       */
/* ================================================================== */

/* Punto de entrada: recibe el stack inicial del kernel (sp[0] = argc,
   sp+1 = argv, luego envp y auxv). No retorna: o ejecuta el binario o
   sale con codigo de error. */
void nrld_main(long *sp);

/* Muestra la ayuda (--help) por stdout. */
void print_usage_help(void);

#endif /* NRRLD_EXECUTOR_H */
