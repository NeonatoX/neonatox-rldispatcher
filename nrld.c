/* ------------------------------------------------------------------ */
/*  nrld.c -- punto de entrada de NeonatoX RLDispatcher.                 */
/*                                                                      */
/*  nrld es un linker dinamico "falso": se instala como                  */
/*  /lib64/ld-linux-x86-64.so.2 para que el kernel lo cargue en lugar  */
/*  del loader glibc real. Este fichero solo aporta el stub de entrada */
/*  (_start) y delega todo el trabajo en el modulo executor.            */
/*                                                                      */
/*  La logica vive repartida en modulos:                                */
/*    utils.h/.c          syscalls, strings, log, helpers de ficheros   */
/*    elf_parser.h/.c     formato ELF (e_ident, DT_NEEDED, PT_INTERP)   */
/*    sysroot_manager.h/.c  resolucion de libs en el sysroot + config  */
/*    appimages.h/.c      AppImage type-2 (squashfs embebido)           */
/*    executor.h/.c       flujo principal: entorno, modo root/usuario   */
/*                                                                      */
/*  Freestanding: sin libc, todo via syscalls crudos x86-64.           */
/* ------------------------------------------------------------------ */

#include "utils.h"
#include "executor.h"

/* Stub de entrada. El kernel deja en %rsp: argc, argv[], envp[], auxv.
   Pasamos el stack tal cual a nrld_main(), que es la unica que sabe
   interpretarlo. Tras el call solo queda un exit(0) por si la funcion
   volviera alguna vez (no deberia: siempre hace execve o exit). */
__asm__(
    ".global _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "    mov %rsp, %rdi\n"
    "    and $0xfffffffffffffff0, %rsp\n"
    "    call nrld_main\n"
    "    mov $60, %rax\n"
    "    xor %rdi, %rdi\n"
    "    syscall\n"
);
