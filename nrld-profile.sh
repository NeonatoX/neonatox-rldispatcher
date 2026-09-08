# NeonatoX nrld - perfil de entorno para binarios glibc sobre hosts musl.
# Lo genera el instalador (meson) desde esta plantilla. Instalado en
# /etc/profile.d/nrld-profile.sh (login shells) y, para terminales de
# escritorio (shell interactiva no-login), se hace source desde ~/.bashrc:
#
#     echo "source /etc/profile.d/nrld-profile.sh" >> ~/.bashrc
#
# SOLO exporta LD_PRELOAD: el proxy tiene guard ABI (se desactiva solo bajo
# musl, verificado: gnu_get_libc_version), asi que es inerte para binarios
# musl. LD_LIBRARY_PATH NO va aqui: apuntar al sysroot de forma global haria
# que los binarios musl resolvieran builds glibc del mismo soname (libz,
# libstdc++, libffi...) -> "Error relocating ... __snprintf_chk" / crash.
# Cada app glibc recibe su LD_LIBRARY_PATH de nrld (modo usuario, inyectado
# en el env del hijo, que lo hereda); los hijos cuyo entorno se vacie
# (sandbox de contenido) resuelven vía el cache ldconfig del sysroot.
#
# LD_PRELOAD debe estar presente cuando se execve el binario glibc:
# Firefox/Brave heredan el env del parent y las pestanas re-ejecutan la
# copia parcheada <base>.nrld-<pid> que quedo en el dir del app.
export LD_PRELOAD=@PROXY@
export NEONATOX_SYSROOT=@SYSROOT@
# NEONATOX_PROXY_LOG=/tmp/nrld-proxy.log   # log espejo del proxy (debug pestanas)