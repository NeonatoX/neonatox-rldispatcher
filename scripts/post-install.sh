#!/bin/sh
# NeonatoX nrld: tareas post-instalacion que requieren root.
# Reconstruye el cache del ldconfig del sysroot real (glibc) para que su
# loader resuelva las libs del sysroot incluso sin LD_LIBRARY_PATH.
# No fatal: con DESTDIR (instalacion empaquetada) o falta de ldconfig se omite.
set -u
SYSR="$1"

if [ -n "${DESTDIR:-}" ]; then
    exit 0
fi

if [ -x "$SYSR/usr/bin/ldconfig" ]; then
    if "$SYSR/usr/bin/ldconfig" -n "$SYSR/usr/lib" "$SYSR/lib" 2>/dev/null; then
        echo "[post-install] ldconfig del sysroot actualizado"
    else
        echo "[post-install] aviso: ldconfig del sysroot fallo (no fatal)"
    fi
fi

exit 0