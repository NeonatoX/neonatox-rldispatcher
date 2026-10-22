#!/bin/bash
# Test TSan del scan strict del proxy (data race de found_bad/bad_path/verdict_cache).
#
# Uso: run_tsan.sh <srcdir>
#
# Que hace:
#   1. construye el harness (8 hilos x 500 dlopen("libm.so.6")) con TSan,
#   2. construye el proxy DOS veces desde el mismo fuente:
#        - legacy: -DNRLD_SCAN_TLS=0 (el estado del scan en globales, el
#          codigo previo al fix) -> DEBE reportar data race,
#        - fix:    por defecto (el estado del scan en TLS) -> NO debe
#          reportar ninguna,
#   3. ejecuta ambos con LD_PRELOAD=proxy y NEONATOX_STRICT_SYSROOT=1,
#   4. comprueba que el veredicto en single-thread no cambia (permitido
#      dentro del sysroot, rechazado fuera).
#
# El host es musl y su gcc no puede construir binarios glibc con TSan, pero el
# sysroot trae un toolchain glibc completo (/usr/lib/glibc6/usr/bin/gcc +
# libtsan.so). Si no esta, el test hace SKIP (77).
#
# Nota de TSan: symbolize=0 es OBLIGATORIO aqui. El symbolizer de TSan hace
# fork/exec y se cuelga (deadlock) con el lock del loader cuando hay dlopen
# concurrente; los offsets del reporte se simbolizan aqui offline con
# addr2line.
set -u

SRCDIR="${1:?uso: run_tsan.sh <srcdir>}"

GLIBC_CC="${NRLD_GLIBC_CC:-/usr/lib/glibc6/usr/bin/gcc}"
SYSROOT="${NRLD_SYSROOT:-/usr/lib/glibc6}"
GLIBC_LIB="$SYSROOT/usr/lib"
GLIBC_INC="$SYSROOT/usr/include"
GLIBC_LD="$GLIBC_LIB/ld-linux-x86-64.so.2"

if [ ! -x "$GLIBC_CC" ] || [ ! -x "$GLIBC_LD" ]; then
    echo "SKIP: no hay toolchain glibc en $GLIBC_CC"
    exit 77
fi
if [ ! -f "$GLIBC_LIB/libtsan.so" ]; then
    echo "SKIP: el sysroot $SYSROOT no trae libtsan"
    exit 77
fi

WORK="$(mktemp -d /tmp/nrld-tsan.XXXXXX)" || exit 1
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# El sysroot no trae los symlinks de enlazado (libc.so, libgcc_s.so...):
# se crean symlinks a las sonames reales en un dir privado.
LINK="$WORK/link"; mkdir -p "$LINK"
for pair in libc.so:libc.so.6 libm.so:libm.so.6 libpthread.so:libpthread.so.0 \
            libdl.so:libdl.so.2 librt.so:librt.so.1 libgcc_s.so:libgcc_s.so.1 \
            libtsan.so:libtsan.so.2.0.0; do
    ln -sf "$GLIBC_LIB/${pair#*:}" "$LINK/${pair%%:*}"
done

GCC="$GLIBC_CC --sysroot=$SYSROOT -fno-use-linker-plugin -L$LINK"

# --- harness (instrumentado con TSan)
$GCC -fsanitize=thread -g -O1 "$SRCDIR/test/tsan/tsan_dlopen.c" -o "$WORK/tsan_dlopen" \
    || fail "no se pudo compilar el harness con TSan"

# --- proxy instrumentado: variant "legacy" (globales) y variant "fix" (TLS).
#     El .so se llama libnrld-proxy.so en ambos casos: el propio proxy se
#     permite en el scan por nombre (ends_with "/libnrld-proxy.so").
build_proxy() {  # $1=dir destino  $2=flags extra  $3=tag
    mkdir -p "$1"
    $GCC -fsanitize=thread -ftls-model=initial-exec -fPIC -g -O1 \
         -I"$GLIBC_INC" $2 -c "$SRCDIR/proxy_readlink.c" -o "$WORK/proxy_$3.o" \
        2>"$WORK/build_$3.log" || fail "no se pudo compilar el proxy ($3): $(cat "$WORK/build_$3.log")"
    $GCC -fsanitize=thread -shared -o "$1/libnrld-proxy.so" "$WORK/proxy_$3.o" \
        || fail "no se pudo enlazar el proxy ($3)"
}
build_proxy "$WORK/legacy" "-DNRLD_SCAN_TLS=0" legacy
build_proxy "$WORK/fixed"  ""                            fixed

OPTS="symbolize=0 suppressions=$SRCDIR/test/tsan/tsan.supp exitcode=66"

# Corre el harness con el proxy dado. El binario se arranca con el loader
# REAL del sysroot (no con /lib64, que en este host apunta a nrld).
run_case() {  # $1=dir del proxy  $2=log  $3..=args del harness
    local dir="$1" log="$2"; shift 2
    LD_PRELOAD="$dir/libnrld-proxy.so" NEONATOX_STRICT_SYSROOT=1 \
    NEONATOX_SYSROOT="$SYSROOT" TSAN_OPTIONS="$OPTS" \
    timeout 180 "$GLIBC_LD" --library-path "$GLIBC_LIB" \
        "$WORK/tsan_dlopen" "$@" >"$log" 2>&1
}

echo "--- caso 1: estado del scan en GLOBALES (codigo previo) -> debe reportar race"
legacy_ok=0
for attempt in 1 2 3; do
    run_case "$WORK/legacy" "$WORK/legacy.log" 8 500 libm.so.6
    rc=$?
    if grep -q "WARNING: ThreadSanitizer: data race" "$WORK/legacy.log"; then
        legacy_ok=1
        break
    fi
    echo "    (intento $attempt: no se detecto la carrera, se reintenta)"
done
[ "$legacy_ok" -eq 1 ] \
    || fail "el build legacy (globales) NO reporto data race: el detector no sirve"
[ "$rc" -ne 0 ] \
    || fail "el build legacy deberia salir con el codigo de TSan (66), no 0"
echo "    race reportada (rc=$rc):"
grep -m2 -A4 "WARNING: ThreadSanitizer: data race" "$WORK/legacy.log" | sed 's/^/    /'
# Simboliza los offsets offline (symbolize=0 evita el fork del symbolizer,
# que se cuelga con el loader lock en este workload).
for off in $(grep -oE "libnrld-proxy.so\+0x[0-9a-f]+" "$WORK/legacy.log" | sed 's/.*+//' | sort -u | head -4); do
    echo -n "    $off -> "
    addr2line -f -e "$WORK/legacy/libnrld-proxy.so" "$off" 2>/dev/null | tr '\n' ' '
    echo
done

echo "--- caso 2: estado del scan en TLS (fix) -> no debe reportar race"
run_case "$WORK/fixed" "$WORK/fixed.log" 8 500 libm.so.6
rc=$?
if grep -q "WARNING: ThreadSanitizer: data race" "$WORK/fixed.log"; then
    grep -m2 -A6 "WARNING: ThreadSanitizer: data race" "$WORK/fixed.log" >&2
    fail "el build con TLS sigue reportando data race"
fi
[ "$rc" -eq 0 ] \
    || fail "el build con TLS deberia salir limpio (rc=0), salio rc=$rc"
grep -q "harness: 8 hilos x 500 dlopen(libm.so.6) -> rc=0" "$WORK/fixed.log" \
    || fail "el harness con TLS no completo las 8x500 dlopen"
echo "    limpio (rc=0, 0 data races)"

echo "--- caso 3: veredicto single-thread sin cambios"
# (a) lib dentro del sysroot -> permitido
run_case "$WORK/fixed" "$WORK/st_ok.log" 1 1 libm.so.6 \
    || fail "single-thread: libm.so.6 (dentro del sysroot) deberia estar permitido"
# (b) lib fuera del sysroot -> rechazado con el mensaje de siempre
printf 'int fake(void){return 42;}\n' > "$WORK/fake.c"
$GCC -fPIC -shared -o "$WORK/libfake.so.1" "$WORK/fake.c" \
    || fail "no se pudo compilar la lib de prueba"
run_case "$WORK/fixed" "$WORK/st_bad.log" 1 1 "$WORK/libfake.so.1"
if [ $? -eq 0 ]; then
    fail "single-thread: una lib fuera del sysroot deberia ser rechazada"
fi
grep -q "The following glibc library is missing" "$WORK/st_bad.log" \
    || fail "single-thread: falta el mensaje de rechazo de la lib fuera del sysroot"
echo "    permitido dentro del sysroot, rechazado fuera (veredicto intacto)"

echo "OK: TSan del scan strict (race antes / limpio despues, veredicto igual)"
exit 0
