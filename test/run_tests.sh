#!/bin/bash
# E2E tests for nrld (neonatox-RLDispatcher).
# Usage: run_tests.sh <nrld> <proxy> <srcdir>
set -u

if [ $# -ne 3 ]; then
    echo "uso: $0 <nrld> <proxy> <srcdir>" >&2
    exit 2
fi

NR="$1"; PROXY="$2"; SRCDIR="$3"

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 requerido para generar los probes"
    exit 77
fi

WORK="$(mktemp -d /tmp/nrld-e2e.XXXXXX)" || exit 1
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

python3 "$SRCDIR/test/gen_probes.py" "$WORK" >/dev/null || fail "gen_probes.py fallo"

# --- 1. NEEDED resuelto dentro del sysroot (extralibfinder) -> rc=0
if ! "$NR" "$WORK/need_vdpau" >/dev/null 2>&1; then
    fail "1: need_vdpau (NEEDED libvdpau_trace.so.1 en subdir del sysroot) deberia correr rc=0"
fi
echo "ok 1: need_vdpau corre rc=0"

# --- 2. sweep: dos corridas dejan a lo sumo una copia <base>-nrld-*
rm -f "$WORK"/need_vdpau-nrld-* 2>/dev/null
"$NR" "$WORK/need_vdpau" >/dev/null 2>&1
"$NR" "$WORK/need_vdpau" >/dev/null 2>&1
copies=$(ls -A "$WORK"/need_vdpau-nrld-* 2>/dev/null | wc -l)
if [ "$copies" -gt 1 ]; then
    fail "2: tras dos corridas quedan $copies copias (sweep debe dejar <=1)"
fi
echo "ok 2: sweep deja <=1 copia ($copies)"

# --- 3. NEEDED ausente: default SILENCIOSO; NRLD_DEBUG=1 avisa [ADV];
#     strict falla limpio y reporta el sysroot incompleto
"$NR" "$WORK/need_missing" >"$WORK/def.log" 2>&1
if grep -q "Falta la libreria glibc" "$WORK/def.log"; then
    fail "3: default deberia estar silencioso (sin [ADV]) ante NEEDED ausente"
fi
if ! NRLD_DEBUG=1 "$NR" "$WORK/need_missing" >"$WORK/adv.log" 2>&1; then
    echo "nota: need_missing devuelve rc!=0 (el loader no resuelve la lib) — se evalua solo el aviso"
fi
grep -q "Falta la libreria glibc" "$WORK/adv.log" \
    || fail "3: NRLD_DEBUG=1 deberia avisar [ADV] por NEEDED ausente"
if NEONATOX_STRICT_SYSROOT=1 NRLD_DEBUG=1 "$NR" "$WORK/need_missing" >"$WORK/str.log" 2>&1; then
    fail "3: strict deberia fallar (exit 1) por NEEDED ausente"
fi
grep -q "Sysroot glibc incompleto" "$WORK/str.log" \
    || fail "3: strict deberia reportar el sysroot incompleto"
echo "ok 3: default silencioso; NRLD_DEBUG=1 avisa; strict rc!=0"

# --- 4. LD_PRELOAD del proxy es transparente bajo musl (guard ABI)
if ! LD_PRELOAD="$PROXY" /bin/true >/dev/null 2>&1; then
    fail "4: el proxy rompe un binario musl (/bin/true)"
fi
if ! LD_PRELOAD="$PROXY" /bin/sh -c 'exit 0' >/dev/null 2>&1; then
    fail "4: el proxy rompe un binario musl (/bin/sh)"
fi
echo "ok 4: proxy transparente bajo musl (/bin/true, /bin/sh)"

# --- 5. canal: por defecto nrld NO escribe nada (ni stdout ni stderr).
#     Regresion de Investigacion_05: las lineas [DEBUG]/[ADV] en stdout
#     se convertian en argumentos de ld via command substitution.
"$NR" "$WORK/need_vdpau" >"$WORK/ch.out" 2>"$WORK/ch.err"
if [ -s "$WORK/ch.out" ]; then
    fail "5: nrld por defecto debe dejar el stdout limpio del programa"
fi
if [ -s "$WORK/ch.err" ]; then
    fail "5: nrld por defecto no debe escribir diagnostico a stderr"
fi
# con NRLD_DEBUG=3 el diagnostico va a stderr, NUNCA a stdout
NRLD_DEBUG=3 "$NR" "$WORK/need_vdpau" >"$WORK/dbg.out" 2>"$WORK/dbg.err"
if ! grep -q "Starting RLDispatcher" "$WORK/dbg.err"; then
    fail "5: NRLD_DEBUG=3 deberia escribir el diagnostico a stderr"
fi
if grep -q "\[DEBUG\]\|\[ADV\]\|\[INFO\]" "$WORK/dbg.out"; then
    fail "5: el diagnostico NUNCA debe ir a stdout"
fi
echo "ok 5: default silencioso; con NRLD_DEBUG=3 el log va a stderr"

echo "TODOS LOS TESTS OK"
exit 0