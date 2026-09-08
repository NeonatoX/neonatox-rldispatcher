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

# --- 3. NEEDED ausente: strict falla limpio; default avisa y deja correr
"$NR" "$WORK/need_missing" >"$WORK/def.log" 2>&1
grep -q "Falta la libreria glibc" "$WORK/def.log" \
    || fail "3: default deberia avisar [ADV] por NEEDED ausente"
if NEONATOX_STRICT_SYSROOT=1 "$NR" "$WORK/need_missing" >"$WORK/str.log" 2>&1; then
    fail "3: strict deberia fallar (exit 1) por NEEDED ausente"
fi
grep -q "Falta la libreria glibc" "$WORK/str.log" \
    || fail "3: strict deberia reportar la libreria faltante"
echo "ok 3: strict rc!=0 y default avisa ante NEEDED ausente"

# --- 4. LD_PRELOAD del proxy es transparente bajo musl (guard ABI)
if ! LD_PRELOAD="$PROXY" /bin/true >/dev/null 2>&1; then
    fail "4: el proxy rompe un binario musl (/bin/true)"
fi
if ! LD_PRELOAD="$PROXY" /bin/sh -c 'exit 0' >/dev/null 2>&1; then
    fail "4: el proxy rompe un binario musl (/bin/sh)"
fi
echo "ok 4: proxy transparente bajo musl (/bin/true, /bin/sh)"

echo "TODOS LOS TESTS OK"
exit 0