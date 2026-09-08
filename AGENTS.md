# neonatox-RLDispatcher

Fake ELF dynamic linker (`ld-linux-x86-64.so.2`) for Linux x86-64. Part of the neonatox ecosystem.

## Build

Primary build is **meson** (installs binaries to the *host*, config, profile, interp
symlink, and the E2E test). The manual `gcc` recipe produces identical binaries and is
kept as fallback. Compilation can be done as a normal user in the project directory
(`meson test` needs no root). The human compiles and does the root install (not the agent).

```bash
meson setup build --prefix=/usr        # options: -Dglibc_sysroot=... -Dneonatox_dir=...
meson compile -C build
meson test -C build                    # E2E, no root needed
sudo meson install -C build            # binaries + conf + profile + interp symlink + ldconfig
```

Manual recipe (same as meson outputs; defaults `NEO_SYSROOT=/usr/lib/glibc6`,
`NEO_BINDIR=/usr/lib/neonatox`):

```bash
# 1. Proxy shared library (no libc: leaves symbols undefined, resolved by glibc
#    at runtime. Linking with musl `gcc -ldl` would emit NEEDED [libc.so] (musl
#    soname) -> "invalid ELF header" in the glibc loader. Must use -nostdlib.
#    Meson passes -DNEO_SYSROOT/-DNEO_BINDIR + b_lundef=false.)
gcc -nostdlib -shared -fPIC -o libnrld-proxy.so \
    -I/usr/lib/glibc6/usr/include \
    proxy_readlink.c

# 2. Fake loader binary (freestanding, no libc)
gcc -nostdlib -static -ffreestanding -fno-stack-protector -O2 -s \
    -o nrld nrld.c
```

## Architecture

Two components working together:

- **`nrld.c`** → Fake dynamic linker installed at `/usr/lib/glibc6/usr/bin/nrld`. Kernel loads this instead of the real `ld-linux-x86-64.so.2`. It determines the real binary, sets up `LD_LIBRARY_PATH`/`LD_PRELOAD`, then either:
  - **Root mode**: forks and swaps symlinks to run under the real linker, then restores symlinks
  - **User mode**: creates a **patched copy of the app in its own directory** (`<appdir>/<base>.nrld-<pid>`, `make_interp_patched_copy()` in `nrld.c`) whose `PT_INTERP` is rewritten to the real loader (the string is embedded at the copy's EOF, so there's no length limit), then `execve`s that copy. The kernel loads the real `ld-linux` **in-process** as a normal interpreter, so `/proc/self/exe` stays the app copy (same dir → resources/omni.ja/icudtl.dat still resolve) and `LD_LIBRARY_PATH`/`LD_PRELOAD` are inherited from the env. No more `--library-path` flag needed; identical search precedence (env == flag).
  - **Fallback**: if the copy can't be created (app dir not writable) or the ELF has no `PT_INTERP` (static/musl binary), nrld falls back to the old `execve(REAL_LOADER, [--library-path, ...])`.

- **`proxy_readlink.c`** → `LD_PRELOAD` library that intercepts `readlink("/proc/self/exe")` to return the real binary path instead of the fake loader path — **only in loader-as-main mode** (detected via a raw `readlink` of `/proc/self/exe` whose basename is `ld-*`; in user mode the kernel already answers with the app copy and the rewrite is skipped, else Chromium/Electron SIGTRAP). Also enforces the strict sysroot dlopen allowlist (see below). Freestanding (built with `-nostdlib`): no `NEEDED`, libc symbols resolved by glibc at runtime.

## Key constraints

- **x86-64 only** — uses raw `syscall` instructions and x86-64 register conventions
- **No libc in nrld** — all functions reimplemented via raw syscalls (no malloc, no printf, etc.)
- **Hardcoded paths** — `REAL_LOADER`, `INTERP_PATH`, `SYSROOT_LIBS` etc. are compile-time constants in `nrld.c` (around `nrld.c:765-775`)
- **Installation requires root** — binaries go to `/usr/lib/glibc6/` which needs to exist
- Code comments and README are in Spanish

## Known behavior

`nrld` must NOT try to load non-ELF files, or it recursively intercepts processes that exec non-binaries (e.g. Firefox launching a crash handler over a `.dmp` file, which segfaults with "invalid ELF header"). Early-exit guard: `is_elf()` check after `file_exists()` in `nrld.c` — non-ELF files cause an immediate clean `exit(0)`.

**AppImage / type-2 ELFs (`EI_ABIVERSION`):** AppImage-style ELFs carry a non-zero `EI_ABIVERSION` (byte 8 of `e_ident`, e.g. `0x41`/"AI"), which the glibc loader **rejects outright** with "ELF file ABI version invalid" — before any NEEDED/lib logic. `maybe_patch_abi_version()` (in `nrld.c`) detects a non-zero byte 8 after the `is_elf` check and creates a **patched copy** in `/tmp/nrld-<pid>/` with that byte zeroed, then execs the copy instead of the original. Original path is untouched and kept for `NEONATOX_REAL_EXE` (dlopen allowlist). Verified: ABI-65 ELF → patched copy `ABIVERSION=0` exec'd; normal ELFs are run as-is (no patch).

**Children that re-exec their own binary (Firefox/Chromium tabs, `process exited with status 1`):** Firefox + Brave content processes are spawned by re-exec'ing their own executable. They resolve it through `/proc/self/exe` by mechanisms that **bypass LD_PRELOAD** (`open`+`read` of the magic symlink, or a raw `readlink` syscall), so the proxy's interposed libc `readlink` never fires. Under the old user mode (`execve(REAL_LOADER, [--library-path, ...])`) the kernel's `/proc/self/exe` was the loader, so children re-exec'd the loader **as the program**: glibc treats the first non-option argv as the app, fails, and exits 1 (the observed "process N exited with status 1" storm; those PIDs never show a `[DEBUG] NeonatoX` line). Fixed by **user-mode** executing a patched copy (`make_interp_patched_copy`) whose `PT_INTERP` is the real loader: the kernel loads it **in-process**, `/proc/self/exe` is the copy inside the app dir, and children re-exec it successfully through ANY mechanism — no nrld, no loader-as-main, no interposition required. Children that run this way are glibc-natural: inherited `LD_LIBRARY_PATH`/`LD_PRELOAD` configures the in-process loader identically. The patched copy `<base>-nrld-<pid>` is left in the app dir (children keep re-exec'ing that path; removing it early would break them). So each run leaves one copy — `make_interp_patched_copy()` self-sweeps the residue: on the next run for the same `<base>` it walks the app dir, and every `<base>-nrld-*` whose path is no longer `/proc/self/exe` of a live process (its tab tree has exited) is unlinked; an in-use copy (concurrent instance still spawning tabs from it) is kept. Net effect: at most one stale copy per `<base>` survives, cleaned by the next run.

**IMPORTANT — the copy name and IPvproxy readlink gate (Chromium/Electron SIGTRAP root cause, verified live):** the gating fact is that the crash of Brave/Heroic/Electron under nrld was **NOT the copy name** — it was the proxy's `readlink("/proc/self/exe")` interposition. In user mode the kernel's `/proc/self/exe` already points at the copy inside the app dir (correct); the proxy rewrote the answer to `NEONATOX_REAL_EXE` (the *original* binary path), so any Chromium-family recursive self-exe resolution saw a path that differs from the running binary (whose interp would re-enter nrld) and died `NOTREACHED`/SIGTRAP in early startup. Isolated empirically with the same clean-named Electron copy: traps with `NEONATOX_REAL_EXE` in env (K/L), lives without it (J/H). Fix (`proxy_readlink.c`): `init_proxy` runs a raw `readlink` of `/proc/self/exe`; only when the basename is `ld-*` (loader-as-main fallback, no patched copy) does the override to `NEONATOX_REAL_EXE` apply — user mode always returns the kernel answer. The copy is still named `<base>-nrld-<pid>` (dashes, no leading dot) so residues are visible and Chromium never sees a dot-prefixed basename, but that is cosmetic, not the fix.

**Why user mode needs the app dir writable:** the interp-patched copy is created next to the app so `dirname(/proc/self/exe)` still resolves `omni.ja`/`icudtl.dat`/resources. In read-only dirs nrld falls back to the old loader-as-main scheme (children of such apps re-break, but the app itself runs).

Verified end-to-end in this env: `needvdpau2` (PT_INTERP + NEEDED `libvdpau_trace.so.1` in a sysroot subdir) → patched copy with `PT_INTERP=/usr/lib/glibc6/usr/lib/ld-linux-x86-64.so.2`, kernel exec → in-process real loader → NEEDED resolved via env → rc=0. Static/no-interp ELFs cleanly fall back (`[ADV] Binario sin PT_INTERP ...`).

**Live result after the readlink gate (root install of new nrld + proxy):** Brave, balenaEtcher (Electron) and modern Firefox (vanilla) all run under nrld — the Chromium/Electron SIGTRAP family is gone. The gate fix (user mode keeps the kernel's `/proc/self/exe` answer) resolved every Electron app; the `-nrld-<pid>` copy naming is cosmetic. Heroic and other type-2 AppImages go through the same user-mode flow (nrld extracts to `/tmp/nrld-appimage-<pid>/`, writable, then a `heroic-nrld-<pid>` copy) so they inherit the same fix.

**Internal-binary discovery (AppRun is the canonical entry):** the AppImage runtime only ever execs `AppRun`, so nrld honors it as-is — BUT only for the two forms that are safe: a **symlink→ELF** (OCAT) and a **`#!` script** (Heroic, balena). A plain-ELF `AppRun` is deliberately NOT preferred: those launchers (OpenShot) break when run naked instead of the real app binary (their bundled libncurses TUI + `.desktop` check). Script case: nrld `execve`s `AppRun` **directly** (no loader/copy, no `LD_PRELOAD` — feeding the glibc proxy to the musl bash would contaminate it) with the inherited env plus `APPDIR=<extraction root>` and `APPIMAGE=<AppImage path>` (what the real runtime sets; without `APPDIR` script-resolved-AAppDir breaks for any arg `$1`). The script then execs the real internal ELF (`heroic`, `balena-etcher.bin`, ...) which re-enters nrld as the interp of a plain binary in that dir → standard user mode (patched copy → in-process glibc loader). **Before this, `find_internal_bin` fell back to "the first top-level ELF executable" and picked `libvulkan.so.1` over `heroic` (a `.so`, marked exec) → nrld ran the glibc loader with a shared object as the program → SIGSEGV ("intenta ejecutar una lib en tmp").** The generic ELF scan now also skips `.so` files. Verified: Heroic 2.22.1 AppImage launches and runs (frontend ready, wine downloads, legendary/gogdl/nile/comet all run through nrld user mode); OCAT (symlink→`OCAuxiliaryTools`) and CARTRIDGE (script→`cartridge`) pick the right binary; OpenShot picks `usr/bin/openshot-qt` (AppRun plain-ELF launcher correctly bypassed) and reaches the full Qt GUI.

**Extraction dir hygiene:** each AppImage launch leaves ~600 MB in `/tmp/nrld-appimage-<pid>/` (extraction + `heroic-nrld-<pid>` copy), so `extract_appimage` first runs `sweep_stale_appimage_dirs`: any `/tmp/nrld-appimage-*` dir that no live process references (no `/proc/<pid>/exe` inside it, no `/proc/<pid>/cwd` == it) is recursively removed. A running instance keeps its own dir (its exe/cwd live there); stale dirs from exited runs are cleaned on the next launch.

**Mozilla-launcher binaries (`firefox`/`firefox-bin`, Firefox moderno + ESR regression, fixed):** the `firefox` shipped in official tarballs (also `firefox-esr`, Living the same in `/home/neonatox/Descargas/`) is NOT a script — it's a tiny ELF (only `libc`/`libpthread` NEEDED) whose `main` resolves the real binary via `readlink("/proc/self/exe")` and appends `-bin` (strings: `/proc/self/exe`, `-bin`, `Couldn't find the application directory.`, `Exec failed with error: %s`). In user mode `/proc/self/exe` is the patched copy `<dir>/firefox-nrld-<pid>`, so the derived target is `<dir>/firefox-nrld-<pid>-bin` → **`Exec failed with error: No such file or directory`** (reproduced; also affected ESR). Feed `firefox-bin` directly (patched copy) → browser starts (fontconfig init + full process tree, previously "Firefox moderno runs" only because we had launched `firefox-bin` directly). Fix: `launcher_bin_redirect()` in nrld.c — in user mode, if the target basename is `X` and a sibling `X-bin` exists in the same dir and is an ELF, nrld redirects to `X-bin` (same argv, skips the launcher). Root mode is untouched (the launcher runs natively there and its `/proc/self/exe` is the app path). Verified live: both Descargas Firefox build and ESR reach a running browser (Socket/RDD/GPU + main processes); Tor Browser unaffected (`firefox.real` is the app, not a launcher pair). Wine diagnostic (context): Proton-CachyOS wine 11 runs under nrld user mode up to its own preloader which needs `/lib/ld-linux.so.2` (32-bit) for ANY PE — host musl has no multilib, so wine needs a 32-bit glibc in the sysroot or a wow64 runner.

## musl ↔ glibc ABI isolation (CRITICAL)

The host is **musl-based** (`/lib/ld-musl-x86-64.so.1`), `/usr/lib/glibc6/` is the isolated glibc sysroot, and the goal is transparently running glibc binaries over musl without contaminating the musl env.

- **A glibc GUI app (e.g. Firefox) dlopens the GTK/GNOME stack at runtime** (`libgtk-3.so.0`, `libpango-1.0.so.0`, `libcairo.so.2`, `libglib-2.0.so.0`, X11, dbus, ...) from `/usr/lib/`, which are **musl-built** there. Musl libs depend on `libc.so` (musl soname); the glibc loader provides `libc.so.6`. Loading musl libs under the glibc loader = **two libcs in one process** → glibc `strtod_l()` dereferences a musl-AbI `locale_t` (observed `%rcx=0`/SIGSEGV at `__GI_____strtod_l_internal+0x1a`), crashing the glibc app.
- **Root cause of Firefox crash (coredump confirmed):** the sysroot currently ships only core glibc; it is **MISSING the whole GNOME/GUI stack** (gtk, pango, cairo, gdk-pixbuf, atk, atk-bridge, harfbuzz, glib2, gobject, gio, fribidi, X11, dbus, asound — all absent from `/usr/lib/glibc6/usr/lib`, present only as musl in `/usr/lib`).
- **Fix strategy:** place **glibc** builds of the entire GNOME stack in `/usr/lib/glibc6/usr/lib`. Verified precedence: glibc's loader searches `--library-path`/`LD_LIBRARY_PATH` **before** its compiled-in system path `/usr/lib`, so sysroot copies always win over musl ones.
- **NOTE:** `--inhibit-rpath`/`--inhibit-cache` do **NOT** block the loader from falling back to its compiled-in `/usr/lib` when a lib is absent in the sysroot; a missing sysroot lib silently resolves to musl `/usr/lib`. Keeping musl out therefore requires a complete sysroot GUI stack, not loader flags.

### Pre-flight NEEDED coverage guard (in `nrld.c`)

`nrld` parses the target ELF's `DT_NEEDED` sonames (via `PT_DYNAMIC`/`PT_LOAD` vaddr→offset mapping) and — since the guard is now **transitive** — also the `DT_NEEDED` of every library that resolves inside the sysroot (see "Transitive NEEDED guard" below), checking each is resolvable in `bin_dir` + the sysroot dirs. If a NEEDED lib is missing from the sysroot (so glibc would fall back to musl `/usr/lib` and mix ABIs):
- **Default:** prints an `[ADV]` warning naming the lib, but still runs (non-GUI binary baseline unaffected).
- **Strict mode** (env `NEONATOX_STRICT_SYSROOT=1` **or** config file `/usr/lib/glibc6/etc/nrld.conf` containing `strict`): fails cleanly (exit 1) with a readable error before ever reaching the musl mixing — this is the intended "fail like a glibc system missing those libs" behavior. The config file lets plain `./firefox` be strict without an env prefix (nrld reads it via raw syscalls; `config_enforces_strict()` scans for the token).

**General-purpose intent:** Firefox is only the pilot app. The goal is running **any standalone glibc binary over musl** cleanly (Brave, AppImages, OpenShot, etc.). The sysroot currently ships only core glibc + libstdc++/libgcc_s; it is **missing even base third-party libs** (zlib, bz2, lzma, zstd, libffi, expat, openssl) and the entire GUI stack. So, in strict mode, any such app fails cleanly with a generic message ("Instala las librerias glibc faltantes en /usr/lib/glibc6/usr/lib") instead of a confusing SIGSEGV. To make apps actually RUN, populate the sysroot with glibc builds of the missing libs (base + per-app queue); sysroot wins over `/usr/lib` by library-path precedence.

Verified: `locale` (all NEEDED in sysroot) clean; `needpango` (NEEDED `libpango-1.0.so.0`, musl-only) warns by default and clean-fails under strict mode.

### dlopen/dlclose interposition (in `proxy_readlink.c`)

Firefox's GTK/ICU/Pango come via **runtime `dlopen`** of `libxul.so`, not static NEEDED — so the nrld NEEDED guard can't see them. The proxy interposes `dlopen`/`dlmopen`: only active with strict mode (`NEONATOX_STRICT_SYSROOT=1`). After each real `dlopen` it scans the **whole runtime link map** (`dl_iterate_phdr`), because the object itself may be allowed (e.g. `libxul.so` in the app dir) while its **transitive NEEDED closure** pulls musl `/usr/lib` builds (`libgtk-3`, `libicuuc`, ...). If ANY loaded object resolves outside the sysroot, the handle is `dlclose`d, NULL returned, and a clear stderr message names the offending library (`[neonatox] Falta la libreria glibc para ejecutar la app: ...`) → the app fails cleanly instead of mixing two libcs and SIGSEGVing. Allowed paths: `/usr/lib/glibc6/*`, the app's own dir (from `NEONATOX_REAL_EXE`), and the running glibc loader itself (`/ld-linux-x86-64.so.2` basename — with the interp-patched user mode the rtld shows up in the link map as a normal object named its interp path, e.g. `/lib64/ld-linux-x86-64.so.2`, instead of as the always-allowed empty-name main program; it can only ever be the sysroot's glibc build); the main program (empty `dlpi_name`) is always allowed.
- Verified in this env: proxy loads cleanly under glibc with strict both off and on; sysroot-resolved loads (locale, NSS via `getent passwd`, gconv via `iconv`) are allowed and not false-rejected. Algorithm validated with a musl probe: `dl_iterate_phdr` after `dlopen(musl-lib)` correctly reveals the pulled musl deps.
- **Build caveat:** the musl host toolchain CANNOT build working glibc dynamic test binaries (`libc.a` missing `_init`/`_fini`; `dlopen` test binaries SIGSEGV at `_start`), so no live end-to-end rejection of the real `libxul→musl-GTK` chain is possible here — only the sysroot-allowed path is verified live.
- **Live result with Firefox (strict on):** holds no longer as "clean" — with the sysroot missing the whole GUI/ICU stack and the guard not yet catching `libxul`'s dlopen'd subtree, Firefox still mixed musl/glibc and SIGSEGV'd (coredump shows both libcs + musl GTK/ICU in one process). The proxy link-map scan above is the intended fix; needs root install + live re-test.

### Transitive NEEDED guard (nrld)

The pre-flight guard was widened from the top binary's direct `DT_NEEDED` to a **transitive closure** (`scan_missing_libs` in `nrld.c`): it walks the dependency tree, and for every library that resolves inside the sysroot it also inspects that library's own `DT_NEEDED`, so a musl-only dependency hidden one level down is reported. Covers apps whose whole dep tree is statically linked (most standalone binaries / AppImages). It does NOT cover `dlopen`'d trees (Firefox's `libxul`) — that's the proxy link-map scan's job. Cycle/dedup via a visited soname set (depth-bounded at 512).

