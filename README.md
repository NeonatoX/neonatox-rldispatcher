# neonatox-RLDispatcher (nrld)

Fake ELF dynamic linker para **hosts musl**. En lugar del clásico `gcompat`/`libgcompat.so`
(que emula glibc *dentro* del proceso musl), ejecuta binarios glibc con un **glibc real,
completamente aislado y autosuficiente** dentro de `/usr/lib/glibc6/`, sin contaminar el
entorno musl del host (sin mezclar dos libcs en un mismo proceso).

> **La idea**: reemplazar `gcompat` en sistemas musl por un glibc real aislado 100%,
> que resuelva sus propias librerías sin tocar `/usr/lib` del host.
> **La desventaja** (confesada): para apps complejas hay que instalar *casi media distro
> glibc* (GTK, Qt, ICU, fonts, dbus...) dentro del sysroot. 😄

- Solo **x86-64**, sin libc, syscalls raw (freestanding).
- Ruta instalada `/usr/lib/glibc6/` (sysroot glibc aislado); interp del sistema
  `/lib64/ld-linux-x86-64.so.2` → `nrld`.
- Comentarios y documentación en español.

---

## Los archivos y su propósito

| Archivo | Líneas | Rol |
|---|---|---|
| `nrld.c` | 1457 | El fake loader (freestanding, sin libc). Detecta el binario, lee `/etc/nrld.conf` (host), arma `LD_LIBRARY_PATH`/`LD_PRELOAD`, guard transitivo de NEEDED, y en **modo usuario** ejecuta una copia patcheada `<base>-nrld-<pid>` (mismo dir del app, `PT_INTERP` → loader real) para que el kernel cargue el loader glibc **in-process** y `/proc/self/exe` siga apuntando a la app. |
| `appimages.c` | 386 | Soporte AppImage type-2 (extracción squashfs a `/tmp`, binario interno) + los walkers recursivos de directorios: libs internas, plugin Qt (`QT_PLUGIN_PATH`) y el **extralibfinder**. Se `#include` desde `nrld.c`. |
| `proxy_readlink.c` | 588 | `LD_PRELOAD` que endereza `readlink("/proc/self/exe")` y aplica la aislación ABI en runtime (`dlopen` strict + cache de veredictos + crash diagnostics), **transparente bajo musl** (guard ABI: `dlopen("libc.so.6")==NULL` → pasa todo sin tocar nada). |
| `meson.build` / `meson_options.txt` | — | Build del proyecto (ver **Compilar**): `nrld` (executable freestanding static), `libnrld-proxy.so` (shared), genera e instala `/etc/nrld.conf` + `/etc/profile.d/nrld-profile.sh` (plantillas con `@PLACEHOLDERS@`), symlink `/lib64/ld-linux-x86-64.so.2`, y el test E2E. |
| `nrld.conf` | 12 | Plantilla de `/etc/nrld.conf` (host): `key = value` — `library_path` (LD_LIBRARY_PATH), `proxy` (LD_PRELOAD) y la clave `strict` (modo estricto global). |
| `nrld-profile.sh` | 17 | Plantilla de `/etc/profile.d/nrld-profile.sh`: env `LD_PRELOAD`/`LD_LIBRARY_PATH`/`NEONATOX_SYSROOT` para que las pestañas de Firefox/Brave hereden el proxy (ver **Uso**). |
| `scripts/post-install.sh` | 20 | Refresca el cache `ldconfig` del sysroot glibc (`-n` con los dirs del sysroot); no fatal, salta con `DESTDIR`. |
| `test/gen_probes.py` | 134 | Genera ELF64 x86-64 mínimos de prueba (struct-only, sin toolchain glibc): `need_vdpau` (NEEDED `libvdpau_trace.so.1`) y `need_missing` (NEEDED inexistente). |
| `test/run_tests.sh` | 61 | E2E (corre vía `meson test`): humo rc=0, sweep ≤1 copia oculta, strict vs default, proxy transparente bajo musl, **canal stdout limpio** (regresión de Investigación 05: nrld no escribe nada por defecto y el diagnóstico con `NRLD_DEBUG=3` va a stderr). |
| `README.md` | — | Este documento. |
| `AGENTS.md` | — | Notas técnicas de la aislación musl↔glibc (restricciones, comportamientos conocidos). |

---

## nrld silencioso por defecto (--help)

`nrld` es **silencioso por defecto** (nivel 0: solo `[ERROR]`) y escribe TODO su
diagnóstico a **stderr**, nunca a stdout: a stdout vive la salida real del programa.
Un loader real (`ld.so`) no escribe a stdout; re-efectuarlo allí rompía protocolos
que capturan stdout (command substitution de `make`, `lto-wrapper`/`collect2`,
pipes glibc). El log se reactiva por proceso con `NRLD_DEBUG=<0-3>` o globalmente
con `log_level` en `/etc/nrld.conf`. Con `nrld --help` (o `-h`) se obtiene el
resumen completo (impreso en stdout, es salida pedida):

```text
NeonatoX RLDispatcher (nrld) -- fake glibc linker para hosts musl

Uso:
  nrld --help                        Muestra esta ayuda
  nrld BIN [ARGOS...]                Ejecuta BIN glibc sobre el sysroot
  nrld [--verbose|--quiet] BIN ...   Ajusta el log de la ejecucion
  (instalado como /lib64/ld-linux-x86-64.so.2: los binarios con ese
   PT_INTERP se ejecutan solos con ./BIN, sin invocar nrld a mano)

Que hace con BIN:
  1. Detecta el binario real (AT_EXECFN o argv[1]) y exige que sea ELF.
  2. AppImage type-2: extrae el squashfs a /tmp/nrld-appimage-<pid>/
     (sin FUSE, nunca escribe fuera de /tmp) y usa el binario interno
     mas sus dirs de librerias internas (lib/, usr/lib/<triplet>, ...).
  3. Guard transitivo de DT_NEEDED: verifica que cada libreria necesitada
     (y las de sus dependencias) resuelve dentro del sysroot glibc.
  4. Extralibfinder: si un soname falta en los dirs estandar, lo busca
     en subdirectorios no estandar del sysroot (gvfs/, pulseaudio/, ...)
     y anade ese dir a LD_LIBRARY_PATH / --library-path.
  5. Corrige DT_NEEDED absolutos creando copias parcheadas en
     /tmp/nrld-patch-<pid>/ (traducidos a soname resoluble por --library-path).
  6. Executa una copia parcheada (<base>-nrld-<pid>) de BIN en su
     propio directorio cuyo PT_INTERP apunta al loader glibc real (cargado
     in-process por el kernel): /proc/self/exe queda en el dir de la app,
     los hijos que re-ejecutan su propio binario funcionan. LD_PRELOAD con
     el proxy libnrld-proxy.so (scan strict de dlopen).

Configuracion (/etc/nrld.conf, lo escribe el instalador; key = value):
  library_path = <dirs>      LD_LIBRARY_PATH (default: dirs del sysroot)
  proxy        = <ruta>      LD_PRELOAD (default: NEO_BINDIR/libnrld-proxy.so)
  strict                      modo estricto global (sin env)
  log_level    = <0-3>       nivel de log global (ver 'Salida')

Modo estricto del sysroot (aislacion musl<->glibc):
  NEONATOX_STRICT_SYSROOT=1 ./BIN    falla limpio si falta algo
  echo strict > /etc/nrld.conf       hace estricto todo (sin env)
  (evita la mezcla de dos libcs en un proceso -> el SIGSEGV de strtod_l)

Variables de entorno que nrld importa/exporta:
  NRLD_DEBUG=<0-3>           log de ESTE proceso (0=off,1=warn,2=info,3=debug)
  NEONATOX_STRICT_SYSROOT   strict por env (0/1)
  NEONATOX_REAL_EXE         ruta real del binario (la lee el proxy)
  NEONATOX_SYSROOT          root del sysroot (la lee el proxy)
  NEONATOX_APPDIR           raiz extraida de un AppImage
  NEONATOX_DUMPENV          dump del entorno del hijo a /tmp (debug)
  (vars del proxy: NEONATOX_PROXY_LOG=<archivo> espejo a archivo de los
   mensajes [neonatox]; NEONATOX_CRASHDUMP=1 activa los crash handlers)
  QT_PLUGIN_PATH            dir del plugin de plataforma Qt (si aplica)

Salida (SILENCIO por defecto; diagnostico SOLO a stderr):
  nrld NO escribe a stdout: ahi vive la salida real del programa. Un
  loader real (ld.so) nunca escribe a stdout; re-escribirlo ahi rompia
  make $(shell ...), lto-wrapper/collect2 y los pipes glibc.
  Nivel 0: solo [ERROR] (default)   Nivel 1: + [ADV] avisos
  Nivel 2: + [INFO]/[OK]            Nivel 3: + [DEBUG] razonamiento
  Reactiva el log con NRLD_DEBUG=3 ./BIN, 'nrld --verbose BIN',
  o log_level = 3 en /etc/nrld.conf (global). --help si imprime (stdout).

Copyright (C) 2026 Carlos Sanchez. Licencia GPL v3.
```

> `--help`/`-h`, `--verbose`/`-v` y `--quiet`/`-q` solo actúan cuando se invoca
> `nrld` directamente (nunca como `PT_INTERP`, para no robarle esos flags a la app).

---

## Secciones de los archivos y qué resuelven

### `nrld.c`

| Sección | Refs. | Qué resuelve |
|---|---|---|
| Helpers sin libc | syscalls `syscallN()`, `my_strlen/cpy/cat/cmp`, `print_msg/print_out/print_err`, `file_exists`, `uint_to_str`, `is_elf` | Todo el runtime freestanding (no hay `malloc`/`printf`). `print_msg` = log por niveles a **stderr** (silencio por defecto, ver `--help`), `print_out` = stdout (solo `--help`), `print_err` = errores duros a stderr siempre. |
| `read_eident`, `copy_bytes` | ~123 | Lee `e_ident` y copia archivos en chunks (para parchear). |
| `maybe_patch_abi_version` | ~166 | Los ELF type-2/AppImage llevan `EI_ABIVERSION != 0` y el loader glibc los **rechaza**; crea copia parcheada en `/tmp/nrld-<pid>/` y ejecuta la copia (el original queda intacto). |
| Globals AppImage + forward `find_lib_in_sysroot` | ~230 | Estado compartido (antes del `#include "appimages.c"`). |
| `resolve_lib_path` | ~265 | Soname → ruta: dir del binario + subdirs estándar + `g_extra_libdirs` + sysroot; con fallback **extralibfinder**. |
| `get_needed_names` | ~319 | Parsea `DT_NEEDED` de un ELF (vía `PT_DYNAMIC`/`PT_LOAD`, vaddr→offset). |
| `create_shadow_copy` | ~442 | `DT_NEEDED` con **ruta absoluta** (e.g. `libxul.so`): el loader ignora el path pero pierde la lib; se traduce a soname en una copia parcheada que `--library-path` sí resuelve. |
| `scan_missing_libs` / `check_needed_libs` | ~524 / ~622 | Guard **transitivo** de cobertura NEEDED (BFS con visited, ciclo/dedup acotado a 512): recorre los `DT_NEEDED` de cada lib que resuelve dentro del sysroot. |
| `load_nrld_conf` | ~650 | Lee `/etc/nrld.conf` (host, lo escribe el instalador) por raw syscalls: `library_path`/`proxy` (overrides de LD_LIBRARY_PATH/LD_PRELOAD), token `strict` → todas las apps estrictas sin prefijo env, y `log_level` (nivel de log global, sustituible por `NRLD_DEBUG` por proceso). |
| `make_interp_patched_copy` | ~846 | Crea la copia parcheada `<base>-nrld-<pid>` en el dir del app (interp → loader real embebido al EOF, sin límite), self-sweep de copias viejas. |
| `cleanup_run_residue` + watchdog | Antes del `execve` de la copia, nrld fork un **watchdog** que espera (poll `kill(getppid(),0)` + `/proc/<pid>/stat` a 30 ms) a que la app muera y borra los residuos del run: la copia `<base>-nrld-<pid>`, el dir ABI `/tmp/nrld-<pid>`, la extracción AppImage y los parches de DT_NEEDED absolutos — nada queda tras salir con normalidad (verificado: corridas repetidas dejan 0 copias). El self-sweep sigue como red de seguridad (kill/Ctrl-C matan al grupo antes de limpiar). |
| `_start_main` | ~1001 | Entrada: `argc/argv/envp/auxv`, `AT_EXECFN`, modo manual (`nrld BIN`) vs directo (`PT_INTERP`), guard no-ELF, lectura de conf, build de `LD_LIBRARY_PATH`/`LD_PRELOAD`/`QT_PLUGIN_PATH`/`NEONATOX_REAL_EXE`/`NEONATOX_SYSROOT`, sanitización de `LD_*`, y el **modo raíz** (fork + swap de symlinks de `/lib64`) vs **modo usuario** (`make_interp_patched_copy` → exec de la copia parcheada con el loader in-process; fallback al exec directo del loader real si no hay `PT_INTERP` o el dir no es escribible). |
| `print_usage_help` | ~945 | El `--help` (stdout, es salida pedida). |

### `appimages.c`

| Sección | Qué resuelve |
|---|---|
| `get_squashfs_offset` | Escaneo **inverso** del magic `"hsqs"` (búsqueda del último squashfs embebido). |
| `is_appimage` | `EI_ABIVERSION != 0` + squashfs presente. |
| `name_is_so`, `dir_has_so` | Detección de `.so` (con versiones `.so.1.2.3`). |
| `collect_libdirs_rec` | Recorre la raíz extraída (profundidad ≤3) y colecciona los dirs que contienen `.so` → `g_extra_libdirs`. |
| `collect_qt_plugins_rec` | Busca el dir `platforms/` que contiene `.so` (plugin de plataforma Qt) → `QT_PLUGIN_PATH`. **Buffer local por llamada**: un buffer compartido rompía los hermanos tras una recursión profunda (no llegaba a `usr/bin`). |
| `find_lib_under` / `find_lib_in_sysroot` | **Extralibfinder**: localiza un soname faltante recursivamente en subdirectorios no estándar del sysroot (`gvfs/`, `pulseaudio/`, `engines-3/`, `dri/`...) y registra el dir para `resolve_lib_path` + `--library-path`. Nunca mira musl `/usr/lib`. |
| `find_elf_exec_in`, `find_internal_bin` | Descubre el binario interno del AppImage: **AppRun symlink→ELF** (OCAT) y **AppRun script `#!`** (se execa tal cual con `APPDIR`/`APPIMAGE`; el shell lanza el ELF real) son entradas canónicas. Un `AppRun` **ELF plano NO se prioriza** (launchers tipo OpenShot rompen al correr pelados: ncurses TUI + `.desktop`): se cae a `*.bin`, `usr/bin` y ELF top-level (nunca una `.so`). |
| `extract_appimage` | `unsquashfs` del host (musl) hacia `/tmp/nrld-appimage-<pid>/` + recolección de dirs de libs. Antes de extraer, `sweep_stale_appimage_dirs` borra las extracciones viejas que ningún proceso vivo referencia (exe/cwd en `/proc/*`): cada AppImage deja ~600 MB, sin esto `/tmp` se llena. |
| `append_lib_subdirs` | Monta la lista `:` de dirs internos + `g_extra_libdirs` para `LD_LIBRARY_PATH`. |
| Vía `AppRun` script en `_start_main` | Cuando el binario interno es un script, nrld lo execa **directo** (sin loader/copia) con el env heredado + `APPDIR=<raiz>` + `APPIMAGE=<AppImage>`, igual que el runtime real. El script execa el ELF interno, que **re-entra a nrld** como interp de un binario normal ya extraído → modo usuario estándar (copia parcheada). Fix de AppImages tipo Heroic (antes se elegía la primera ELF top-level, p. ej. `libvulkan.so.1`, y se ejecutaba el loader con la `.so`). |
| `launcher_bin_redirect` | Launcher estilo mozilla (`firefox`/`firefox-bin`, `thunderbird`...): el launcher es un ELF pequeño que deriva el binario real con `readlink("/proc/self/exe")` + `"-bin"`. En modo usuario `/proc/self/exe` es la copia `<base>-nrld-<pid>`, así que la derivación da `<base>-nrld-<pid>-bin` → `Exec failed with error: No such file or directory` (regresión Firefox moderno + ESR). Si existe el hermano `<base>-bin` (ELF) en el mismo dir, nrld ejecuta directamente ese binario real saltándose el launcher. Solo en modo usuario; en modo ROOT el launcher corre nativo y resuelve bien. |

### `proxy_readlink.c`

| Sección | Qué resuelve |
|---|---|
| Guard ABI musl (`g_glibc_host`) | En `init_proxy`: `dlopen("libc.so.6", RTLD_NOW)` devuelve NULL bajo musl → el proxy **se vuelve transparente** (readlink/dlopen/dlmopen delegan sin tocar nada, sin crash handlers). Solo en procesos con glibc real activa la interposición, para no romper los binarios musl del host con el `LD_PRELOAD` del perfil. |
| `readlink("/proc/self/exe")` | Solo reescribe cuando el kernel apunta al loader (modo cargador-as-main, sin copia parcheada) → devuelve `NEONATOX_REAL_EXE`. En modo usuario (copia con PT_INTERP parcheada) el `/proc/self/exe` del kernel YA es la app: reescribirlo a `NEONATOX_REAL_EXE` (el binario original) rompe la resolución recursiva de Chromium/Electron (SIGTRAP/NOTREACHED en arranque, verificado live). El modo se detecta una vez en `init_proxy` con un `readlink` crudo de `/proc/self/exe`: si el basename es `ld-*` → loader-as-main (red de seguridad); si es la app → no se toca la respuesta del kernel. |
| `derive_allow_dir`, `is_allowed_path` | Dirs permitidos: `/usr/lib/glibc6/*` (`under_sysroot`, root desde `NEONATOX_SYSROOT`), `NEO_BINDIR` (el proxy/librarys propias), el dir del exe real, `NEONATOX_APPDIR` y el propio loader glibc del rtld. |
| `redirect_to_sysroot` | Reencamina `dlopen("/usr/lib/...")` a la copia glibc del sysroot si existe (mismo path relativo). |
| `dlopen`/`dlmopen` interposición | Solo strict: tras cada `dlopen` escanea **todo el link-map** (`dl_iterate_phdr`); si algo resuelve fuera del sysroot (musl) → `dlclose` + `NULL` + mensaje `[neonatox] Falta la libreria...`. Cubre árboles cargados en runtime (el `libxul` de Firefox). |
| Verdict cache | Una ruta permitida queda permitida para todo el proceso → Chromium (cientos de `dlopen`) no paga un walk completo por cada uno. |
| Crash diagnostics (`NEONATOX_CRASHDUMP=1`) | Handlers SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE: dump del módulo+offset (vía `/proc/self/maps`) y de librerías musl mapeadas. |
| `NEONATOX_PROXY_LOG` / `NEONATOX_DUMPENV` | Espejo a archivo de los mensajes `[neonatox]` (no a stderr, para no ensuciar) y dump del entorno a `/tmp/neonatox-env-<pid>.txt`. |

---

## Compilar

Vía **meson** (recomendado: genera también `/etc/nrld.conf`, `/etc/profile.d/nrld-profile.sh`,
el symlink del interp y el test E2E):

```bash
meson setup build --prefix=/usr        # opciones: -Dglibc_sysroot=...
meson compile -C build
meson test -C build                    # E2E (no necesita root)
sudo meson install -C build            # root: instala + symlink + ldconfig del sysroot
```

O receta **manual** (mismos binarios, sin conf/perfil/symlink automático):

```bash
# 1. Proxy (sin libc: deja símbolos undefined, los resuelve glibc en runtime)
gcc -nostdlib -shared -fPIC -o libnrld-proxy.so \
    -I/usr/lib/glibc6/usr/include \
    proxy_readlink.c

# 2. Fake loader (freestanding, sin libc)
gcc -nostdlib -static -ffreestanding -fno-stack-protector -O2 -s \
    -o nrld nrld.c
```

> `-I/usr/lib/glibc6/usr/include`: cabeceros glibc del sysroot (definen `Lmid_t`).
> (En el build meson, `NEO_SYSROOT`/`NEO_BINDIR` se pasan con `-D`; en la receta
> manual valen sus defaults `-DNEO_SYSROOT="/usr/lib/glibc6"`,
> `-DNEO_BINDIR="/usr/lib/neonatox"`.)
> `-nostdlib` en el proxy: si se enlazara con el `gcc` musl del host emitiría
> `NEEDED [libc.so]` (soname musl) → "invalid ELF header" en el loader glibc.
> El proxy debe compilarse **sin** libc del host y con `-fno-stack-protector`
> ausentes → símbolos ambiguos quedan como undefined legítimos que glibc resuelve
> en runtime (en meson, `b_lundef=false`).

## Instalar (requiere root)

```bash
sudo meson install -C build
```

Instala y deja listo:

- `/usr/lib/neonatox/nrld` y `/usr/lib/neonatox/libnrld-proxy.so` **(en el host,
  fuera del sysroot)**.
- `/etc/nrld.conf` (host) — generado desde la plantilla `nrld.conf`; strict
  global con `echo strict | sudo tee -a /etc/nrld.conf`.
- `/etc/profile.d/nrld-profile.sh` — env del perfil (ver **Uso**).
- symlink `/lib64/ld-linux-x86-64.so.2` → `/usr/lib/neonatox/nrld` (el kernel
  carga nrld como interp).
- post-install: refresca el cache `ldconfig` del sysroot glibc.

**Migrar desde el layout viejo** (mezclas de `/usr/lib/glibc6/usr/bin/nrld`,
`/usr/lib/glibc6/lib/libnrld-proxy.so` y `/usr/lib/glibc6/etc/nrld.conf` existentes
**después** de instalar el nuevo, porque el re-install repointa el symlink de
`/lib64`):

```bash
sudo rm -f /usr/lib/glibc6/usr/bin/nrld \
           /usr/lib/glibc6/lib/libnrld-proxy.so \
           /usr/lib/glibc6/etc/nrld.conf
```

En vez de `meson install`, la instalación manual equivale a:

```bash
sudo install -o root -m755 nrld /usr/lib/neonatox/nrld
sudo install -o root -m644 libnrld-proxy.so /usr/lib/neonatox/libnrld-proxy.so
sudo ln -svf /usr/lib/neonatox/nrld /lib64/ld-linux-x86-64.so.2
sudo install -o root -m644 nrld.conf /etc/nrld.conf   # ajustar librerías si no son las default
sudo install -o root -m644 nrld-profile.sh /etc/profile.d/nrld-profile.sh
```

## Uso

`nrld` es el interp del sistema (`/lib64/ld-linux-x86-64.so.2` → nrld), así que el kernel lo
carga solo: `./firefox`, `./othello-app`, `./AppImage...`. Modo estricto global:

```bash
echo strict | sudo tee -a /etc/nrld.conf
```

**Pestañas de Firefox/Brave (proxies de contenido):** con el modo usuario, la
copia parcheada `<base>-nrld-<pid>` hereda `LD_PRELOAD`/`LD_LIBRARY_PATH` solo
en arranque directo — el sandbox de contenido quita el `LD_PRELOAD` a los
procesos hijo. El perfil exporta el entorno para que los hijos lo hereden de la
shell:

```bash
source /etc/profile.d/nrld-profile.sh            # login shells ya lo hacen solos
echo 'source /etc/profile.d/nrld-profile.sh' >> ~/.bashrc   # shells interactivas de escritorio
```

En strict (env `NEONATOX_STRICT_SYSROOT=1` o `nrld.conf`): falla limpio (exit 1) si falta
cualquier dependencia `DT_NEEDED` (guard transitivo) o si un `dlopen` en runtime resolvería a
una build musl de `/usr/lib` — en vez del SIGSEGV de mezcla de libcs en `strtod_l`.
El proxy es **transparente bajo musl**: el mismo `LD_PRELOAD` global del perfil no rompe
los binarios musl del host (ver `test/run_tests.sh`, caso 4).

---

## Estado actual

- **Sysroot** `/usr/lib/glibc6/`: core glibc + libstdc++/libgcc_s + **pila GUI base** glibc
  (gtk, gdk-pixbuf, pango, cairo, glib2/gobject/gio, atk, ICU, X11/*xcb, dbus, libpulse,
  avahi, openssl, libjxl, turbojpeg, gvfs, ...) en `/usr/lib/glibc6/usr/lib`, más libs en
  subdirectorios no estándar (`gvfs/`, `pulseaudio/`, `engines-3/`, `gconv/`, `dri/`,
  `systemd/`, `ossl-modules/`, `pkcs11/`, `security/`, `audit/`, `cairo/`,
  `libcanberra-0.30/`, `tinysparql-3.0/`, `vdpau/`, `gbm/`).
- **Extralibfinder** validado E2E: un ELF con `NEEDED libvdpau_trace.so.1` (que solo existe en
  `/usr/lib/glibc6/usr/lib/vdpau/`) se resuelve en strict (`[OK]`) y el dir del subdir entra en
  `LD_LIBRARY_PATH` → la app corre (rc=0).
- **OpenShot 4.0.0** (AppImage): arranca completo bajo Xvfb con strict (Qt `xcb` cargado vía
  `QT_PLUGIN_PATH`, sin `[neonatox] Falta`). El plugin Qt se detectó tras arreglar el buffer
  compartido del scan recursivo.
- **Firefox**: abre ventana (pestañas aún pendientes). **OCAT**: abre. **Brave**: llega al
  exec del loader; sin proxy falla ICU (esperado, lo corrige el proxy con `readlink`);
  pendiente re-test con el proxy con verdict-cache y si hace falta `--no-sandbox`/
  `--disable-gpu`/`--disable-dev-shm-usage`.
- **Procesos hijo que re-ejecutan su binario (pestañas Firefox/Brave)**: fail-mode clásico
  era "process N exited with status 1" (el hijo resolvía `/proc/self/exe` por una vía que
  sortea el `LD_PRELOAD` del proxy y, bajo el esquema viejo loader-as-main, re-ejecutaba el
  loader como programa → glibc lo rechazaba como app). Corregido con el modo usuario actual:
  el hijo re-ejecuta la copia patcheada `<base>-nrld-<pid>` que queda en el dir del app
  (`PT_INTERP` → loader real, kernel in-process), glibc-natural, sin nrld ni interposición.
  La copia parcheada se mantiene en el dir tras el arranque (los hijos la re-ejecutan);
  tiene nombre legible (`<base>-nrld-<pid>`). Cada ejecución deja una, y la
  siguiente ejecución del mismo `<base>` **barre las copias
  viejas** (solo se conserva la que aún es `/proc/self/exe` de un proceso vivo, p. ej. una
  instancia concurrente). Sobrevive a lo sumo una copia obsoleta por `<base>`, limpiada por
  la siguiente ejecución.
- **Refactor build/config/host (`main` actual)**: sysroot `/usr/lib/glibc6` como default
  compile-time (`NEO_SYSROOT`, no runtime); binarios y config en el **host**
  (`/usr/lib/neonatox/`, `/etc/nrld.conf`, `/etc/profile.d/nrld-profile.sh`) fuera del
  sysroot; copias legibles `<base>-nrld-<pid>`; proxy con **guard ABI musl** (transparente
  bajo musl, activo solo bajo glibc). Build con **meson** (`meson setup|compile|test|install`)
  manteniendo la receta gcc manual. **E2E en `meson test`** sobre ELF64 mínimos generados por
  `test/gen_probes.py` (estructura a mano, sin toolchain glibc en el host): humo rc=0,
  sweep ≤1 copia, strict vs default y proxy-musl-transparente — todo verde.
- **Limitación conocida**: el toolchain musl del host no puede construir binarios dinámicos
  glibc de test (`libc.a` sin `_init`/`_fini`); los flujos end-to-end de dlopen se validan con
  los artefactos prácticos reales (los probes de `gen_probes.py` se escriben a mano).

---

## Copyright

Copyright (C) 2026 **Carlos Sánchez** — licencia **GPL v3**.

Parte del ecosistema **neonatox**.
