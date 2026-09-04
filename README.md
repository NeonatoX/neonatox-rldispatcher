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
| `nrld.c` | 1285 | El fake loader (freestanding, sin libc). Detecta el binario, arma `LD_LIBRARY_PATH`/`LD_PRELOAD`, guard transitivo de NEEDED, y en **modo usuario** ejecuta una copia parcheada del app (mismo dir, `PT_INTERP` → loader real) para que el kernel cargue el loader glibc **in-process** y `/proc/self/exe` siga apuntando al app. |
| `appimages.c` | 386 | Soporte AppImage type-2 (extracción squashfs a `/tmp`, binario interno) + los walkers recursivos de directorios: libs internas, plugin Qt (`QT_PLUGIN_PATH`) y el **extralibfinder**. Se `#include` desde `nrld.c`. |
| `proxy_readlink.c` | 461 | `LD_PRELOAD` que endereza `readlink("/proc/self/exe")` y aplica la aislación ABI en runtime (`dlopen` strict + cache de veredictos + crash diagnostics). |
| `README.md` | — | Este documento. |
| `AGENTS.md` | — | Notas técnicas de la aislación musl↔glibc (restricciones, comportamientos conocidos). |

---

## nrld verboso (--help)

`nrld` es verboso por diseño: imprime `[DEBUG]`, `[ADV]`, `[INFO]`, `[OK]` y `[ERROR]` a
stderr explicando cada decisión. Con `nrld --help` (o `-h`) se obtiene el resumen completo:

```text
NeonatoX RLDispatcher (nrld) -- fake glibc linker para hosts musl

Uso:
  nrld --help                        Muestra esta ayuda (modo verboso)
  nrld BIN [ARGOS...]                Ejecuta BIN glibc sobre el sysroot
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
     /tmp/nrld-<pid>/ (traducidos a soname resoluble por --library-path).
  6. Ejecuta BIN: en modo usuario crea una copia parcheada en el MISMO
     directorio de la app (<base>.nrld-<pid>, PT_INTERP reescrito al loader
     real) y la exec: el kernel carga el loader glibc in-process, asi
     /proc/self/exe sigue siendo el app (recursos/omni.ja/icudtl.dat OK)
     y los hijos que re-ejecutan su propio binario siguen funcionando.
     Con LD_PRELOAD del proxy libnrld-proxy.so (endereza /proc/self/exe
     y aplica el scan strict de dlopen). Si no hay PT_INTERP (estatico/
     musl) o el dir no es escribible: fallback al loader como principal
     (--library-path + LD_PRELOAD).

Modo estricto del sysroot (aislacion musl<->glibc):
  NEONATOX_STRICT_SYSROOT=1 ./BIN    falla limpio si falta algo
  echo strict > /etc/nrld.conf       hace estricto todo (sin env)
  (evita la mezcla de dos libcs en un proceso -> el SIGSEGV de strtod_l)

Variables de entorno que nrld importa/exporta:
  NEONATOX_STRICT_SYSROOT   strict por env (0/1)
  NEONATOX_REAL_EXE         ruta real del binario (la lee el proxy)
  NEONATOX_APPDIR           raiz extraida de un AppImage
  NEONATOX_DUMPENV          dump del entorno del hijo a /tmp (debug)
  NEONATOX_PROXY_LOG        archivo espejo de los mensajes del proxy a stderr
                            (imprescindible para ver rechazos en procesos de
                            contenido de Firefox, cuyo stderr se pierde en el
                            pipe del parent)
  QT_PLUGIN_PATH            dir del plugin de plataforma Qt (si aplica)

Salida (modo verboso por defecto):
  [DEBUG] razonamiento interno      [ADV] avisos (faltantes/extraccion)
  [INFO]  cambios de config         [OK]  todas las NEEDED en el sysroot
  [ERROR] fallo (solo en strict)    [neonatox] mensajes del proxy

Copyright (C) 2026 Carlos Sanchez. Licencia GPL v3.
```

> `--help`/`-h` solo actúa cuando se invoca `nrld` directamente (nunca como `PT_INTERP`,
> para no robarle el flag a la app).

---

## Secciones de los archivos y qué resuelven

### `nrld.c`

| Sección | Refs. | Qué resuelve |
|---|---|---|
| Helpers sin libc | syscalls `syscallN()`, `my_strlen/cpy/cat/cmp`, `print_msg/print_err`, `file_exists`, `uint_to_str`, `is_elf` | Todo el runtime freestanding (no hay `malloc`/`printf`). |
| `read_eident`, `copy_bytes` | ~123 | Lee `e_ident` y copia archivos en chunks (para parchear). |
| `maybe_patch_abi_version` | ~148 | Los ELF type-2/AppImage llevan `EI_ABIVERSION != 0` y el loader glibc los **rechaza**; crea copia parcheada en `/tmp/nrld-<pid>/` y ejecuta la copia (el original queda intacto). |
| Globals AppImage + forward `find_lib_in_sysroot` | ~230 | Estado compartido (antes del `#include "appimages.c"`). |
| `resolve_lib_path` | ~247 | Soname → ruta: dir del binario + subdirs estándar + `g_extra_libdirs` + sysroot; con fallback **extralibfinder**. |
| `get_needed_names` | ~302 | Parsea `DT_NEEDED` de un ELF (vía `PT_DYNAMIC`/`PT_LOAD`, vaddr→offset). |
| `fix_abs_needed` / `create_shadow_copy` | ~414 | `DT_NEEDED` con **ruta absoluta** (e.g. `libxul.so`): el loader ignora el path pero pierde la lib; se traduce a soname en una copia parcheada que `--library-path` sí resuelve. |
| `scan_missing_libs` / `check_needed_libs` | ~507 | Guard **transitivo** de cobertura NEEDED (BFS con visited, ciclo/dedup acotado a 512): recorre los `DT_NEEDED` de cada lib que resuelve dentro del sysroot. |
| `config_enforces_strict` | ~615 | Lee `/usr/lib/glibc6/etc/nrld.conf` por raw syscalls; token `strict` → todas las apps estrictas sin prefijo env. |
| `_start_main` | ~689 | Entrada: `argc/argv/envp/auxv`, `AT_EXECFN`, modo manual (`nrld BIN`) vs directo (`PT_INTERP`), guard no-ELF, build de `LD_LIBRARY_PATH`/`LD_PRELOAD`/`QT_PLUGIN_PATH`/`NEONATOX_REAL_EXE`, sanitización de `LD_*`, y el **modo raíz** (fork + swap de symlinks de `/lib64`) vs **modo usuario** (`make_interp_patched_copy` → exec de la copia parcheada con el loader in-process; fallback al exec directo del loader real si no hay `PT_INTERP` o el dir no es escribible). |
| `print_usage_help` | ~689 | El `--help` verbose. |

### `appimages.c`

| Sección | Qué resuelve |
|---|---|
| `get_squashfs_offset` | Escaneo **inverso** del magic `"hsqs"` (búsqueda del último squashfs embebido). |
| `is_appimage` | `EI_ABIVERSION != 0` + squashfs presente. |
| `name_is_so`, `dir_has_so` | Detección de `.so` (con versiones `.so.1.2.3`). |
| `collect_libdirs_rec` | Recorre la raíz extraída (profundidad ≤3) y colecciona los dirs que contienen `.so` → `g_extra_libdirs`. |
| `collect_qt_plugins_rec` | Busca el dir `platforms/` que contiene `.so` (plugin de plataforma Qt) → `QT_PLUGIN_PATH`. **Buffer local por llamada**: un buffer compartido rompía los hermanos tras una recursión profunda (no llegaba a `usr/bin`). |
| `find_lib_under` / `find_lib_in_sysroot` | **Extralibfinder**: localiza un soname faltante recursivamente en subdirectorios no estándar del sysroot (`gvfs/`, `pulseaudio/`, `engines-3/`, `dri/`...) y registra el dir para `resolve_lib_path` + `--library-path`. Nunca mira musl `/usr/lib`. |
| `find_elf_exec_in`, `find_internal_bin` | Descubre el binario interno del AppImage (AppRun→ELF, `*.bin`, `usr/bin`, ELF top-level). |
| `extract_appimage` | `unsquashfs` del host (musl) hacia `/tmp/nrld-appimage-<pid>/` + recolección de dirs de libs. |
| `append_lib_subdirs` | Monta la lista `:` de dirs internos + `g_extra_libdirs` para `LD_LIBRARY_PATH`. |

### `proxy_readlink.c`

| Sección | Qué resuelve |
|---|---|
| `readlink("/proc/self/exe")` | Devuelve `NEONATOX_REAL_EXE` en vez del loader. Con el modo usuario actual el `/proc/self/exe` del kernel ya es el app (copia parcheada), así que esta interposición es la red de seguridad para procesos ya cargados bajo el camino viejo/loader-as-main (los hijos que re-ejecutan se cubren solos vía la copia parcheada). |
| `derive_allow_dir`, `is_allowed_path` | Dirs permitidos: `/usr/lib/glibc6/*`, el dir del exe real y `NEONATOX_APPDIR`. |
| `redirect_to_sysroot` | Reencamina `dlopen("/usr/lib/...")` a la copia glibc del sysroot si existe (mismo path relativo). |
| `dlopen`/`dlmopen` interposición | Solo strict: tras cada `dlopen` escanea **todo el link-map** (`dl_iterate_phdr`); si algo resuelve fuera del sysroot (musl) → `dlclose` + `NULL` + mensaje `[neonatox] Falta la libreria...`. Cubre árboles cargados en runtime (el `libxul` de Firefox). |
| Verdict cache | Una ruta permitida queda permitida para todo el proceso → Chromium (cientos de `dlopen`) no paga un walk completo por cada uno. |
| Crash diagnostics (`NEONATOX_CRASHDUMP=1`) | Handlers SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE: dump del módulo+offset (vía `/proc/self/maps`) y de librerías musl mapeadas. |
| `NEONATOX_DUMPENV` | Dump del entorno del proceso a `/tmp/neonatox-env-<pid>.txt`. |

---

## Compilar

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
> `-nostdlib` en el proxy: si se enlazara con el `gcc` musl del host emitiría
> `NEEDED [libc.so]` (soname musl) → "invalid ELF header" en el loader glibc.

## Instalar (requiere root)

```bash
sudo install -o root -m755 nrld /usr/lib/glibc6/usr/bin/nrld
sudo install -o root -m644 libnrld-proxy.so /usr/lib/glibc6/lib/libnrld-proxy.so
sudo ln -svf /usr/lib/glibc6/usr/bin/nrld /lib64/ld-linux-x86-64.so.2
sudo install -o root -m644 libnrld-proxy.so /usr/lib/glibc6/lib/libnrld-proxy.so
sudo install -o root -m644 nrld.conf /usr/lib/glibc6/etc/nrld.conf
```

## Uso

`nrld` es el interp del sistema (`/lib64/ld-linux-x86-64.so.2` → nrld), así que el kernel lo
carga solo: `./firefox`, `./othello-app`, `./AppImage...`. Modo estricto global:

```bash
sudo mkdir -p /usr/lib/glibc6/etc
echo strict | sudo tee /usr/lib/glibc6/etc/nrld.conf
```

En strict (env `NEONATOX_STRICT_SYSROOT=1` o `nrld.conf`): falla limpio (exit 1) si falta
cualquier dependencia `DT_NEEDED` (guard transitivo) o si un `dlopen` en runtime resolvería a
una build musl de `/usr/lib` — en vez del SIGSEGV de mezcla de libcs en `strtod_l`.

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
  el hijo re-ejecuta la copia parcheada `<base>.nrld-<pid>` que queda en el dir del app
  (`PT_INTERP` → loader real, kernel in-process), glibc-natural, sin nrld ni interposición.
  La copia parcheada se mantiene en el dir tras el arranque (los hijos la re-ejecutan);
  cada ejecución deja una, y la siguiente ejecución del mismo `<base>` **barre las copias
  viejas** (solo se conserva la que aún es `/proc/self/exe` de un proceso vivo, p. ej. una
  instancia concurrente). Sobrevive a lo sumo una copia obsoleta por `<base>`, limpiada por
  la siguiente ejecución.
- **Limitación conocida**: el toolchain musl del host no puede construir binarios dinámicos
  glibc de test (`libc.a` sin `_init`/`_fini`); los flujos end-to-end de dlopen se validan con
  los artefactos prácticos reales.

---

## Copyright

Copyright (C) 2026 **Carlos Sánchez** — licencia **GPL v3**.

Parte del ecosistema **neonatox**.
