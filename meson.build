project('neonatox-rldispatcher', 'c',
    version: '0.1.0',
    meson_version: '>=0.61',
    default_options: [
        'c_std=gnu99',
        'prefix=/usr',
        'optimization=2',
        'b_ndebug=if-release',
        'b_lundef=false',
    ])

sysroot = get_option('glibc_sysroot')
ndir    = get_option('neonatox_dir')
interp  = get_option('interp_path')

glibc_incs = join_paths(sysroot, 'usr', 'include')

nrld_sources = files(
    'nrld.c',
    'utils.c',
    'elf_parser.c',
    'sysroot_manager.c',
    'appimages.c',
    'executor.c',
)

nrld_cargs = [
    '-ffreestanding',
    '-fno-stack-protector',
    '-DNEO_SYSROOT="@0@"'.format(sysroot),
    '-DNEO_BINDIR="@0@"'.format(ndir),
]

nrld = executable('nrld',
    sources: nrld_sources,
    c_args: nrld_cargs,
    link_args: ['-nostdlib', '-static'],
    install: true,
    install_dir: ndir,
)

# Variante SOLO para tests: el mismo nrld con el limite de dirs extra de
# librerias (MAX_EXTRA_DIRS) reducido a 2, para poder ejercitar el guard de
# "g_extra_libdirs lleno" con una app que necesita 3 dirs distintos.
# No se instala (install: false).
nrld_lim2 = executable('nrld-lim2',
    sources: nrld_sources,
    c_args: nrld_cargs + ['-DMAX_EXTRA_DIRS=2'],
    link_args: ['-nostdlib', '-static'],
    install: false,
)

proxy = shared_library('nrld-proxy',
    sources: 'proxy_readlink.c',
    c_args: [
        '-I' + glibc_incs,
        # El estado del scan strict (found_bad/bad_path/verdict_cache) es TLS
        # por hilo. initial-exec -> acceso directo (sin __tls_get_addr): el
        # proxy es siempre LD_PRELOAD, asi que su bloque TLS es estatico.
        # OJO: nunca dlopen()ear este .so (initial-exec + bloque grande
        # excede el surplus de TLS estatico de glibc -> "cannot allocate
        # memory in static TLS block").
        '-ftls-model=initial-exec',
        '-DNEO_SYSROOT="@0@"'.format(sysroot),
        '-DNEO_BINDIR="@0@"'.format(ndir),
    ],
    link_args: ['-nostdlib'],
    install: true,
    install_dir: ndir,
)

conf = configuration_data()
conf.set('SYSROOT', sysroot)
conf.set('PROXY', join_paths(ndir, 'libnrld-proxy.so'))
conf.set('LIBRARY_PATH', join_paths(sysroot, 'usr', 'lib') + ':' + join_paths(sysroot, 'lib'))

configure_file(input: 'nrld.conf',
    output: 'nrld.conf',
    configuration: conf,
    install: true,
    install_dir: get_option('sysconfdir'))

configure_file(input: 'nrld-profile.sh',
    output: 'nrld-profile.sh',
    configuration: conf,
    install: true,
    install_dir: join_paths(get_option('sysconfdir'), 'profile.d'))

install_symlink('ld-linux-x86-64.so.2',
    pointing_to: join_paths(ndir, 'nrld'),
    install_dir: '/lib64')

meson.add_install_script('scripts/post-install.sh', sysroot)

test('e2e', find_program('bash'),
    args: [files('test/run_tests.sh'),
           nrld.full_path(),
           proxy.full_path(),
           meson.project_source_root(),
           nrld_lim2.full_path()],
    timeout: 180)

# Test TSan del scan strict del proxy: 8 hilos x 500 dlopen() concurrentes.
# El estado del scan (found_bad/bad_path/verdict_cache) es TLS por hilo; este
# test comprueba que la version con globals (codigo previo) reporta la
# carrera y que la version TLS no reporta ninguna, y que el veredicto en
# single-thread no cambia. Requiere el toolchain glibc del sysroot (libtsan):
# sin el -> SKIP.
test('tsan', find_program('bash'),
    args: [files('test/tsan/run_tsan.sh'),
           meson.project_source_root()],
    timeout: 300)
