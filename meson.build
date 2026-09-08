project('neonatox-rldispatcher', 'c',
    version: '1.1.0',
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

nrld = executable('nrld',
    sources: 'nrld.c',
    c_args: [
        '-ffreestanding',
        '-fno-stack-protector',
        '-DNEO_SYSROOT="@0@"'.format(sysroot),
        '-DNEO_BINDIR="@0@"'.format(ndir),
    ],
    link_args: ['-nostdlib', '-static'],
    install: true,
    install_dir: ndir,
)

proxy = shared_library('nrld-proxy',
    sources: 'proxy_readlink.c',
    c_args: [
        '-I' + glibc_incs,
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
           meson.project_source_root()],
    timeout: 180)