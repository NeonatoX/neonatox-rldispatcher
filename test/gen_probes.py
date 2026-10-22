#!/usr/bin/env python3
"""Generate minimal handcrafted ELF64 x86-64 test probes for nrld E2E tests.

Each probe is a dynamically-linked executable whose PT_INTERP is
/lib64/ld-linux-x86-64.so.2 and whose payload just calls exit(0). The only
functional content is a single DT_NEEDED entry:

  need_vdpau   -> NEEDED libvdpau_trace.so.1 (resolves ONLY inside the sysroot
                  via the extralibfinder: NEEDED already found in a bin_dir
                  subdir, so no -L provided; checker (0/1-style) NOT run either.
                  This is the AppImage/standalone case.)
  need_missing -> NEEDED libnrld-missing-probe.so.1 (nowhere; strict fails)

Payload probes (sin DT_NEEDED, payload de machine code escrito a mano):

  exec_scrub -> execve("/bin/sh", ["sh","-c","echo L=$LD_LIBRARY_PATH
               P=$LD_PRELOAD FOO=$FOO"], envp craft con LD_LIBRARY_PATH/
               LD_PRELOAD/FOO. Target musl: el proxy debe scrubear LD_*.
  exec_keep  -> execve(argv[1], [argv[1], NULL], envp heredado del stack.
               Target glibc (env_dump): el env debe pasar INTACTO.
  env_dump   -> imprime todas las lineas de su envp heredado y exit(0).

No section headers, one RWX PT_LOAD, three program headers (LOAD, INTERP,
DYNAMIC). Written with struct only.
"""
import os
import struct
import sys


CODE_VADDR = 0x400000 + 0x300   # code_off de build_simple

# vaddr del stub PLT de execve (plt0 16B + el primer stub); la calcula
# igual build_simple (assert abajo) — el payload la necesita para el call.
PLT_EXECVE = 0x400000 + 0x1c0 + 16


class Asm:
    """Miniensamblador x86-64: suficiente para los payloads de arriba.

    El blob que produce se coloca en el ELF en la vaddr CODE_VADDR, asi que
    las etiquetas valen como diferencias RIP y las tablas de punteros se
    resuelven como CODE_VADDR+pos."""

    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.refs = []          # (pos, label, kind)

    def label(self, name):
        self.labels[name] = len(self.buf)

    def raw(self, b):
        self.buf += bytes(b)

    def strz(self, s):
        self.buf += s.encode() + b"\0"

    def ptrs(self, *names):
        for nm in names:
            if nm is None:
                self.buf += b"\0" * 8
            else:
                self.buf += struct.pack("<Q", CODE_VADDR + self.labels[nm])

    def jcc_short(self, opcode, label):
        self.refs.append((len(self.buf), label, "short"))
        self.raw([opcode, 0])

    def lea_rip(self, reg_field, label):
        # REX.W 8d /r con ModRM mod=00 rm=101 (RIP-relative)
        self.refs.append((len(self.buf), label, "rip"))
        self.raw([0x48, 0x8d, 0x05 | (reg_field << 3), 0, 0, 0, 0])

    def call_abs(self, target):
        # e8 rel32 a una vaddr absoluta (p.ej. el stub PLT de execve)
        self.refs.append((len(self.buf), ("call", target), "call"))
        self.raw([0xe8, 0, 0, 0, 0])

    def resolve(self):
        for pos, label, kind in self.refs:
            if kind == "call":
                off = label[1] - (CODE_VADDR + pos + 5)
                struct.pack_into("<i", self.buf, pos + 1, off)
                continue
            tgt = self.labels[label]
            if kind == "short":
                off = tgt - (pos + 2)
                assert -128 <= off <= 127, "jcc corto fuera de rango"
                self.buf[pos + 1] = off & 0xff
            else:
                off = tgt - (pos + 7)
                struct.pack_into("<i", self.buf, pos + 3, off)
        self.refs = []


def payload_exec_scrub():
    """execve("/bin/sh", sh -c 'echo L=$LD_LIBRARY_PATH P=$LD_PRELOAD
    FOO=$FOO', envp con LD_LIBRARY_PATH/LD_PRELOAD/FOO)."""
    a = Asm()
    a.lea_rip(7, "shpath")      # lea rdi,[rip+shpath]
    a.lea_rip(6, "argv")        # lea rsi,[rip+argv]
    a.lea_rip(2, "envp")        # lea rdx,[rip+envp]
    a.call_abs(PLT_EXECVE)      # call execve@plt (via libc: pasa por la
                                # interposicion del proxy, no por syscall)
    a.raw([0x89, 0xc7])                   # mov edi,eax (rc=-1)
    a.raw([0xb8, 0x3c, 0, 0, 0])          # mov eax,60 (exit)
    a.raw([0x0f, 0x05])                   # syscall
    a.label("shpath"); a.strz("/bin/sh")
    a.label("sh"); a.strz("sh")
    a.label("dashc"); a.strz("-c")
    a.label("cmd"); a.strz("echo L=$LD_LIBRARY_PATH P=$LD_PRELOAD FOO=$FOO")
    a.label("ldlp"); a.strz("LD_LIBRARY_PATH=/usr/lib/glibc6/usr/lib")
    a.label("ldpre"); a.strz("LD_PRELOAD=/usr/lib/neonatox/libnrld-proxy.so")
    a.label("foo"); a.strz("FOO=bar")
    a.label("argv"); a.ptrs("sh", "dashc", "cmd", None)
    a.label("envp"); a.ptrs("ldlp", "ldpre", "foo", None)
    a.resolve()
    return bytes(a.buf)


def payload_exec_keep():
    """execve(argv[1], [argv[1], NULL], envp heredado). Target glibc."""
    a = Asm()
    a.raw([0x48, 0x8b, 0x04, 0x24])          # mov rax,[rsp] (argc)
    a.raw([0x48, 0x83, 0xf8, 0x02])          # cmp rax,2
    a.jcc_short(0x7c, "fail")                # jl fail
    a.raw([0x48, 0x8b, 0x7c, 0x24, 0x10])    # mov rdi,[rsp+16] (argv[1])
    a.raw([0x48, 0x8d, 0x74, 0x24, 0x10])    # lea rsi,[rsp+16] ({argv[1],NULL})
    a.raw([0x48, 0x8b, 0x0c, 0x24])          # mov rcx,[rsp] (argc)
    a.raw([0x48, 0x8d, 0x54, 0xcc, 0x10])    # lea rdx,[rsp+rcx*8+16] (envp)
    a.call_abs(PLT_EXECVE)      # call execve@plt (interpuesto; target
                                # glibc -> sin scrub, env intacto)
    a.label("fail")
    a.raw([0xb8, 0x3c, 0, 0, 0])             # mov eax,60
    a.raw([0xbf, 0x7f, 0, 0, 0])             # mov edi,127
    a.raw([0x0f, 0x05])                      # syscall
    a.resolve()
    return bytes(a.buf)


def payload_env_dump():
    """Imprime cada entrada de su envp heredado (una por linea) y exit(0)."""
    a = Asm()
    a.raw([0x48, 0x83, 0xec, 0x10])          # sub rsp,16 (newline buf)
    a.raw([0x48, 0x8b, 0x5c, 0x24, 0x10])    # mov rbx,[rsp+16] (argc)
    a.raw([0x4c, 0x8d, 0x64, 0xdc, 0x20])    # lea r12,[rsp+rbx*8+32] (envp)
    a.label("loop")
    a.raw([0x4d, 0x8b, 0x34, 0x24])          # mov r14,[r12]
    a.raw([0x4d, 0x85, 0xf6])                # test r14,r14
    a.jcc_short(0x74, "done")                # jz done
    a.raw([0x31, 0xd2])                      # xor edx,edx
    a.label("l2")
    a.raw([0x41, 0x80, 0x3c, 0x16, 0x00])    # cmp byte [r14+rdx],0 (SIB base=110+r14)
    a.jcc_short(0x74, "l3")                  # je l3
    a.raw([0x48, 0xff, 0xc2])                # inc rdx
    a.jcc_short(0xeb, "l2")                  # jmp l2
    a.label("l3")                            # write(1, envp[i], len)
    a.raw([0xb8, 1, 0, 0, 0])                # mov eax,1
    a.raw([0xbf, 1, 0, 0, 0])                # mov edi,1
    a.raw([0x4c, 0x89, 0xf6])                # mov rsi,r14
    a.raw([0x0f, 0x05])                      # syscall
    a.raw([0xc6, 0x04, 0x24, 0x0a])          # mov byte [rsp],10
    a.raw([0xb8, 1, 0, 0, 0])                # mov eax,1
    a.raw([0xbf, 1, 0, 0, 0])                # mov edi,1
    a.raw([0x48, 0x89, 0xe6])                # mov rsi,rsp
    a.raw([0xba, 1, 0, 0, 0])                # mov edx,1
    a.raw([0x0f, 0x05])                      # syscall
    a.raw([0x49, 0x83, 0xc4, 0x08])          # add r12,8
    a.jcc_short(0xeb, "loop")                # jmp loop
    a.label("done")
    a.raw([0x48, 0x83, 0xc4, 0x10])          # add rsp,16
    a.raw([0x31, 0xff])                      # xor edi,edi
    a.raw([0xb8, 0x3c, 0, 0, 0])             # mov eax,60
    a.raw([0x0f, 0x05])                      # syscall
    a.resolve()
    return bytes(a.buf)


def build_simple(path, interp, payload, needed=None, funcs=()):
    """ELF64 ET_EXEC con PT_INTERP, DT_NEEDED opcional e imports via PLT.

    - needed: DT_NEEDED (p.ej. libc.so.6). Sin libs en scope el proxy
      preloaded no resuelve `environ` (simbolo de DATOS: la resolucion es
      al cargar, no lazy); en procesos glibc reales libc siempre esta.
    - funcs: funciones a importar via PLT+RELA (p.ej. execve). El payload
      las llama con `call` en vez de syscall crudo: solo asi pasan por la
      interposicion del proxy (execve -> scrub de LD_* a hijos musl).

    El DYNAMIC lleva STRTAB/STRSZ/SYMTAB/HASH (y PLT*/RELA si hay funcs)
    ademas de DT_NULL: el loader glibc hace SEGV con un PT_DYNAMIC que solo
    contiene DT_NULL (mismo hallazgo que en build(); ahi sin hash/symtab
    casca al resolver)."""
    base = 0x400000
    interp_off = 0x100
    dynstr_off = 0x140
    dynsym_off = 0x160
    syhash_off = 0x190
    rela_off = 0x1a8

    nfunc = len(funcs)
    nsyms = 1 + nfunc                 # sym0 NULL + funcs

    interp_b = interp.encode() + b"\0"
    dynstr = b"\0"
    needed_off = 0
    if needed:
        needed_off = len(dynstr)
        dynstr += needed.encode() + b"\0"
    func_offs = []
    for fn in funcs:
        func_offs.append(len(dynstr))
        dynstr += fn.encode() + b"\0"

    dynsym = bytes(24)                        # sym0 NULL
    for off in func_offs:
        # Elf64_Sym: st_name, st_info=GLOBAL|FUNC, st_other, st_shndx=UNDEF
        dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0)

    # SysV hash con todos los simbolos alcanzables:
    # bucket[i]=i+1, chain[j]=j+1, chain[nsyms-1]=0
    nbucket = max(nfunc, 1)
    syhash = struct.pack("<II", nbucket, nsyms)
    for i in range(nbucket):
        syhash += struct.pack("<I", i + 1)
    for j in range(nsyms):
        syhash += struct.pack("<I", 0 if j == 0 or j == nsyms - 1 else j + 1)

    # PLT: stub0 (resolver) + un stub de 16B por funcion
    plt_off = rela_off + 24 * nfunc
    plt = bytearray()
    plt_entries_off = []
    got_off = plt_off + 16 + 16 * nfunc
    # plt0: pushq GOT[1]; jmpq *GOT[2]; nop pad
    plt += bytes([0xff, 0x35]) + struct.pack("<i", (base + got_off + 8) - (base + plt_off + 6))
    plt += bytes([0xff, 0x25]) + struct.pack("<i", (base + got_off + 16) - (base + plt_off + 12))
    plt += b"\x90" * 4
    rela = b""
    got = b""
    for i in range(nfunc):
        entry_off = plt_off + 16 + 16 * i
        slot = base + got_off + 8 * (3 + i)
        # stub: jmpq *slot(%rip); pushq $i (indice de reloc); jmp plt0
        plt += bytes([0xff, 0x25]) + struct.pack("<i", slot - (base + entry_off + 6))
        plt += bytes([0x68]) + struct.pack("<I", i)
        # e9 en entry_off+11: el rel32 es relativo a la SIGUIENTE instruccion
        # (entry_off+16), no al propio e9 — con +11 el destino cae 5 bytes
        # dentro de plt0 y se decodifica como bucle jmp [GOT3]->push->e9->
        # plt0+5->... que hunde el stack hasta hacer SEGV en push (bug
        # encontrado analizando el core: rip=0x4001d6, rsp al fondo del VMA).
        plt += bytes([0xe9]) + struct.pack("<i", (base + plt_off) - (base + entry_off + 16))
        rela += struct.pack("<QQq", slot, ((i + 1) << 32) | 7, 0)   # R_X86_64_JUMP_SLOT
        # GOT: [_DYNAMIC, link_map, resolver] + slots apuntando al push
        got += struct.pack("<Q", base + plt_off + 16 + 16 * i + 6)

    dyn_off = got_off + 8 * (3 + nfunc)
    got_prefix = struct.pack("<QQQ", base + dyn_off, 0, 0)   # _DYNAMIC, 0, 0
    entries = []
    if needed:
        entries.append(struct.pack("<qq", 1, needed_off))   # DT_NEEDED
    entries += [
        struct.pack("<qq", 5, base + dynstr_off),   # DT_STRTAB
        struct.pack("<qq", 10, len(dynstr)),        # DT_STRSZ
        struct.pack("<qq", 6, base + dynsym_off),   # DT_SYMTAB
        struct.pack("<qq", 4, base + syhash_off),   # DT_HASH
    ]
    if nfunc:
        entries += [
            struct.pack("<qq", 3, base + got_off),          # DT_PLTGOT
            struct.pack("<qq", 2, 24 * nfunc),              # DT_PLTRELSZ
            struct.pack("<qq", 20, 7),                      # DT_PLTREL=DT_RELA
            struct.pack("<qq", 23, base + rela_off),        # DT_JMPREL
            struct.pack("<qq", 7, base + rela_off),         # DT_RELA
            struct.pack("<qq", 8, 24 * nfunc),              # DT_RELASZ
            struct.pack("<qq", 9, 24),                      # DT_RELAENT
        ]
    entries.append(struct.pack("<qq", 0, 0))                # DT_NULL
    dyn = b"".join(entries)
    total = 0x300 + len(payload)

    if nfunc == 1:
        # el payload hardcodea la vaddr del stub de execve
        assert base + plt_off + 16 == PLT_EXECVE, "PLT_EXECVE desalineado"

    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,  # ELF
        0x02, 0x01, 0x01, 0x00,  # 64-bit, LE, version 1, SysV ABI
        0x00, 0x00, 0x00, 0x00,  # EI_PAD: el loader glibc rechaza
        0x00, 0x00, 0x00, 0x00,  # e_ident con padding != 0
    ])
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, 2, 62, 1,
        base + 0x300,     # e_entry
        0x40,             # e_phoff
        0, 0, 64, 56, 3, 0, 0, 0)

    def phdr(ptype, pflags, poff, pvaddr, psize, palign):
        return struct.pack("<IIQQQQQQ", ptype, pflags,
                           poff, pvaddr, pvaddr, psize, psize, palign)

    phdrs = b"".join([
        phdr(1, 7, 0, base, total, 0x1000),                          # PT_LOAD
        phdr(3, 4, interp_off, base + interp_off, len(interp_b), 1),  # INTERP
        phdr(2, 6, dyn_off, base + dyn_off, len(dyn), 8),            # DYNAMIC
    ])

    blob = bytearray(total)
    blob[0:len(ehdr)] = ehdr
    blob[0x40:0x40 + len(phdrs)] = phdrs
    blob[interp_off:interp_off + len(interp_b)] = interp_b
    blob[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    blob[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    blob[syhash_off:syhash_off + len(syhash)] = syhash
    if nfunc:
        blob[rela_off:rela_off + len(rela)] = rela
        blob[plt_off:plt_off + len(plt)] = plt
        blob[got_off:got_off + len(got_prefix)] = got_prefix
        blob[got_off + 24:got_off + 24 + len(got)] = got
    blob[dyn_off:dyn_off + len(dyn)] = dyn
    blob[0x300:0x300 + len(payload)] = payload

    with open(path, "wb") as fh:
        fh.write(blob)
    os.chmod(path, 0o755)
    return path


def build(path, soname):
    # ELF load base
    base = 0x400000

    ehdr_off = 0x00
    phdr_off = 0x40
    interp_off = 0x100
    dynstr_off = 0x140
    dyn_off = 0x200
    dynsym_off = 0x240
    syhash_off = 0x280
    code_off = 0x300

    interp = b"/lib64/ld-linux-x86-64.so.2\0"

    dynstr = b"\0" + soname.encode() + b"\0"
    strtab_vaddr = base + dynstr_off
    strlen = len(dynstr)

    # 8 qwords: DT_NEEDED[1](idx 1), DT_STRTAB[5], DT_STRSZ[10],
    #           DT_SYMTAB[6], DT_HASH[4], DT_NULL[0]
    # (DT_SYMTAB + hash SysV de un solo simbolo: sin ellos, el loader glibc
    #  casca (segfault) al resolver los simbolos indefinidos de la lib
    #  cargada contra el scope del main.)
    dyn = b"".join([
        struct.pack("<qq", 1, 1),
        struct.pack("<qq", 5, strtab_vaddr),
        struct.pack("<qq", 10, strlen),
        struct.pack("<qq", 6, base + dynsym_off),
        struct.pack("<qq", 4, base + syhash_off),
        struct.pack("<qq", 0, 0),
    ])

    # .dynsym: una unica entrada NULL (24 bytes de ceros)
    dynsym = bytes(24)

    # SysV hash: {nbucket=1, nchain=1, bucket[0]={0}, chain[0]={0}}
    syhash = struct.pack("<IIII", 1, 1, 0, 0)

    # mov $60,%eax; xor %edi,%edi; syscall   -> exit(0)
    code = bytes([0xb8, 0x3c, 0x00, 0x00, 0x00,
                  0x31, 0xff,
                  0x0f, 0x05])

    total = code_off + len(code)

    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,  # ELF
        0x02, 0x01, 0x01, 0x00,  # 64-bit, LE, version 1, SysV ABI
        0x00, 0x00, 0x00, 0x00,  # EI_PAD: el loader glibc rechaza
        0x00, 0x00, 0x00, 0x00,  # e_ident con padding != 0
    ])

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,        # e_ident
        2,              # e_type: ET_EXEC
        62,             # e_machine: x86-64
        1,              # e_version
        base + code_off,  # e_entry
        phdr_off,       # e_phoff
        0,              # e_shoff (no sections)
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        3,              # e_phnum
        0, 0, 0)        # e_shentsize, e_shnum, e_shstrndx

    def phdr(ptype, pflags, poff, pvaddr, psize, palign):
        return struct.pack(
            "<IIQQQQQQ",
            ptype, pflags,
            poff, pvaddr, pvaddr,
            psize, psize,
            palign)

    phdrs = b"".join([
        phdr(1, 7, 0, base, total, 0x1000),                  # PT_LOAD RWX
        phdr(3, 4, interp_off, base + interp_off, len(interp), 1),  # PT_INTERP
        phdr(2, 6, dyn_off, base + dyn_off, len(dyn), 8),    # PT_DYNAMIC
    ])

    blob = bytearray(total)
    blob[ehdr_off:ehdr_off + len(ehdr)] = ehdr
    blob[phdr_off:phdr_off + len(phdrs)] = phdrs
    p = interp_off
    blob[p:p + len(interp)] = interp
    p = dynstr_off
    blob[p:p + len(dynstr)] = dynstr
    p = dyn_off
    blob[p:p + len(dyn)] = dyn
    p = dynsym_off
    blob[p:p + len(dynsym)] = dynsym
    p = syhash_off
    blob[p:p + len(syhash)] = syhash
    p = code_off
    blob[p:p + len(code)] = code

    with open(path, "wb") as fh:
        fh.write(blob)
    os.chmod(path, 0o755)
    return path


def build_multi(path, sonames):
    """ELF64 ET_EXEC con PT_INTERP y VARIOS DT_NEEDED (en orden).

    El orden de los DT_NEEDED importa: nrld los resuelve en ese orden, y cada
    uno que solo exista en un subdir NO estandar del sysroot consume una
    entrada del array de "dirs extra" de librerias (MAX_EXTRA_DIRS). Con
    MAX_EXTRA_DIRS=2 y 3 subdirs distintos, el tercero no cabe -> el guard
    debe avisar ("g_extra_libdirs lleno") y reportar la lib como faltante.

    Layout propio (calculado) para no tocar el de build() (probes historicos).
    """
    base = 0x400000

    def align8(x):
        return (x + 7) & ~7

    ehdr_off = 0x00
    phdr_off = 0x40
    interp_off = 0x100

    interp = b"/lib64/ld-linux-x86-64.so.2\0"

    # dynstr: "\0" + nombres separados por "\0"; el offset de cada nombre es
    # el valor de su DT_NEEDED.
    dynstr = b"\0"
    needed_offs = []
    for sn in sonames:
        needed_offs.append(len(dynstr))
        dynstr += sn.encode() + b"\0"

    dynsym = bytes(24)                       # sym0 NULL
    syhash = struct.pack("<IIII", 1, 1, 0, 0)

    # El tamano del DYNAMIC no depende de sus valores (todas las entradas son
    # de 16 B), asi que el layout se puede calcular antes de construirlo.
    dyn_size = (len(needed_offs) + 5) * 16

    off = 0x140
    dynstr_off = off; off = align8(off + len(dynstr))
    dyn_off = off;    off = align8(off + dyn_size)
    dynsym_off = off; off = align8(off + len(dynsym))
    syhash_off = off; off = align8(off + len(syhash))
    code_off = off

    # DYNAMIC: N DT_NEEDED (en orden) + STRTAB + STRSZ + SYMTAB + HASH + NULL.
    # Cada entrada es un par (tag, valor) de 8+8 bytes.
    entries = []
    for noff in needed_offs:
        entries.append(struct.pack("<qq", 1, noff))             # DT_NEEDED
    entries += [
        struct.pack("<qq", 5, base + dynstr_off),             # DT_STRTAB
        struct.pack("<qq", 10, len(dynstr)),                  # DT_STRSZ
        struct.pack("<qq", 6, base + dynsym_off),             # DT_SYMTAB
        struct.pack("<qq", 4, base + syhash_off),             # DT_HASH
        struct.pack("<qq", 0, 0),                             # DT_NULL
    ]
    dyn = b"".join(entries)

    # mov $60,%eax; xor %edi,%edi; syscall   -> exit(0)
    code = bytes([0xb8, 0x3c, 0x00, 0x00, 0x00,
                  0x31, 0xff,
                  0x0f, 0x05])

    total = code_off + len(code)

    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,  # ELF
        0x02, 0x01, 0x01, 0x00,  # 64-bit, LE, version 1, SysV ABI
        0x00, 0x00, 0x00, 0x00,  # EI_PAD: el loader glibc rechaza
        0x00, 0x00, 0x00, 0x00,  # e_ident con padding != 0
    ])
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,                 # e_type: ET_EXEC
        62,                # e_machine: x86-64
        1,                 # e_version
        base + code_off,   # e_entry
        phdr_off,          # e_phoff
        0, 0,              # e_shoff, e_flags
        64,                # e_ehsize
        56,                # e_phentsize
        3,                 # e_phnum
        0, 0, 0)           # e_shentsize, e_shnum, e_shstrndx

    def phdr(ptype, pflags, poff, pvaddr, psize, palign):
        return struct.pack("<IIQQQQQQ", ptype, pflags,
                           poff, pvaddr, pvaddr, psize, psize, palign)

    phdrs = b"".join([
        phdr(1, 7, 0, base, total, 0x1000),                       # PT_LOAD RWX
        phdr(3, 4, interp_off, base + interp_off, len(interp), 1),  # PT_INTERP
        phdr(2, 6, dyn_off, base + dyn_off, len(dyn), 8),         # PT_DYNAMIC
    ])

    blob = bytearray(total)
    blob[ehdr_off:ehdr_off + len(ehdr)] = ehdr
    blob[phdr_off:phdr_off + len(phdrs)] = phdrs
    p = interp_off
    blob[p:p + len(interp)] = interp
    p = dynstr_off
    blob[p:p + len(dynstr)] = dynstr
    p = dyn_off
    blob[p:p + len(dyn)] = dyn
    p = dynsym_off
    blob[p:p + len(dynsym)] = dynsym
    p = syhash_off
    blob[p:p + len(syhash)] = syhash
    p = code_off
    blob[p:p + len(code)] = code

    with open(path, "wb") as fh:
        fh.write(blob)
    os.chmod(path, 0o755)
    return path


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    build("%s/need_vdpau" % outdir, "libvdpau_trace.so.1")
    build("%s/need_missing" % outdir, "libnrld-missing-probe.so.1")
    # need_multi: 3 libs que solo existen en subdirs NO estandar del sysroot
    # (vdpau/, gvfs/, cairo/) -> 3 dirs extra distintos. Con el limite real
    # (MAX_EXTRA_DIRS=64) los 3 se registran y la app corre; con el limite a 2
    # (build nrld-lim2) el tercero no cabe -> el guard debe avisar.
    # Los 3 nombres son UNICOS en el sysroot (el extralibfinder encuentra
    # siempre el subdir previsto) y las libs cargan limpias (sin simbolos
    # indefinidos: son modulos autonomos, no plugins de otra app).
    build_multi("%s/need_multi" % outdir, [
        "libc.so.6",
        "libvdpau_trace.so.1",   # sysroot/usr/lib/vdpau
        "libgvfscommon.so",      # sysroot/usr/lib/gvfs
        "libcairo-fdr.so",       # sysroot/usr/lib/cairo
    ])
    glinterp = "/lib64/ld-linux-x86-64.so.2"
    build_simple("%s/exec_scrub" % outdir, glinterp, payload_exec_scrub(),
                 needed="libc.so.6", funcs=["execve"])
    build_simple("%s/exec_keep" % outdir, glinterp, payload_exec_keep(),
                 needed="libc.so.6", funcs=["execve"])
    build_simple("%s/env_dump" % outdir, glinterp, payload_env_dump(),
                 needed="libc.so.6")
    print("probes generados en %s" % outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())