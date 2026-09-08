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

No section headers, one RWX PT_LOAD, three program headers (LOAD, INTERP,
DYNAMIC). Written with struct only.
"""
import os
import struct
import sys


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


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    build("%s/need_vdpau" % outdir, "libvdpau_trace.so.1")
    build("%s/need_missing" % outdir, "libnrld-missing-probe.so.1")
    print("probes generados en %s" % outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())