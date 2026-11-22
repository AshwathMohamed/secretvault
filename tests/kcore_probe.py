#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""kcore_probe.py - read one page of kernel memory through /proc/kcore and count how many
8-byte words of my secret pattern are in it.

usage: sudo ./kcore_probe.py 0xffff88800abc1000

It prints one line:  status=<STATUS> pattern_words=<N> nonzero_bytes=<M> [errno=<E>]
Every status has its own exit code, so a test can't mix them up:
  FULL_READ          exit 0  got all 4096 bytes (a zero-filled page also counts)
  PARTIAL_READ       exit 2  got fewer than 4096 bytes -> inconclusive
  UNREADABLE         exit 3  the kernel refused the read (errno tells why)
  SEGMENT_NOT_FOUND  exit 4  the address is not in any /proc/kcore segment -> inconclusive
  ERROR              exit 5  could not open or parse /proc/kcore, or bad arguments
pattern_words: 512 = whole page is the secret pattern, 0 = none of it.
Needs CONFIG_PROC_KCORE=y and root.
"""
import os
import struct
import sys

PAGE = 4096                                         # size of one page in bytes
PATTERN = (0xC0FFEE5EC2E7BEEF).to_bytes(8, "little")   # the 8 bytes my module fills the page with
# exit code for every status
EXIT = {"FULL_READ": 0, "PARTIAL_READ": 2, "UNREADABLE": 3, "SEGMENT_NOT_FOUND": 4, "ERROR": 5}


def report(status, data=b"", err=None):
    """print the result line and exit with the code of that status"""
    words = sum(1 for i in range(0, len(data) - 7, 8) if data[i:i + 8] == PATTERN)   # how many words are my pattern
    nonzero = sum(1 for b in data if b)                                               # how many bytes are not zero
    extra = f" errno={err}" if err is not None else ""
    print(f"status={status} pattern_words={words} nonzero_bytes={nonzero}{extra}")
    sys.exit(EXIT[status])


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        report("ERROR")
    try:
        va = int(sys.argv[1], 16) & ~(PAGE - 1)   # va = the address to read, rounded down to the start of its page
        # KCORE_PATH is only for my self-test with a fake file, normally it is /proc/kcore
        fd = os.open(os.environ.get("KCORE_PATH", "/proc/kcore"), os.O_RDONLY)   # fd = file descriptor of kcore
    except (ValueError, OSError) as e:
        print(f"error: {e}")
        report("ERROR")

    try:
        eh = os.pread(fd, 64, 0)   # eh = the ELF header (first 64 bytes of the file)
        if len(eh) < 64 or eh[:4] != b"\x7fELF":
            report("ERROR")
        e_phoff, = struct.unpack_from("<Q", eh, 32)                  # where the program header table starts
        e_phentsize, e_phnum = struct.unpack_from("<HH", eh, 54)     # size of one entry, number of entries

        # kcore is an ELF file where every segment is a range of kernel memory. find the one with my address
        for i in range(e_phnum):
            ph = os.pread(fd, e_phentsize, e_phoff + i * e_phentsize)   # ph = one program header entry
            # Elf64_Phdr: p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
            # p_offset = where the data is in the file, p_vaddr = kernel address where the segment starts,
            # p_filesz = how many bytes of it are really in the file (this is the one to use, not p_memsz)
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz = struct.unpack_from("<IIQQQQQ", ph, 0)
            if p_type != 1 or not (p_vaddr <= va < p_vaddr + p_filesz):   # type 1 = loadable segment
                continue
            try:
                data = os.pread(fd, PAGE, p_offset + (va - p_vaddr))   # data = the page I wanted to read
            except OSError as e:
                report("UNREADABLE", err=e.errno)
            report("FULL_READ" if len(data) == PAGE else "PARTIAL_READ", data)
        report("SEGMENT_NOT_FOUND")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
