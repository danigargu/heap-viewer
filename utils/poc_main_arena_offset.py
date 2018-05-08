#!/usr/bin/python
# coding: utf-8
#
# PoC for extract libc's main_arena offset using python
# by @danigargu
#

import os
import re
from ctypes import *

def get_libc_address():
    address = None
    maps_file = open('/proc/%d/maps' % os.getpid())
    for line in maps_file.readlines():
        m = re.findall("libc-.+\.so", line)
        if not m:
            continue
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+)', line)
        if m:
            address = int(m.groups()[0], 16)
            break
    return address

def main():
    libc = cdll.LoadLibrary(None)
    libc.malloc.restype = POINTER(c_size_t)

    p1 = libc.malloc(2048)
    p2 = libc.malloc(2048)

    libc.free(p1)
    main_arena = p1[1]-96

    libc_start = get_libc_address()
    main_arena_offset = main_arena-libc_start

    print("[*] Main arena: 0x%x" % main_arena)
    print("[*] Main arena offset: 0x%x" % main_arena_offset)

if __name__ == '__main__':
    main()


