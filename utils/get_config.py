#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - get_config.py
# by @danigargu
#

import os
import sys
import re
import json

from ctypes import *
from subprocess import check_output as run


def get_symbols(filename):
    symbols = dict()

    if not os.path.exists(filename):
        return symbols

    output = run('nm %s 2>&1' % (filename), shell=True).split("\n")
    for line in map(lambda x: x.split(" "), output):
        if len(line) != 3:
            continue
        symbols[line[2]] = int(line[0], 16)
    return symbols


def get_hash_debug_file(filename):
    debug_file = None
    dir_dbg = "/usr/lib/debug"
    dir_build_id = "/.build-id"

    if not os.path.exists(filename):
        return None
    
    output = run("objdump -s -j .note.gnu.build-id %s 2>&1" % filename, shell=True)
    m = re.findall(r"([0-9a-f]{8})", output)
    if m:
        build_hash = ''.join(m)[32:]
        debug_file = "%s%s/%s/%s.debug" % (dir_dbg, dir_build_id, build_hash[:2], build_hash[2:])
    return debug_file


def get_libc_version(libc_filename):
    m = re.match("libc-(.+)\.so", libc_filename)
    if m:
        return float(m.groups()[0])
    return None


def gnu_get_libc_version():
    try:
        libc = cdll.LoadLibrary(None)
        libc_version = libc.gnu_get_libc_version
        libc_version.restype = c_char_p
        return libc_version()
    except:
        return None


def find_libc(folder):
    if not os.path.isdir(folder):
        return None

    for filename in os.listdir(folder):
        if re.match("libc-.+\.so", filename):
            return os.path.normpath(folder + "/" + filename)
    return None


def get_libc_dbg_files():
    debug_lib_path = '/usr/lib/debug/lib/'
    archs_folder = {
        '32': 'i386-linux-gnu',
        '64': 'x86_64-linux-gnu'
    }

    libc_files = {}
    if not os.path.isdir(debug_lib_path):
        return None

    for arch, folder in archs_folder.iteritems():
        arch_path = os.path.normpath(debug_lib_path + "/" + folder)
        libc_file = find_libc(arch_path)

        if libc_file and os.path.isfile(libc_file):
            libc_files[arch] = libc_file

    return libc_files


def get_libc_dbg_files_build_id():
    libc_symlinks = {
        '32': '/lib/i386-linux-gnu/libc.so.6',
        '64': '/lib/x86_64-linux-gnu/libc.so.6'
    }
    libc_files = {}
    found = False

    for arch, filename in libc_symlinks.iteritems():
        if not os.path.isfile(filename):
            continue

        libc_path  = os.path.realpath(filename)
        debug_file = get_hash_debug_file(libc_path)

        if debug_file and os.path.isfile(debug_file):
            libc_files[arch] = debug_file
            found = True

    if found:
        return libc_files
    return None


def get_libc_files():
    libc_files = get_libc_dbg_files()
    if not libc_files:
        libc_files = get_libc_dbg_files_build_id()
    return libc_files


def main():  
    libc_files = get_libc_files()
    if not libc_files:
        print("ERROR: unable to locate libc-dbg files")
        return

    for k,v in libc_files.iteritems():
        print("[*] libc %s: %s" % (k,v))
    print("[*] config.json:\n")

    symbol_names = [
        'main_arena', # required
        'mp_', 
        'global_max_fast', 
    ]

    config = {
        'libc_offsets': None,
        'libc_version': gnu_get_libc_version()
    }

    offsets = {}
    for arch, filename in libc_files.iteritems():
        syms = {}
        libc_syms = get_symbols(filename)
        for sym_name in symbol_names:
            syms[sym_name] = libc_syms.get(sym_name)
        offsets[arch] = syms

    config['libc_offsets'] = offsets
    print json.dumps(config, indent=2)


if __name__ == '__main__':
    main()


