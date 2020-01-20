#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import sys
import json
import idc

from heap_viewer import CONFIG_PATH
from heap_viewer.misc import *

ptr_size = None
ptr_mask = None
get_ptr = None
program_module = None
main_arena = None
malloc_par = None
global_max_fast = None
libc_version = None
libc_base = None
stop_during_tracing = None
start_tracing_at_startup = None
detect_double_frees_and_overlaps = None
filter_library_calls = None
hexdump_limit = None
libc_offsets = None

m = sys.modules[__name__]

def load():
    config = None
    m.ptr_size = get_arch_ptrsize()
    m.libc_version = get_libc_version()
    m.libc_base = get_libc_base()

    if m.ptr_size == 4:
        m.get_ptr = idc.get_wide_dword
    elif m.ptr_size == 8:
        m.get_ptr = idc.get_qword

    m.ptr_mask = (1 << 8*m.ptr_size)-1
    m.program_module = get_program_module()

    try:
        with open(CONFIG_PATH, 'rb') as f:
            config = json.loads(f.read())
    except Exception as e:
        # default config
        config = {}

    m.stop_during_tracing = config.get('stop_during_tracing', True)
    m.start_tracing_at_startup = config.get('start_tracing_at_startup', False)
    m.detect_double_frees_and_overlaps = config.get('detect_double_frees_and_overlaps', True)
    m.filter_library_calls = config.get('filter_library_calls', False)
    m.hexdump_limit = config.get('hexdump_limit', 1024)
    m.libc_offsets = config.get('libc_offsets')

    main_arena = None
    malloc_par = None

    if type(m.libc_offsets) is dict:
        main_arena = m.libc_offsets.get("main_arena")
        malloc_par = m.libc_offsets.get("mp_")
        global_max_fast = m.libc_offsets.get("global_max_fast")

    if main_arena is not None:
        main_arena += m.libc_base

    if malloc_par is not None:
        malloc_par += m.libc_base
        
    m.main_arena = main_arena
    m.malloc_par = malloc_par


def dump():
    config = {
        'stop_during_tracing': m.stop_during_tracing,
        'start_tracing_at_startup': m.start_tracing_at_startup,
        'detect_double_frees_and_overlaps': m.detect_double_frees_and_overlaps,
        'filter_library_calls': m.filter_library_calls,
        'hexdump_limit': m.hexdump_limit,
        'libc_offsets': m.libc_offsets
    }
    return json.dumps(config, indent=4)


def save():
    with open(CONFIG_PATH, 'wb') as f:
        config_json = dump().encode("utf-8")
        f.write(config_json)

"""
def update_file(data):
    config = json.loads(data)
    with open(CONFIG_PATH, 'wb') as f:
        f.write(json.dumps(config, indent=4))
"""

