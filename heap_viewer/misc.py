#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import re
import idaapi
import json

from idc import *
from idaapi import *
from idautils import *
from ctypes import *

from collections import OrderedDict

# --------------------------------------------------------------------------
__plugname__ = 'HeapViewer'

PLUGIN_DIR  = idadir(os.path.join("plugins", "heap_viewer"))
FILES_DIR   = os.path.join(PLUGIN_DIR, "files")
ICONS_DIR   = os.path.join(FILES_DIR, "icons")
CONFIG_PATH = os.path.join(FILES_DIR, "config.json")

# --------------------------------------------------------------------------
class HeapConfig(object):
    def __init__(self, config_file):
        with open(config_file, 'rb') as f:
            self.__dict__ = json.loads(f.read())

    @property
    def offsets(self):
        ptr_size = get_arch_ptrsize()
        if ptr_size == 4:
            return self.libc_offsets.get('32')
        elif ptr_size == 8:
            return self.libc_offsets.get('64')
        return None

    def dump_config(self):
        return json.dumps(self.__dict__, indent=4)

    def write_to_file(self, filename):
        config = self.dump_config()
        with open(filename, 'wb') as f:
            f.write(config)

# --------------------------------------------------------------------------
def log(msg):
    idaapi.msg("[%s] %s\n" % (__plugname__, msg))

# --------------------------------------------------------------------------
def round_up(offset, alignment):
    return (offset + alignment - 1) & -alignment

# --------------------------------------------------------------------------
def get_struct_offsets(struct_type):
    result = OrderedDict() 
    size   = 0
    align  = 1    

    for name, ctype in struct_type._fields_:
        fieldsize = sizeof(ctype)
        fieldalignment = alignment(ctype)
        size  = round_up(size, fieldalignment)        
        align = max(align, fieldalignment) # set new alignment
        result[name] = size
        size += fieldsize

    size = round_up(size, align)
    return result

# --------------------------------------------------------------------------
def offset_of(struct_type, member):
    result = None
    offset  = 0
    for name, ctype in struct_type._fields_:
        if name == member:
            result = offset
            break
        offset += sizeof(ctype)
    return result

# --------------------------------------------------------------------------
def get_libc_version():
    ''' resolve current libc version via appcall '''
    try:
        gnu_get_libc_version = Appcall.proto("gnu_get_libc_version", "char *gnu_get_libc_version();")
        return gnu_get_libc_version()
    except:
        return None

# --------------------------------------------------------------------------
def apply_struct(ea, struct_name):
    sid = get_struc_id(struct_name)
    size = idc.GetStrucSize(sid)
    MakeUnknown(ea, size, idc.DOUNK_DELNAMES)
    doStruct(ea, size, sid)
    return size

# --------------------------------------------------------------------------
def add_malloc_chunk_struct(ptr_size=8):
    sid = get_struc_id('malloc_chunk_64')

    if sid != -1:
        DelStruc(sid)

    sid = AddStruc(-1, 'malloc_chunk_64')
    members = ['prev_size', 'size', 'fd', 'bk', 'fd_nextsize', 'bk_nextsize']

    struct_size = 7*ptr_size

    for i, member in enumerate(members):
        offset = i * ptr_size
        member_name = "%s_%d" % (member,offset)
        AddStrucMember(sid=sid, 
            name=member_name, 
            offset=offset, 
            flag=FF_QWORD|FF_DATA, 
            typeid=-1, 
            nbytes=ptr_size)

    return sid

# --------------------------------------------------------------------------
def get_arch_ptrsize():
    info = idaapi.get_inf_structure() 
    ptr_size = None  
    if info.is_64bit():
        ptr_size = 8
    elif info.is_32bit():
        ptr_size = 4
    else:
        raise Exception("Invalid arch")
    return ptr_size

# --------------------------------------------------------------------------
def get_main_arena_address_x64():
    main_arena = None
    malloc_addr = LocByName("__libc_malloc")
    
    if malloc_addr == BADADDR:
        raise Exception("Unable to resolve malloc address")

    if not GetFunctionName(malloc_addr):    
        MakeFunction(malloc_addr)  

    for head in Heads(malloc_addr):
        if GetMnem(head) == "cmpxchg" and GetOpType(head, 0) == o_mem:
            main_arena = GetOperandValue(head, 0)
            break   
    return main_arena

# --------------------------------------------------------------------------
def get_libc_base():
    libc_filter = lambda x: re.findall("libc_.*\.so", SegName(x))
    for addr in filter(libc_filter, Segments()):
        seg = getseg(addr)
        if seg.perm | SEGPERM_EXEC == seg.perm:
            return addr
    return None

# --------------------------------------------------------------------------
def get_func_name_offset(ea):
    func = idaapi.get_func(ea)
    if func:
        offset = ea - func.startEA
        return "%s+0x%d" % (GetFunctionName(ea), offset)
    return None

# --------------------------------------------------------------------------
def addr_by_name_expr(name):
    m = re.match(r"[\w]+", name)
    if m:
        sym_name = m.group()
        addr = LocByName(sym_name)
        if addr != BADADDR:
            name = name.replace(sym_name, str(addr))
            return int(eval(name))
    return None

# --------------------------------------------------------------------------
def make_html_chain(name, chain, b_error):
    empty_bin = '<span style="color: red; font-weight: bold">Empty</span>'
    res_html = '<style>p{font-family:Consoles;font-size:13px}</style>'
    res_html += '<p><b>%s</b>: ' % name

    if not len(chain):
        res_html += empty_bin
    else:
        for i in range(len(chain)):
            res_html += "0x%x" % chain[i]
            if i != len(chain)-1:
                if i == len(chain)-2:
                    res_html += ' ← '.decode("utf-8")
                else:
                    res_html += ' → '.decode("utf-8")
        res_html += '</p>'
    
    return res_html

# --------------------------------------------------------------------------





