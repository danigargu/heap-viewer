#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#
# IO_FILE structs
#

from ctypes import *
from misc import *

#-----------------------------------------------------------------------
# struct _IO_FILE 32 bits

class IO_file_32(LittleEndianStructure):
    _pack_ = 4
    _fields_ =  [
        ("_flags", c_uint32),
        ("_IO_read_ptr", c_uint32),
        ("_IO_read_end", c_uint32),
        ("_IO_read_base", c_uint32),
        ("_IO_write_base", c_uint32),
        ("_IO_write_ptr", c_uint32),
        ("_IO_write_end", c_uint32),
        ("_IO_buf_base", c_uint32),
        ("_IO_buf_end", c_uint32),
        ("_IO_save_base", c_uint32),
        ("_IO_backup_base", c_uint32),
        ("_IO_save_end", c_uint32),
        ("_markers", c_uint32),
        ("_chain", c_uint32),
        ("_fileno", c_int32),
        ("_flags2", c_int32),
        ("_old_offset", c_int32), ## revisar
        ("_cur_column", c_ushort),
        ("_vtable_offset", c_char),
        ("_shortbuf", c_char * 1),
        ("_lock", c_uint32),
        ("_offset", c_int64),
        ("_codecvt", c_uint32),
        ("_wide_data", c_uint32),
        ("_freeres_list", c_uint32),
        ("_freeres_buf", c_uint32),
        ("__pad5", c_uint32),
        ("_mode", c_int32),
        ("_unused2", c_char * 40),
        ("vtable", c_uint32)
    ]

#-----------------------------------------------------------------------
# struct _IO_FILE 64 bits

class IO_file_64(LittleEndianStructure):
    _pack_ = 8
    _fields_ =  [
        ("_flags", c_uint32),
        ("_IO_read_ptr", c_uint64),
        ("_IO_read_end", c_uint64),
        ("_IO_read_base", c_uint64),
        ("_IO_write_base", c_uint64),
        ("_IO_write_ptr", c_uint64),
        ("_IO_write_end", c_uint64),
        ("_IO_buf_base", c_uint64),
        ("_IO_buf_end", c_uint64),
        ("_IO_save_base", c_uint64),
        ("_IO_backup_base", c_uint64),
        ("_IO_save_end", c_uint64),
        ("_markers", c_uint64),
        ("_chain", c_uint64),
        ("_fileno", c_int32),
        ("_flags2", c_int32),
        ("_old_offset", c_int64),
        ("_cur_column", c_ushort),
        ("_vtable_offset", c_char),
        ("_shortbuf", c_char * 1),
        ("_lock", c_uint64),
        ("_offset", c_int64),
        ("_codecvt", c_uint64),
        ("_wide_data", c_uint64),
        ("_freeres_list", c_uint64),
        ("_freeres_buf", c_uint64),
        ("__pad5", c_uint64),
        ("_mode", c_int32),
        ("_unused2", c_char * 20),
        ("vtable", c_uint64)
    ]

#-----------------------------------------------------------------------
# struct _IO_jump_t 32 bits

class IO_jump_t_32(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [
        ("__dummy", c_uint32),
        ("__dummy2", c_uint32),
        ("__finish", c_uint32),
        ("__overflow", c_uint32),
        ("__underflow", c_uint32),
        ("__uflow", c_uint32),
        ("__pbackfail", c_uint32),
        ("__xsputn", c_uint32),
        ("__xsgetn", c_uint32),
        ("__seekoff", c_uint32),
        ("__seekpos", c_uint32),
        ("__setbuf", c_uint32),
        ("__sync", c_uint32),
        ("__doallocate", c_uint32),
        ("__read", c_uint32),
        ("__write", c_uint32),
        ("__seek", c_uint32),
        ("__close", c_uint32),
        ("__stat", c_uint32),
        ("__showmanyc", c_uint32),
        ("__imbue", c_uint32),
    ]

#-----------------------------------------------------------------------
# struct _IO_jump_t 64 bits

class IO_jump_t_64(LittleEndianStructure):
    _pack_ = 8
    _fields_ = [
        ("__dummy", c_uint64),
        ("__dummy2", c_uint64),
        ("__finish", c_uint64),
        ("__overflow", c_uint64),
        ("__underflow", c_uint64),
        ("__uflow", c_uint64),
        ("__pbackfail", c_uint64),
        ("__xsputn", c_uint64),
        ("__xsgetn", c_uint64),
        ("__seekoff", c_uint64),
        ("__seekpos", c_uint64),
        ("__setbuf", c_uint64),
        ("__sync", c_uint64),
        ("__doallocate", c_uint64),
        ("__read", c_uint64),
        ("__write", c_uint64),
        ("__seek", c_uint64),
        ("__close", c_uint64),
        ("__stat", c_uint64),
        ("__showmanyc", c_uint64),
        ("__imbue", c_uint64),
    ]

#-----------------------------------------------------------------------
# struct _IO_FILE_plus 32 bits

class IO_file_plus_32(LittleEndianStructure):
    _pack_ = 4
    _fields_ =  [
        ("file", IO_file_32),
        ("vtable", c_uint32)
    ]

#-----------------------------------------------------------------------
# struct _IO_FILE_plus 64 bits

class IO_file_plus_64(LittleEndianStructure):
    _pack_ = 8
    _fields_ =  [
        ("file", IO_file_64),
        ("vtable", c_uint64)
    ]

#-----------------------------------------------------------------------
def parse_io_file_struct(address):
    io_file_s = None
    io_jump_s = None

    ptr_size = get_arch_ptrsize()    
    if ptr_size == 4:
        io_file_s = IO_file_32
        io_jump_s = IO_jump_t_32
    else:
        io_file_s = IO_file_64
        io_jump_s = IO_jump_t_64

    buff_file = get_bytes(address, sizeof(io_file_s))
    assert len(buff_file) == sizeof(io_file_s)
    io_file_data = io_file_s.from_buffer_copy(buff_file)

    buff_io_jump = get_bytes(io_file_data.vtable, sizeof(io_jump_s))
    assert len(buff_io_jump) == sizeof(io_jump_s)
    io_jump_data = io_jump_s.from_buffer_copy(buff_io_jump)

    return {
        'io_file': (address, io_file_data),
        'io_jump_t': (io_file_data.vtable, io_jump_data)
    }

#-----------------------------------------------------------------------

