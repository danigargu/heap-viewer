#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import traceback

import idc
import idaapi

from ctypes import *
from collections import OrderedDict

from heap_viewer.misc import *
from heap_viewer import config

#-----------------------------------------------------------------------
# Some glibc heap constants

HEAP_MAX_SIZE = 1024 * 1024

PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

SIZE_BITS = (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

NBINS = 128
NSMALLBINS = 64
NFASTBINS = 10
BINMAPSHIFT = 5

BITSPERMAP = (1 << BINMAPSHIFT)
BINMAPSIZE = (NBINS / BITSPERMAP)

FASTCHUNKS_BIT = 1

TCACHE_BINS = 64
TCACHE_MAX_BYTES = 1032
TCACHE_COUNT = 7

DL_PAGESIZE = 4096

#-----------------------------------------------------------------------
# Heap types

heap_types = {
    4: [c_int, c_uint32],
    8: [c_int, c_uint64]
} 

#-----------------------------------------------------------------------
# struct malloc_par

def malloc_par():
    t_int, t_uint = heap_types.get(config.ptr_size)

    fields = [
        ("trim_threshold",   t_uint),
        ("top_pad",          t_uint),
        ("mmap_threshold",   t_uint),
        ("arena_test",       t_uint),
        ("arena_max",        t_uint),
        ("n_mmaps",          t_int),
        ("n_mmaps_max",      t_int),
        ("max_n_mmaps",      t_int),
        ("no_dyn_threshold", t_int),
        ("mmapped_mem",      t_uint),
        ("max_mmapped_mem",  t_uint),
        ("max_total_mem",    t_uint)
    ]
    if config.libc_version >= "2.24":
        fields.pop() # max_total_mem was removed in glibc 2.24

    fields.extend([("sbrk_base", t_uint)])

    if config.libc_version >= "2.26":
        fields.extend([
            ("tcache_bins",           t_uint),
            ("tcache_max_bytes",      t_uint),
            ("tcache_count",          t_uint),
            ("tcache_unsorted_limit", t_uint),
        ])

    class malloc_par_struct(LittleEndianStructure):
        _pack_ = config.ptr_size
        _fields_ = fields

    return malloc_par_struct

"""
class malloc_par(LittleEndianStructure):
    def __str__(self):
        pass

class malloc_par_32(malloc_par):
    _fields_ =  [
        ("trim_threshold",        c_uint32),
        ("top_pad",               c_uint32),
        ("mmap_threshold",        c_uint32),
        ("arena_test",            c_uint32),
        ("arena_max",             c_uint32),
        ("n_mmaps",               c_int),
        ("n_mmaps_max",           c_int),
        ("max_n_mmaps",           c_int),
        ("no_dyn_threshold",      c_int),
        ("mmapped_mem",           c_uint32),
        ("max_mmapped_mem",       c_uint32),
        #("max_total_mem",        c_uint32),
        ("sbrk_base",             c_uint32),
        ("tcache_bins",           c_uint32),
        ("tcache_max_bytes",      c_uint32),
        ("tcache_count",          c_uint32),
        ("tcache_unsorted_limit", c_uint32)
    ]

class malloc_par_64(malloc_par):
    _fields_ =  [
        ("trim_threshold",        c_uint64),
        ("top_pad",               c_uint64),
        ("mmap_threshold",        c_uint64),
        ("arena_test",            c_uint64),
        ("arena_max",             c_uint64),
        ("n_mmaps",               c_int),
        ("n_mmaps_max",           c_int),
        ("max_n_mmaps",           c_int),
        ("no_dyn_threshold",      c_int),
        ("mmapped_mem",           c_uint64),
        ("max_mmapped_mem",       c_uint64),
        #("max_total_mem",         c_uint64),
        ("sbrk_base",             c_uint64),
        ("tcache_bins",           c_uint64),
        ("tcache_max_bytes",      c_uint64),
        ("tcache_count",          c_uint64),
        ("tcache_unsorted_limit", c_uint64)
    ]
"""

#-----------------------------------------------------------------------
# struct malloc_state (Arenas)

def malloc_state():
    t_int, t_uint = heap_types.get(config.ptr_size)

    fields = [
        ("mutex",            t_int),
        ("flags",            t_int),
    ]
    if config.libc_version >= "2.26":
        fields.extend([("have_fastchunks", t_int)])

    fields.extend([
        ("fastbinsY",        t_uint * NFASTBINS),
        ("top",              t_uint),
        ("last_remainder",   t_uint),
        ("bins",             t_uint * (NBINS * 2 - 2)),
        ("binmap",           c_uint * BINMAPSIZE),
        ("next",             t_uint),
        ("next_free",        t_uint),
        ("attached_threads", t_uint),
        ("system_mem",       t_uint),
        ("max_system_mem",   t_uint)
    ])

    class malloc_state_struct(LittleEndianStructure):
        _pack_ = config.ptr_size
        _fields_ = fields

    return malloc_state_struct

"""
class malloc_state_32(malloc_state):
    _fields_ =  [
        ("mutex",            c_int),
        ("flags",            c_int),
        ("fastbinsY",        c_uint32 * NFASTBINS),
        ("top",              c_uint32),
        ("last_remainder",   c_uint32),
        ("bins",             c_uint32 * (NBINS * 2 - 2)),
        ("binmap",           c_uint * BINMAPSIZE),
        ("next",             c_uint32),
        ("next_free",        c_uint32),
        ("attached_threads", c_uint32),
        ("system_mem",       c_uint32),
        ("max_system_mem",   c_uint32)
    ]

class malloc_state_32_new(malloc_state):
    _fields_ =  [
        ("mutex",            c_int),
        ("flags",            c_int),
        ("have_fastchunks",  c_int),
        ("fastbinsY",        c_uint32 * (NFASTBINS + 1)),
        ("top",              c_uint32),
        ("last_remainder",   c_uint32),
        ("bins",             c_uint32 * (NBINS * 2 - 2)),
        ("binmap",           c_uint * BINMAPSIZE),
        ("next",             c_uint32),
        ("next_free",        c_uint32),
        ("attached_threads", c_uint32),
        ("system_mem",       c_uint32),
        ("max_system_mem",   c_uint32)
    ]

class malloc_state_64(malloc_state):
    _pack_ = 8
    _fields_ =  [
        ("mutex",            c_int),
        ("flags",            c_int),
        ("fastbinsY",        c_uint64 * NFASTBINS),
        ("top",              c_uint64),
        ("last_remainder",   c_uint64),
        ("bins",             c_uint64 * (NBINS * 2 - 2)),
        ("binmap",           c_uint * BINMAPSIZE),
        ("next",             c_uint64),
        ("next_free",        c_uint64),
        ("attached_threads", c_uint32),
        ("system_mem",       c_uint64),
        ("max_system_mem",   c_uint64)
    ]

class malloc_state_64_new(malloc_state):
    _fields_ =  [
        ("mutex",            c_int),
        ("flags",            c_int),
        ("have_fastchunks",  c_int),
        ("fastbinsY",        c_uint64 * NFASTBINS),
        ("top",              c_uint64),
        ("last_remainder",   c_uint64),
        ("bins",             c_uint64 * (NBINS * 2 - 2)),
        ("binmap",           c_uint * BINMAPSIZE),
        ("next",             c_uint64),
        ("next_free",        c_uint64),
        ("attached_threads", c_uint64),
        ("system_mem",       c_uint64),
        ("max_system_mem",   c_uint64)
    ]
"""

#-----------------------------------------------------------------------
# struct malloc_chunk

class malloc_chunk_base(LittleEndianStructure):
    def __str__(self):
        return (
            "prev_size: 0x%x\n"
            "size: 0x%x\n" 
            "prev_inuse: %d\n"
            "fd: 0x%x\n"
            "bk: 0x%x\n"
            "fd_nextsize: 0x%x\n"
            "bk_nextsize: 0x%x\n"  % (self.prev_size, self.norm_size, self.prev_inuse, 
                self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)
        )

    def get_flags(self):
        return (self.size & PREV_INUSE,
                self.size & IS_MMAPPED,
                self.size & NON_MAIN_ARENA)

    @property
    def data(self):
        return buffer(self)[:]

    @property
    def norm_size(self):
        return self.size & ~SIZE_BITS

    @property
    def prev_inuse(self):
        return bool(self.size & PREV_INUSE)

    @property
    def is_mmapped(self):
        return bool(self.size & IS_MMAPPED)

    @property
    def non_main_arena(self):
        return bool(self.size & NON_MAIN_ARENA)


def malloc_chunk():
    t_int, t_uint = heap_types.get(config.ptr_size)

    class malloc_chunk_struct(malloc_chunk_base):
        _pack_ = config.ptr_size
        _fields_ = [
            ("prev_size",   t_uint), # Size of previous chunk (if free).
            ("size",        t_uint), # Size in bytes, including overhead.

            ("fd",          t_uint), # double links -- used only if free.
            ("bk",          t_uint),

            # Only used for large blocks: pointer to next larger size.
            ("fd_nextsize", t_uint),  # double links -- used only if free.
            ("bk_nextsize", t_uint)
        ]

    return malloc_chunk_struct


"""
class malloc_chunk_64(malloc_chunk):
    _fields_ =  [
        ("prev_size",   c_uint64), # Size of previous chunk (if free).
        ("size",        c_uint64), # Size in bytes, including overhead.

        ("fd",          c_uint64), # double links -- used only if free.
        ("bk",          c_uint64),

        # Only used for large blocks: pointer to next larger size.
        ("fd_nextsize", c_uint64),  # double links -- used only if free.
        ("bk_nextsize", c_uint64)
    ]

class malloc_chunk_32(malloc_chunk):
    _fields_ =  [
        ("prev_size",   c_uint32), # Size of previous chunk (if free).
        ("size",        c_uint32), # Size in bytes, including overhead.

        ("fd",          c_uint32), # double links -- used only if free.
        ("bk",          c_uint32),

        # Only used for large blocks: pointer to next larger size.
        ("fd_nextsize", c_uint32),  # double links -- used only if free.
        ("bk_nextsize", c_uint32)
    ]
"""

#-----------------------------------------------------------------------
# struct heap_info


def heap_info():
    t_int, t_uint = heap_types.get(config.ptr_size)

    class heap_info_struct(LittleEndianStructure):
        _pack_ = config.ptr_size
        _fields_ = [
            ("ar_ptr",        t_uint), # Arena for this heap.
            ("prev",          t_uint), # Previous heap.
            ("size",          t_uint), # Current size in bytes.
            ("mprotect_size", t_uint), # Size in bytes that has been mprotected
        ]

    return heap_info_struct


"""
class heap_info_32(LittleEndianStructure):
    _fields_ =  [
        ("ar_ptr",        c_uint32), # Arena for this heap.
        ("prev",          c_uint32), # Previous heap.
        ("size",          c_uint32), # Current size in bytes.
        ("mprotect_size", c_uint32), # Size in bytes that has been mprotected
    ]

class heap_info_64(LittleEndianStructure):
    _fields_ =  [
        ("ar_ptr",        c_uint64), # Arena for this heap.
        ("prev",          c_uint64), # Previous heap.
        ("size",          c_uint64), # Current size in bytes.
        ("mprotect_size", c_uint64), # Size in bytes that has been mprotected
    ]
"""

# -----------------------------------------------------------------------
# Tcache structs

def tcache_perthread():
    t_int, t_uint = heap_types.get(config.ptr_size)

    class tcache_perthread_struct(LittleEndianStructure):
        _pack_ = config.ptr_size
        _fields_ = [
            ("counts",  c_ubyte * TCACHE_BINS),
            ("entries", t_uint * TCACHE_BINS),
        ]

    return tcache_perthread_struct

"""
class tcache_perthread_32(LittleEndianStructure): 
    _fields_ =  [
        ("counts",           c_ubyte * TCACHE_BINS),
        ("entries",          c_uint32 * TCACHE_BINS),
    ]

class tcache_perthread_64(LittleEndianStructure):
    _fields_ =  [
        ("counts",           c_ubyte * TCACHE_BINS),
        ("entries",          c_uint64 * TCACHE_BINS),
    ]
"""

# -----------------------------------------------------------------------
# ptmalloc2 allocator - Glibc Heap

class Heap(object):
    def __init__(self):
        self.ptr_size        = None
        self.get_ptr         = None
        self.offsets         = None
        self.malloc_state_s  = None
        self.malloc_chunk_s  = None
        self.chunk_offsets   = None
        self.main_arena_addr = None
        self.arena_offsets   = None
        self.tcache_enabled  = False
        self.initialize()

    def initialize(self):
        self.ptr_size = config.ptr_size
        self.libc_base = config.libc_base
        self.get_ptr = config.get_ptr
        self.main_arena_addr = get_main_arena_addr()

        if self.main_arena_addr is None:
            raise Exception("Unable to resolve main_arena address")

        # structs 
        self.tcache_enabled = self.is_tcache_enabled()
        self.malloc_state_s = malloc_state()
        self.heap_info_s = heap_info()
        self.malloc_chunk_s = malloc_chunk()
        self.tcache_perthread_s = tcache_perthread()
        self.chunk_offsets = get_struct_offsets(self.malloc_chunk_s)
        self.arena_offsets = get_struct_offsets(self.malloc_state_s)

    @property
    def malloc_alignment(self):
        # https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=4e61a6be446026c327aa70cef221c9082bf0085d
        if config.libc_version > "2.25" and self.ptr_size == 4:
            return 16
        return self.ptr_size * 2

    @property
    def malloc_align_mask(self):
        return self.malloc_alignment - 1 

    @property
    def max_fastbin_size(self):
        return 64 * self.ptr_size / 4

    @property
    def max_smallbin_size(self):
        return 512 * self.ptr_size / 4

    @property
    def min_chunk_size(self):
        ''' The smallest possible chunk '''
        return self.ptr_size * 4

    @property
    def global_max_fast_addr(self):
        libc_base = self.libc_base
        offset = self.libc_offsets.get('global_max_fast')
        if offset:
            return libc_base + self.offset
        return None

    @property
    def min_large_size(self):
        smallbin_width = self.malloc_alignment
        smallbin_correction = int(self.malloc_alignment > 2 * self.ptr_size)
        return ((NSMALLBINS - smallbin_correction) * smallbin_width)

    def is_tcache_enabled(self):
        return (config.libc_version > "2.25")

    def in_smallbin_range(self, sz):
        return sz < self.min_large_size

    def aligned_ok(self, m):
        return (m & self.malloc_align_mask) == 0

    def heap_for_ptr(self, ptr):
        return (ptr & ~(HEAP_MAX_SIZE-1))

    def csize2tidx(self, x):
        return ((x) - self.min_chunk_size + self.malloc_alignment - 1) / self.malloc_alignment

    def tidx2size(self, idx):
        return (idx * self.malloc_alignment + self.min_chunk_size)

    def chunk2mem(self, address):
        return address + (self.ptr_size * 2)

    def mem2chunk(self, address):
        return address - (self.ptr_size * 2)

    def chunk_member_offset(self, member):
        return self.chunk_offsets.get(member)

    def arena_member_offset(self, member):
        return self.arena_offsets.get(member)

    def fastbin_index(self, size):
        if self.ptr_size == 8:
            return (size >> 4) - 2
        return (size >> 3) - 2

    def request2size(self, req):
        min_size = (self.min_chunk_size + self.malloc_align_mask) & ~self.malloc_align_mask
        size = req + self.ptr_size + self.malloc_align_mask

        if size < min_size:
            return min_size
        return size & ~self.malloc_align_mask

    def generic_chain(self, address, offset, stop, add_stop=True, limit=100):
        count = 0
        result = [address]
        b_error = False

        if not isLoaded(address):
            return (result, True)

        next_addr = self.get_ptr(address + offset)
        while next_addr != stop and count < limit:

            if result.count(next_addr) >= 2:
                b_error = True
                break

            result.append(next_addr)
            if not isLoaded(next_addr):
                break

            next_addr = self.get_ptr(next_addr + offset)
            count += 1

        if next_addr == stop and add_stop:
            result.append(stop)

        return (result, b_error)

    def chunk_chain(self, address, stop=0, add_stop=True):
        offset = self.chunk_member_offset('fd')
        return self.generic_chain(address, offset, stop, add_stop)

    def tcache_chain(self, address, add_stop=True):
        return self.generic_chain(address, 0, 0, add_stop) # offset 0: next

    def get_struct(self, address, struct_type):
        assert idaapi.is_loaded(address) == True, "Can't access memory at 0x%x" % address
        sbytes = idaapi.get_bytes(address, sizeof(struct_type))
        return struct_type.from_buffer_copy(sbytes)

    def get_heap_base(self, address=None):
        if not address:
            segm = idaapi.get_segm_by_name("[heap]") # same as mp_->sbrk_base
            if segm:
                return segm.startEA
        else:
            heap_addr = self.heap_for_ptr(address)
            heap_addr = heap_addr + sizeof(self.heap_info_s) + sizeof(self.malloc_state_s)
            return round_up(heap_addr, self.malloc_alignment)
        return None

    def get_tcache_address(self, arena=None):
        heap_base = self.get_heap_base(arena)
        if heap_base:
            first_chunk = self.mem2chunk(heap_base + self.malloc_alignment)
            chunk = self.get_chunk(first_chunk)
            if chunk.norm_size == (sizeof(self.tcache_perthread_s) + self.malloc_alignment):
                return self.chunk2mem(first_chunk)
        return None

    def get_tcache_struct(self, arena=None):
        tcache_address = self.get_tcache_address(arena)
        if tcache_address:
            return get_struct(tcache_address, self.tcache_perthread_s)
        return None

    def get_tcache(self, arena=None):    
        tcache = self.get_tcache_struct(arena)
        if not tcache:
            return None

        results = OrderedDict()
        for i, entry in enumerate(tcache.entries):
            size = self.tidx2size(i)
            results[size] = {
                'next': entry,
                'counts': tcache.counts[i]
            }
        return results

    def get_tcache_entry_by_id(self, idx, arena=None):
        tcache = self.get_tcache_struct(arena)
        if not tcache:
            return None

        next_field = tcache.entries[idx]
        counts = tcache.counts[idx]

        return {'next': next_field, 'counts': counts}

    def get_all_fastbins_chunks(self, address=None):
        chunks = []
        fastbins = self.get_fastbins(address)
        for size, fast_chunk in fastbins.iteritems():
            if fast_chunk:
                chain, b_error = self.chunk_chain(fast_chunk)
                chunks.extend(chain)

        return filter(lambda x: x != 0, chunks)

    def get_all_tcache_chunks(self, address=None):
        chunks = []
        tcache = self.get_tcache(address)
        for size, entry in tcache.iteritems():
            if entry['next']:
                chain, b_error = self.tcache_chain(entry['next'])
                chunks.extend(chain)

        # tcache chunks points to user-data, normalize to proper compare
        return [addr - (self.ptr_size * 2) for addr in chunks if addr != 0] 

    def get_arena(self, address=None):
        if not address:
            address = self.main_arena_addr
        return get_struct(address, self.malloc_state_s)

    def get_arena_for_chunk(self, addr):
        pass # TODO

    def get_global_max_fast(self):
        return self.get_ptr(self.global_max_fast_addr)

    def get_chunk(self, address):
        return get_struct(address, self.malloc_chunk_s)

    def prev_chunk(self, address):
        chunk = self.get_chunk(address)
        return address-chunk.prev_size

    def next_chunk(self, address):
        chunk = self.get_chunk(address)
        return self.get_chunk(address + chunk.norm_size)

    def arenas(self):
        results = []
        main_arena_addr = self.main_arena_addr
    
        arena = self.get_arena() # main_arena
        results.append([main_arena_addr, arena])
        next_ptr = arena.next

        while next_ptr not in (main_arena_addr, 0):

            if not idaapi.is_loaded(next_ptr):
                break

            arena = self.get_arena(next_ptr)
            results.append([next_ptr, arena])
            next_ptr = arena.next 

        return results

    def parse_heap(self, address=None):
        results = []
        tcache_chunks = []
        tcache_size   = 0
        arena = self.get_arena(address)
        heap_base = self.get_heap_base(address)
        fastbins  = self.get_all_fastbins_chunks(address)

        if self.tcache_enabled:
            tcache_chunks = self.get_all_tcache_chunks(address)
            tcache_size = sizeof(self.tcache_perthread_s) + self.malloc_alignment

        if not heap_base:
            return results

        heap_size = idc.SegEnd(heap_base) - heap_base

        '''
        For prevent incorrect parsing in glibc > 2.25 (i386)
        where MALLOC_ALIGNMENT != PTR_SIZE*2
        '''
        chunk_addr = self.mem2chunk(heap_base + self.malloc_alignment)
        stop_parse = False
        count = 0
        
        while not stop_parse: # chunk_addr <= arena.top
            chunk = self.get_chunk(chunk_addr)
            real_size = chunk.norm_size

            if real_size == 0 or real_size > heap_size:
                status = 'Corrupt'
                stop_parse = True

            elif chunk_addr == arena.top:
                status = 'arena->top'
                stop_parse = True

            else:
                status = self.get_chunk(chunk_addr + real_size).prev_inuse
                in_freelist = None
                if status:
                    if chunk_addr in fastbins:
                        in_freelist = 'fastbin'
                    elif chunk_addr in tcache_chunks:
                        in_freelist = 'tcache'
                else:
                    in_freelist = 'bins'

                status = 'Used' if not in_freelist else 'Freed (%s)' % in_freelist

            if count == 0 and self.tcache_enabled:
                if real_size == tcache_size:
                    status = 'tcache_perthread'

            results.append({
                'address': chunk_addr, 
                'prev': chunk.prev_inuse, 
                'size': real_size, 
                'status': status,
                'fd': chunk.fd,
                'bk': chunk.bk
            })            
            
            chunk_addr = chunk_addr + real_size
            count += 1

        return results

    def get_fastbin_by_id(self, idx, arena=None):
        arena = self.get_arena(arena)
        return arena.fastbinsY[idx]

    def get_fastbins(self, arena=None):
        arena = self.get_arena(arena)
        result = OrderedDict()

        size = self.ptr_size * 2
        for fastbin in arena.fastbinsY:
            size += self.ptr_size * 2
            result[size] = fastbin
        return result

    def bin_at(self, index, arena=None):
        """
        bin_at(1) returns the unsorted bin
        Bin 1          - Unsorted BiN
        Bin 2 to 63    - Smallbins
        Bin 64 to 126  - Largebins
        """
        index = index - 1
        arena_addr = arena if arena else self.main_arena_addr
        arena = self.get_arena(arena)

        # TODO: main_arena_addr / per-thread

        fd_offset    = self.chunk_member_offset('fd')
        bins_offset  = self.arena_member_offset('bins')

        bins_base    = (arena_addr + bins_offset) - (self.ptr_size * 2) # - fd_offset
        current_base = (bins_base + (index * self.ptr_size * 2))

        fd, bk = arena.bins[index * 2], arena.bins[index * 2 + 1]
        bin_base = current_base

        return bin_base, fd, bk

    def get_unsortedbin(self, arena=None):
        return self.bin_at(1, arena)

    def get_smallbins(self, arena=None):
        smallbins = OrderedDict()
        size = self.min_chunk_size

        for i in range(2, 64):
            base, fd, bk = self.bin_at(i, arena)
            smallbins[i] = {
                'size': size,
                'base': base,
                'fd': fd,
                'bk': bk
            }
            size += self.malloc_alignment

        return smallbins

    def get_largebins(self, arena=None):
        largebins = OrderedDict()
        size = self.ptr_size * 128 # 512 (32 bits) | 1024 (64 bits)

        for i in range(64, 127):
            base, fd, bk = self.bin_at(i, arena)
            largebins[i] = {
                'size': size,
                'base': base,
                'fd': fd,
                'bk': bk
            }
            size += 64

        return largebins

    def unlinkable(self, p):
        chunk = self.get_chunk(p)
        fd_chunk = self.get_chunk(chunk.fd)
        bk_chunk = self.get_chunk(chunk.bk)
        next_chunk = self.next_chunk(p)

        if fd_chunk.bk != p or bk_chunk.fd != p:
            return False
        if chunk.norm_size != next_chunk.prev_size:
            return False
        return True

    def find_fakefast(self, target_addr):
        max_size = (0x80 if self.ptr_size == 8 else 0x40)
        ea = target_addr - max_size - self.ptr_size
        end_ea = target_addr - self.ptr_size

        results = []
        while ea < end_ea:
            fake_size = Dword(ea)
            idx = self.fastbin_index(fake_size & ~SIZE_BITS)

            if 0 <= idx <= 7:
                if (fake_size & 2 == 2) and ((fake_size & 4 == 4) or (fake_size & 4 == 0)):
                    chunk_addr = ea-self.ptr_size
                    align_size = self.tidx2size(idx)
                    bytes_to   = target_addr-ea-self.ptr_size
                    results.append({
                        'fast_id': idx, 
                        'size': align_size, 
                        'address': chunk_addr,
                        'bytes_to': bytes_to
                    })                      
            ea += 1

        return results

    def is_freeable(self, addr, arena=None):
        errors = []
        try:
            av = self.get_arena(arena)
            chunk = self.get_chunk(addr)
            size = chunk.norm_size

            if chunk.is_mmapped:
                # munmap_chunk
                block = addr - chunk.prev_size
                total_size = chunk.prev_size + size

                if ((block | total_size) & (DL_PAGESIZE-1)) != 0:
                    errors.append("mmapped chunk: invalid pointer.")

            else:
                if addr > (2**(self.ptr_size*8)) - size:
                    errors.append("Invalid pointer. addr > -size")

                if addr & self.malloc_align_mask != 0:
                    errors.append("Invalid pointer. misaligned chunk")

                if size < self.min_chunk_size:
                    errors.append("Invalid size. 0x%x < 0x%x" % (size, self.min_chunk_size))

                if not self.aligned_ok(size):
                    errors.append("Invalid size. 0x%x & 0x%x != 0" % (size, self.malloc_align_mask))

                if self.tcache_enabled:
                    tcache = self.get_tcache_struct(arena)
                    tc_idx = self.csize2tidx(size)

                    if tc_idx < TCACHE_BINS and tcache.counts[tc_idx] >= TCACHE_COUNT:
                        counts = tcache.counts[tc_idx]
                        errors.append("tcache.entries[%d] is full (%d free chunks)" % (tc_idx, counts))

                next_addr   = addr + chunk.norm_size
                next_chunk  = self.get_chunk(next_addr)
                next_size   = next_chunk.size
                chunk_inuse = next_chunk.prev_inuse

                # fastbin checks
                if size <= self.ptr_size*16:
                    if next_size <= self.ptr_size*2:
                        errors.append("Invalid next size (fastbin). next_size (0x%x) <= 0x%x" % \
                            (next_size, self.ptr_size*2))

                    if next_size >= av.system_mem:
                        errors.append("Invalid next size (fastbin). next_size (0x%x) <= system_mem(0x%x)" % \
                            (next_size, av.system_mem))

                    fast_id = self.fastbin_index(size)
                    old = self.get_fastbin_by_id(fast_id, arena)

                    if addr == old:
                        errors.append("Double free or corruption. 0x%x == 0x%x (fastbins[%d])" % \
                            (addr, old, fast_id))

                    if old != 0:
                        old_chunk = self.get_chunk(old)
                        old_fast_id = self.fastbin_index(old_chunk.norm_size)

                        if old_fast_id != fast_id:
                            errors.append("Invalid fastbin entry. fastbin_index_top (%d) != %d" % \
                                (old_fast_id, fast_id))

                else:
                    top = av.top
                    if addr == top:
                        errors.append("Double free or corruption (top). 0x%x == top (0x%x)" % (addr, top))

                    top_size = self.get_chunk(top).norm_size
                    if next_addr >= top+top_size:
                        errors.append("Out of top. next_chunk (0x%x) >= top+top->size (0x%x)" \
                            % (next_addr, top+top_size))

                    if chunk_inuse == 0:
                        errors.append("Double free or corruption (!prev_inuse)")

                    if next_size <= self.ptr_size*2:
                        errors.append("Invalid next size. next_size (0x%x) <= 0x%x" % \
                            (next_size, self.ptr_size*2))

                    if next_size >= av.system_mem:
                        errors.append("Invalid next size. next_size (0x%x) <= system_mem (0x%x)" % \
                            (next_size, av.system_mem))

                    # consolidate backward - unlink
                    if chunk.prev_inuse == 0:
                        prev_chunk = self.get_chunk(addr - chunk.prev_size)
                        if chunk.prev_size != prev_chunk.norm_size:
                            errors.append("unlink: prev->size (0x%x) != chunk->prev_size (0x%x)" % \
                                (prev_chunk.norm_size, chunk.prev_size))

                    base, fd, bk = self.get_unsortedbin(arena)
                    fwd = self.get_chunk(fd)

                    if fwd.bk != base:
                        errors.append("Corrupted unsorted chunks. fwd->bk (0x%x) != bck (0x%x)" % \
                            (fwd.bk, base))

        except Exception as e:
            errors.append("Exception during parsing: " + str(e.message))
            warning(traceback.format_exc())

        if len(errors) == 0:
            return (True, errors)

        return (False, errors)


    def merge_info(self, chunk_addr, arena=None):
        try:
            av = self.get_arena(arena)
            chunk = self.get_chunk(chunk_addr)
            prev_size = chunk.prev_size
            size = chunk.norm_size

            next_addr = chunk_addr + chunk.norm_size
            next_chunk = self.get_chunk(next_addr)
            next_size  = next_chunk.norm_size

            if next_chunk.prev_inuse == 0:
                return ("The chunk is freed")

            fastbins = self.get_all_fastbins_chunks(arena)
            if chunk_addr in fastbins:
                return ("The chunk is already in fastbins")

            if self.tcache_enabled:
                tcache_entries = self.get_all_tcache_chunks(arena)
                if chunk_addr in tcache_entries:
                    return ("The chunk is already in tcache")

                tcache = self.get_tcache_struct(arena)
                tc_idx = self.csize2tidx(size)

                if tc_idx < TCACHE_BINS and tcache.counts[tc_idx] < TCACHE_COUNT:
                    return ("The chunk will be part of tcache.entries[%d]" % tc_idx)

            if size <= self.ptr_size * 16:
                fast_id = self.fastbin_index(size)
                return ("The chunk will be part of fastbins[%d]" % fast_id)

            else:
                if next_addr != av.top:
                    next_next = self.get_chunk(next_addr)
                    next_inuse = next_next.prev_inuse

                # prev chunk is freed
                if chunk.prev_inuse == 0:

                    prev_chunk_addr = self.prev_chunk(chunk_addr)
                    if next_addr == av.top:
                        # show unlink info por prev_chunk
                        return ("The chunk will merge into top, top will be: %#x" %  \
                             prev_chunk_addr)

                    # next chunk is freed
                    elif next_inuse == 0:
                        res = []
                        res.append("The chunk and %#x will merge into %#x" % \
                            (next_addr, prev_chunk_addr))

                        unlink_prev = self.unlinkable(self.prev_chunk_addr)
                        unlink_next = self.unlinkable(self.next_addr)
                        res.append("Unlinkable (%#x): %s" % (prev_chunk_addr, str(unlink_prev)))
                        res.append("Unlinkable (%#x): %s" % (next_addr, str(unlink_next)))
                        return res

                    else:
                        res = []
                        res.append("The chunk will merge into prev_chunk (%#x)" % \
                            (prev_chunk_addr))

                        unlinkable = self.unlinkable(prev_chunk_addr)
                        res.append("Unlinkable(%#x): %s" % (prev_chunk_addr, str(unlinkable)))
                        return res

                # prev chunk in use
                else:
                    if next_addr == av.top:
                        return ("The chunk will merge into top. Top will be: %#x" % \
                            chunk_addr)

                    # if next chunk is freed
                    elif next_inuse == 0:
                        res = []
                        res.append("The chunk will merge with next chunk (%#x)" % \
                            next_addr)

                        unlinkable = self.unlinkable(next_addr)
                        res.append("Unlinkable (%#x): %s" % (next_addr, str(unlinkable)))
                        return res

                    else:
                        return ("The chunk will not merge with other (unsortedbin)")

        except Exception as e:
            warning(traceback.format_exc())

        return None

# --------------------------------------------------------------------------
def find_main_arena():
    main_arena = idc.LocByName("main_arena") # from libc6-dbg
    if main_arena != idc.BADADDR:
        return main_arena

    ea = idc.SegStart(idc.LocByName("_IO_2_1_stdin_"))
    end_ea = idc.SegEnd(ea)

    # &main_arena->next
    offsets = {
        4: [1088, 1096], # 32 bits
        8: [2152, 2160]  # 64 bits
    }[config.ptr_size]

    if ea == idc.BADADDR or end_ea == idc.BADADDR:
        return None

    while ea < end_ea:
        ptr = config.get_ptr(ea) # ptr to main_arena
        if idaapi.is_loaded(ptr) and ptr < ea:
            if (ea-ptr) in offsets:
                return ptr
        ea += config.ptr_size
    return None

# --------------------------------------------------------------------------
def find_malloc_par():
    mp_ = idc.LocByName("mp_")
    if mp_ != idc.BADADDR:
        return mp_

    segm = idaapi.get_segm_by_name("[heap]")
    if segm is None:
        return None

    offset = get_struct_offsets(malloc_par()).get('sbrk_base')
    sbrk_base = segm.startEA
    ea = idc.SegStart(LocByName("_IO_2_1_stdin_"))
    end_ea = idc.SegEnd(ea)

    while ea < end_ea:
        ptr = config.get_ptr(ea)
        if idaapi.is_loaded(ptr) and ptr == sbrk_base:
            return (ea-offset)
        ea += config.ptr_size

    return None

# --------------------------------------------------------------------------
def get_main_arena_addr():
    if config.main_arena is not None:
        return config.main_arena
    return find_main_arena()

# --------------------------------------------------------------------------
def get_malloc_par_addr():
    if config.malloc_par is not None:
        return config.malloc_par
    return find_malloc_par()

# --------------------------------------------------------------------------
def parse_malloc_par(address):
    return get_struct(address, malloc_par())

# --------------------------------------------------------------------------
