#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

from idc import *
from idautils import *
from idaapi import *

from ctypes import *
from misc import *
from collections import OrderedDict

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

#-----------------------------------------------------------------------
# struct malloc_par

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
        ("max_total_mem",         c_uint32),
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
        ("max_total_mem",         c_uint64),
        ("sbrk_base",             c_uint64),
        ("tcache_bins",           c_uint64),
        ("tcache_max_bytes",      c_uint64),
        ("tcache_count",          c_uint64),
        ("tcache_unsorted_limit", c_uint64)
    ]

#-----------------------------------------------------------------------
# struct malloc_state (Arenas)

class malloc_state(LittleEndianStructure):
    pass

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


#-----------------------------------------------------------------------
# struct malloc_chunk

class malloc_chunk(LittleEndianStructure):
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


#-----------------------------------------------------------------------
# struct heap_info

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

# -----------------------------------------------------------------------
# Tcache structs

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

# -----------------------------------------------------------------------
# ptmalloc2 allocator - Glibc Heap

class Heap(object):
    def __init__(self, config):
        self.config          = config
        self.ptr_size        = None
        self.get_ptr         = None
        self.offsets         = None
        self.malloc_state_s  = None
        self.malloc_chunk_s  = None
        self.chunk_offsets   = None
        self.arena_offsets   = None
        self.tcache_enabled  = False
        self.initialize()

    def initialize(self):
        self.ptr_size = get_arch_ptrsize()
        self.libc_base = get_libc_base()
        self.libc_offsets = self.config.offsets

        # TODO: refactor this
        if self.ptr_size == 4:
            self.get_ptr = Dword
            self.heap_info_s = heap_info_32
            self.malloc_state_s = malloc_state_32
            self.malloc_chunk_s = malloc_chunk_32
            self.tcache_perthread_s = tcache_perthread_32
            
            if self.config.libc_version > "2.25":
                self.tcache_enabled = True
                self.malloc_state_s = malloc_state_32_new

        elif self.ptr_size == 8:
            self.get_ptr = Qword
            self.heap_info_s = heap_info_64
            self.malloc_state_s = malloc_state_64
            self.malloc_chunk_s = malloc_chunk_64            
            self.tcache_perthread_s = tcache_perthread_64
            
            if self.config.libc_version > "2.25":
                self.tcache_enabled = True
                self.malloc_state_s = malloc_state_64_new

        self.chunk_offsets = get_struct_offsets(self.malloc_chunk_s)
        self.arena_offsets = get_struct_offsets(self.malloc_state_s)

    @property
    def malloc_alignment(self):
        # https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=4e61a6be446026c327aa70cef221c9082bf0085d
        if self.config.libc_version > "2.25" and self.ptr_size == 4:
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
    def main_arena_addr(self):
        addr = self.libc_base + self.libc_offsets['main_arena']
        return addr

    @property
    def global_max_fast_addr(self):
        libc_base = self.libc_base
        offset = self.libc_offsets.get('global_max_fast')
        if offset:
            return libc_base + self.offset
        return None

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
        assert is_loaded(address) == True, "Invalid ptr detected"
        sbytes = get_bytes(address, sizeof(struct_type))
        return struct_type.from_buffer_copy(sbytes)

    def get_heap_base(self, address=None):
        if not address:
            segm = get_segm_by_name("[heap]") # same as mp_->sbrk_base
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
            return self.get_struct(tcache_address, self.tcache_perthread_s)
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
        return self.get_struct(address, self.malloc_state_s)

    def get_arena_for_chunk(self, addr):
        pass # TODO

    def get_global_max_fast(self):
        return self.get_ptr(self.global_max_fast_addr)

    def get_chunk(self, address):
        return self.get_struct(address, self.malloc_chunk_s)

    def prev_chunk(self, address):
        chunk = self.get_chunk(address)
        return address+chunk.prev_size

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

            if not is_loaded(next_ptr):
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

        heap_size = SegEnd(heap_base) - heap_base

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
        if chunk.size != next_chunk.prev_size:
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

