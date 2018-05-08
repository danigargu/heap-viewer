#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

from idc import *
from idaapi import *
from idautils import *
from ctypes import *
from misc import *

# -----------------------------------------------------------------------
class HeapTracer(DBG_Hooks):
    def __init__(self, form):
        DBG_Hooks.__init__(self)
        self.malloc_addr    = None
        self.free_addr      = None
        self.ptr_size       = None
        self.get_ptr        = None
        self.get_arg        = None
        self.regs           = None
        self.malloc_callers = {}
        self.free_callers   = {}
        self.form           = form        
        self.initialize()

    def initialize(self):
        self.ptr_size = get_arch_ptrsize()

        if self.ptr_size == 4:
            self.regs = {'IP': 'EIP', 'SP': 'ESP', 'AX': 'EAX'}
            self.get_arg = self.arg_from_stack
            self.get_ptr = Dword
            
        elif self.ptr_size == 8:
            self.regs = {'IP': 'RIP', 'SP': 'RSP', 'AX': 'RAX'}
            self.get_arg = self.arg_from_reg
            self.get_ptr = Qword
        else:
            raise Exception("Invalid arch")

        self.malloc_addr = LocByName("__libc_malloc")
        self.free_addr   = LocByName("__libc_free")

        if self.malloc_addr == BADADDR or self.free_addr == BADADDR:
            raise Exception("Unable to resolve malloc/free address")

        for addr in [self.malloc_addr, self.free_addr]:
            add_bpt(addr, 0, BPT_DEFAULT)
            set_bpt_attr(addr, BPTATTR_FLAGS, BPT_UPDMEM | BPT_ENABLED)

    def get_return_address(self):
        RefreshDebuggerMemory()
        esp = GetRegValue(self.regs['SP'])
        return self.get_ptr(esp)

    def arg_from_stack(self, n_arg):
        sp = GetRegValue(self.regs['SP']) + self.ptr_size
        return self.get_ptr(sp + (n_arg * self.ptr_size))

    def arg_from_reg(self, n_arg):
        regs = ['RDI', 'RSI', 'RDX', 'RCX', 'R10', 'R8', 'R9']
        return GetRegValue(regs[n_arg])

    def dbg_bpt(self, tid, bptea):
        if bptea == self.malloc_addr:
            ret_addr = self.get_return_address()
            req_size = self.get_arg(0)
            self.malloc_callers[ret_addr] = req_size
            request_step_until_ret()
            run_requests()

        if bptea == self.free_addr:
            ret_addr = self.get_return_address()
            free_chunk = self.get_arg(0)
            self.free_callers[ret_addr] = free_chunk
            request_step_until_ret()
            run_requests()
        return 0

    def remove_bps(self):
        del_bpt(self.malloc_addr)
        del_bpt(self.free_addr)

    def continue_process(self):
        request_continue_process()
        run_requests()

    def dbg_step_until_ret(self):
        rip = GetRegValue(self.regs['IP'])

        if self.malloc_callers.get(rip):
            addr = GetRegValue(self.regs['AX'])
            req_size = self.malloc_callers[rip]
            self.form.append_traced_chunk(addr, "malloc", req_size, PrevHead(rip))

        elif self.free_callers.get(rip):
            free_chunk = self.free_callers[rip]
            self.form.append_traced_chunk(free_chunk, "free",  None, PrevHead(rip))
 
        return 0

# -----------------------------------------------------------------------


