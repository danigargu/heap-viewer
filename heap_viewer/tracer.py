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
    def __init__(self, form, resume=True):
        DBG_Hooks.__init__(self)
        self.ptr_size        = None
        self.get_ptr         = None
        self.get_arg         = None
        self.regs            = None
        self.callers         = {}
        self.hooked_funcs    = {}
        self.form            = form
        self.resume          = resume
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

        self.hook_malloc_funcs()

    def hook_malloc_funcs(self):
        funcs = [
            'malloc',
            'free',
            'calloc',
            'realloc'
        ]        
        for name in funcs:
            addr = LocByName("__libc_%s" % name)
            if addr == BADADDR:
                warning("Unable to resolve '%s' address" % k)
                continue
            self.hooked_funcs[addr] = name

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
        func_name = self.hooked_funcs.get(bptea)
        if func_name is None:
            return 0

        args = None
        ret_addr = self.get_return_address()

        if func_name == 'malloc':
            req_size = self.get_arg(0)
            args = req_size

        elif func_name == 'calloc':
            req_nmemb = self.get_arg(0)
            req_size = self.get_arg(1)
            args = (req_nmemb, req_size)

        elif func_name == 'realloc':
            target_addr = self.get_arg(0)
            req_size = self.get_arg(1)
            args = (target_addr, req_size)

        elif func_name == 'free':
            free_chunk = self.get_arg(0)
            args = free_chunk

        self.callers[ret_addr] = {
            'func': func_name,
            'args': args
        }
            
        request_step_until_ret()
        run_requests()

        if self.resume:
            request_continue_process()
            run_requests()

        return 0

    def remove_bps(self):
        map(del_bpt, self.hooked_funcs.keys())

    def dbg_step_until_ret(self):
        rip = GetRegValue(self.regs['IP'])
        caller_info = self.callers.get(rip)

        if caller_info is None:
            return 0

        caller = PrevHead(rip)
        func_name = caller_info['func']
        thread_id = get_current_thread()

        if func_name == 'malloc':
            addr = GetRegValue(self.regs['AX'])
            req_size = caller_info['args']
            self.form.append_traced_chunk(addr, func_name, 
                req_size, None, thread_id, caller)

        elif func_name == 'calloc':
            addr = GetRegValue(self.regs['AX'])
            req_nmemb, req_size = caller_info['args']
            self.form.append_traced_chunk(addr, func_name, 
                req_nmemb, req_size, thread_id, caller)

        elif func_name == 'realloc':
            addr = GetRegValue(self.regs['AX'])
            tgt_addr, req_size = caller_info['args']
            self.form.append_traced_chunk(addr, func_name, 
                tgt_addr, req_size, thread_id, caller)

        elif func_name == 'free':
            free_chunk = caller_info['args']
            self.form.append_traced_chunk(free_chunk, func_name, 
                None, None, thread_id, caller)
 
        return 0

# -----------------------------------------------------------------------


