#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

from idc import *
from idaapi import *
from idautils import *
from ctypes import *

from heap_viewer.misc import *
from heap_viewer import config

# -----------------------------------------------------------------------
class HeapTracer(DBG_Hooks):
    def __init__(self, callback, resume=True):
        DBG_Hooks.__init__(self)
        self.ptr_size        = None
        self.get_ptr         = None
        self.get_arg         = None
        self.regs            = None
        self.callers         = {}
        self.hooked_funcs    = {}
        self.callback        = callback
        self.resume          = resume
        self.initialize()

    def initialize(self):
        self.ptr_size = config.ptr_size

        if self.ptr_size == 4:
            self.regs = {'IP': 'EIP', 'SP': 'ESP', 'AX': 'EAX'}
            self.get_arg = self.arg_from_stack
            self.get_ptr = get_wide_dword
            
        elif self.ptr_size == 8:
            self.regs = {'IP': 'RIP', 'SP': 'RSP', 'AX': 'RAX'}
            self.get_arg = self.arg_from_reg
            self.get_ptr = get_qword
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
            addr = get_name_ea_simple("__libc_%s" % name)
            if addr == BADADDR:
                warning("Unable to resolve '%s' address" % name)
                continue
            self.hooked_funcs[addr] = name

            add_bpt(addr, 0, BPT_DEFAULT)
            set_bpt_attr(addr, BPTATTR_FLAGS, BPT_UPDMEM | BPT_ENABLED)                
                
    def get_return_address(self):
        refresh_debugger_memory()
        esp = get_reg_value(self.regs['SP'])
        return self.get_ptr(esp)

    def arg_from_stack(self, n_arg):
        sp = get_reg_value(self.regs['SP']) + self.ptr_size
        return self.get_ptr(sp + (n_arg * self.ptr_size))

    def arg_from_reg(self, n_arg):
        regs = ['RDI', 'RSI', 'RDX', 'RCX', 'R10', 'R8', 'R9']
        return get_reg_value(regs[n_arg])

    def dbg_bpt(self, tid, bptea):
        func_name = self.hooked_funcs.get(bptea)
        if func_name is None:
            return 0

        args = None
        ret_addr = self.get_return_address()
        thread_id = get_current_thread()

        if config.filter_library_calls:
            m_info = get_module(ret_addr)
            if m_info and m_info.name != config.program_module.name:
                return 0

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

            caller = prev_head(ret_addr, 0)

            self.callback(free_chunk, func_name, None, 
                None, thread_id, caller, from_ret=False)

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
        rip = get_reg_value(self.regs['IP'])
        caller_info = self.callers.get(rip)

        if caller_info is None:
            return 0

        refresh_debugger_memory()
        caller = prev_head(rip, 0)
        func_name = caller_info['func']
        thread_id = get_current_thread()

        if func_name == 'malloc':
            addr = get_reg_value(self.regs['AX'])
            req_size = caller_info['args']
            self.callback(addr, func_name, req_size, 
                None, thread_id, caller)

        elif func_name == 'calloc':
            addr = get_reg_value(self.regs['AX'])
            req_nmemb, req_size = caller_info['args']
            self.callback(addr, func_name, req_nmemb, 
                req_size, thread_id, caller)

        elif func_name == 'realloc':
            addr = get_reg_value(self.regs['AX'])
            tgt_addr, req_size = caller_info['args']
            self.callback(addr, func_name, tgt_addr, 
                req_size, thread_id, caller)

        elif func_name == 'free':
            free_chunk = caller_info['args']

            self.callback(free_chunk, func_name, None, 
                None, thread_id, caller)

 
        return 0

# -----------------------------------------------------------------------


