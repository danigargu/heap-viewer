#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi
from misc import *

# --------------------------------------------------------------------------
# TODO: refactor this

class BinGraph(idaapi.GraphViewer):
    def __init__(self, heap, info, close_open=True):   
        self.heap       = heap
        self.info       = info
        self.bin_type   = info['type']
        self.SetCurrentRendererType(idaapi.TCCRT_GRAPH)
        GraphViewer.__init__(self, self.title, close_open)

    @property
    def graph_func(self):
        return {
            'fastbin': self.make_fastbin_graph,
            'unsortedbin': self.make_bin_graph,
            'smallbin': self.make_bin_graph,
            'largebin': self.make_bin_graph,
            'tcache': self.make_tcache_graph
        }[self.bin_type]

    @property
    def title(self):
        if self.bin_type == 'fastbin':
            return "Fastbin[%d]" % self.info['fastbin_id']
        elif self.bin_type == 'unsortedbin':
            return "Unsortedbin"
        elif self.bin_type == 'smallbin':
            return "Smallbin[0x%x]" % self.info['size']
        elif self.bin_type == 'largebin':
            return "Largebin[0x%x]" % self.info['size']
        elif self.bin_type == 'tcache':
            return "Tcache[%d] - 0x%x" % (self.info['bin_id'], self.info['size'])

    def warning_line(self, txt):
        return idaapi.COLSTR(txt, idaapi.SCOLOR_ERROR)


    def chunk_info(self, chunk_addr, chunk):
        line1 = idaapi.COLSTR("Chunk ", idaapi.SCOLOR_NUMBER)
        line2 = idaapi.COLSTR("0x%x\n\n" % (chunk_addr), idaapi.SCOLOR_INSN)
        line3 = idaapi.COLSTR("size: 0x%x\nfd: 0x%x - %s" % 
                (chunk.size, chunk.fd, SegName(chunk.fd), ), SCOLOR_DEFAULT)
        return line1 + line2 + line3


    def tcache_info(self, entry_addr, chunk_addr):        
        line1 = idaapi.COLSTR("entry: ", idaapi.SCOLOR_NUMBER)
        line2 = idaapi.COLSTR("0x%x\n" % (entry_addr), idaapi.SCOLOR_INSN)
        line3 = idaapi.COLSTR("chunk: ", idaapi.SCOLOR_NUMBER)
        line4 = idaapi.COLSTR("0x%x" % (chunk_addr), idaapi.SCOLOR_INSN)
        return line1 + line2 + line3 + line4


    def make_fastbin_graph(self):
        fastbin_id = self.info['fastbin_id']
        size = self.info['size']

        fastbin = self.heap.get_fastbin_by_id(fastbin_id)

        if fastbin == 0:
            warning("Empty fastbin entry")
            return False

        line1 = idaapi.COLSTR("FASTBIN - 0x%02X" % size, idaapi.SCOLOR_ERROR)
        id_header = self.AddNode( (True, "fastbin[%x]" % size, "FASTBIN - 0x%02X" % size) )  
        id_chunk = id_header

        chain, c_error = self.heap.chunk_chain(fastbin, stop=0, add_stop=False)

        for i, chunk_addr in enumerate(chain):
            chunk_info = self.heap.get_chunk(chunk_addr)

            prev_chunk = id_chunk
            id_chunk = self.AddNode( (True, str(chunk_info), self.chunk_info(chunk_addr, chunk_info)) )
            self.AddEdge(prev_chunk, id_chunk)

        if c_error: 
            warn = self.warning_line("[...] - List corrupted or infinite cycle detected")
            id_end = self.AddNode( (True, "[...]", warn) )
            self.AddEdge(id_chunk, id_end)            
        else: 
            id_end = self.AddNode( (True, "TAIL - 0", "TAIL") )
            self.AddEdge(id_chunk, id_end)

        return True


    def make_tcache_graph(self):
        entry_id   = self.info['bin_id']
        entry_size = self.info['size']

        tcache_entry = self.heap.get_tcache_entry_by_id(entry_id)

        if not tcache_entry:
            warning("Unable to get tcache entry")
            return False

        line_header = "TCACHE[%d] - 0x%02X\nCounts: %d\n" % (entry_id, entry_size, tcache_entry['counts'])
        id_header = self.AddNode( (True, line_header, line_header) )
        id_chunk = id_header

        chain, c_error = self.heap.tcache_chain(tcache_entry['next'], add_stop=False)

        for i, mem_addr in enumerate(chain):
            chunk_addr = self.heap.mem2chunk(mem_addr)
            chunk_info = self.heap.get_chunk(chunk_addr)

            prev_chunk = id_chunk
            id_chunk = self.AddNode( (True, str(chunk_info), self.tcache_info(mem_addr, chunk_addr)) )
            self.AddEdge(prev_chunk, id_chunk)

        if c_error: 
            warn = self.warning_line("[...] - List corrupted or infinite cycle detected")
            id_end = self.AddNode( (True, "[...]", warn) )
            self.AddEdge(id_chunk, id_end)
            
        else: 
            id_end = self.AddNode( (True, "TAIL - 0", "TAIL") )
            self.AddEdge(id_chunk, id_end)

        return True

    
    def make_bin_graph(self):
        id_node = dict()
        bin_base = self.info['bin_base']
        chunk = self.heap.get_chunk(bin_base)

        line1 = idaapi.COLSTR("%s " % self.bin_type,idaapi.SCOLOR_NUMBER)
        line2 = idaapi.COLSTR("0x%x\n\n" % bin_base, idaapi.SCOLOR_INSN)
        line3 = idaapi.COLSTR("size: 0x%x\nfd: 0x%x - %s\nbk: 0x%x - %s" % 
                (chunk.size, chunk.fd, SegName(chunk.fd), chunk.bk, SegName(chunk.bk)), SCOLOR_DEFAULT)

        line = line1+line2+line3

        id_base = self.AddNode( (True, str(chunk), line )) 
        id_node[bin_base] = id_base

        chunks  = []
        temp_fd = chunk.fd
        base = id_base

        while temp_fd != bin_base:

            chunk = self.heap.get_chunk(temp_fd)

            line1 = idaapi.COLSTR("Chunk ", idaapi.SCOLOR_NUMBER)
            line2 = idaapi.COLSTR("0x%x\n\n" % (temp_fd), idaapi.SCOLOR_INSN)
            line3 = idaapi.COLSTR("size: 0x%x\nfd: 0x%x - %s\nbk: 0x%x - %s" % 
                (chunk.size, chunk.fd, SegName(chunk.fd), chunk.bk, SegName(chunk.bk)), SCOLOR_DEFAULT)

            id_chunk = self.AddNode( (True, str(chunk), line1 + line2 + line3) )
            
            self.AddEdge(id_base, id_chunk)

            temp_fd = chunk.fd
            id_base = id_chunk

        self.AddEdge(id_base, id_node[bin_base])
        return True

    def OnRefresh(self):
        self.Clear()
        return self.graph_func()

    def OnHint(self, node_id):
        return self[node_id][1]

    def OnGetText(self, node_id):
        is_thread, value, label = self[node_id]
        if is_thread:
            #return (label, 0xf5f5f5)
            return (label, 0xf5f5f5)
        return label

    def OnDblClick(self, node_id):
        # TODO
        return True

    def OnCommand(self, cmd_id):
        if cmd_id == self.cmd_refresh:
            self.Refresh()
            refresh_idaview_anyway()

    def Show(self):
        if not GraphViewer.Show(self):
            return False

        self.cmd_refresh = self.AddCommand("Refresh", "Ctrl+R")
        return True


# --------------------------------------------------------------------------



