#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idc
import idaapi

# --------------------------------------------------------------------------
class BinGraph(idaapi.GraphViewer):
    def __init__(self, parent, info, close_open=True):   
        self.cur_arena  = parent.cur_arena
        self.heap       = parent.heap
        self.info       = info
        self.bin_type   = info['type']
        self.SetCurrentRendererType(idaapi.TCCRT_GRAPH)
        idaapi.GraphViewer.__init__(self, self.title, close_open)

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
        line =  idaapi.COLSTR("Chunk ", idaapi.SCOLOR_NUMBER)
        line += idaapi.COLSTR("0x%x\n\n" % (chunk_addr), idaapi.SCOLOR_INSN)
        line += idaapi.COLSTR("size: 0x%x\nfd: 0x%x - %s" % \
                (chunk.size, chunk.fd, idc.get_segm_name(chunk.fd)), SCOLOR_DEFAULT)
        return line

    def tcache_info(self, entry_addr, chunk_addr):        
        line =  idaapi.COLSTR("entry: ", idaapi.SCOLOR_NUMBER)
        line += idaapi.COLSTR("0x%x\n" % (entry_addr), idaapi.SCOLOR_INSN)
        line += idaapi.COLSTR("chunk: ", idaapi.SCOLOR_NUMBER)
        line += idaapi.COLSTR("0x%x" % (chunk_addr), idaapi.SCOLOR_INSN)
        return line

    def bin_info(self, node_title, chunk_addr, chunk, with_size=True):
        line =  idaapi.COLSTR("%s " % node_title, idaapi.SCOLOR_NUMBER)
        line += idaapi.COLSTR("0x%x\n\n" % chunk_addr, idaapi.SCOLOR_INSN)

        chunk_info = ""
        if with_size:
            chunk_info += "size: 0x%x\n" % chunk.size

        chunk_info += "fd: 0x%x - %s\nbk: 0x%x - %s" % (chunk.fd, \
            idc.get_segm_name(chunk.fd), chunk.bk, idc.get_segm_name(chunk.bk))

        line += idaapi.COLSTR(chunk_info, idaapi.SCOLOR_DEFAULT)
        return line

    def add_error_edge(self, id_node):
        warn = self.warning_line("[...] - List corrupted or infinite cycle detected")
        id_end = self.AddNode( (True, "[...]", warn, None) )
        self.AddEdge(id_node, id_end)  

    def add_tail_edge(self, id_node):
        id_end = self.AddNode( (True, "TAIL - 0", "TAIL", None) )
        self.AddEdge(id_node, id_end)


    def make_fastbin_graph(self):
        fastbin_id = self.info['fastbin_id']
        size = self.info['size']

        fastbin = self.heap.get_fastbin_by_id(fastbin_id, self.cur_arena)

        if fastbin == 0:
            warning("Empty fastbin entry")
            return False

        id_header = self.AddNode( (True, "fastbin[%x]" % size, "FASTBIN - 0x%02X" % size, None) )  
        id_chunk = id_header

        chain, c_error = self.heap.chunk_chain(fastbin, stop=0, add_stop=False)

        for i, chunk_addr in enumerate(chain):
            chunk_info = self.heap.get_chunk(chunk_addr)

            prev_chunk = id_chunk
            id_chunk = self.AddNode( (True, str(chunk_info), self.chunk_info(chunk_addr, chunk_info), chunk_addr) )
            self.AddEdge(prev_chunk, id_chunk)

        if c_error: 
            self.add_error_edge(id_chunk)          
        else: 
            self.add_tail_edge(id_chunk)

        return True


    def make_tcache_graph(self):
        entry_id   = self.info['bin_id']
        entry_size = self.info['size']

        tcache_entry = self.heap.get_tcache_entry_by_id(entry_id, self.cur_arena)

        if not tcache_entry:
            warning("Unable to get tcache entry")
            return False

        line_header = "TCACHE[%d] - 0x%02X\nCounts: %d\n" % (entry_id, entry_size, tcache_entry['counts'])
        id_header = self.AddNode( (True, line_header, line_header, None) )
        id_chunk = id_header

        chain, c_error = self.heap.tcache_chain(tcache_entry['next'], add_stop=False)

        for i, mem_addr in enumerate(chain):
            chunk_addr = self.heap.mem2chunk(mem_addr)

            try:
                chunk_info = self.heap.get_chunk(chunk_addr)
                prev_chunk = id_chunk

                tcache_info = self.tcache_info(mem_addr, chunk_addr)
                id_chunk = self.AddNode( (True, str(chunk_info), tcache_info, chunk_addr) )
                self.AddEdge(prev_chunk, id_chunk)

            except:
                c_error = True

        if c_error: 
            self.add_error_edge(id_chunk)           
        else: 
            self.add_tail_edge(id_chunk)

        return True


    def make_bin_graph(self):
        id_node  = dict()
        bin_base = self.info['bin_base']

        id_chunk = None
        prev_chunk = None
        chain, c_error = self.heap.chunk_chain(bin_base, stop=bin_base, add_stop=False)
        
        for i, chunk_addr in enumerate(chain):
            header = self.bin_type if i == 0 else 'Chunk'
            chunk_info = self.heap.get_chunk(chunk_addr)

            node_info = self.bin_info(header, chunk_addr, chunk_info, i!=0)
            id_chunk = self.AddNode( (True, str(chunk_info), node_info, chunk_addr) )
            id_node[chunk_addr] = id_chunk

            if prev_chunk is not None:
                self.AddEdge(prev_chunk, id_chunk)

            prev_chunk = id_chunk

        if c_error: 
            self.add_error_edge(prev_chunk)
        else:
            self.AddEdge(prev_chunk, id_node[bin_base])
            
        return True

    def OnRefresh(self):
        self.Clear()
        return self.graph_func()

    def OnHint(self, node_id):
        return self[node_id][1]

    def OnGetText(self, node_id):
        default_color = idc.DEFCOLOR
        flag, value, label, address = self[node_id]
        if flag:
            return (label, 0xf5f5f5)
        return label

    def OnDblClick(self, node_id):
        address = self[node_id][3]
        if address is not None:
            idc.jumpto(address)
        return True

    def OnCommand(self, cmd_id):
        if cmd_id == self.cmd_refresh:
            self.Refresh()
            idaapi.refresh_idaview_anyway()

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False

        self.cmd_refresh = self.AddCommand("Refresh", "Ctrl+R")
        return True


# --------------------------------------------------------------------------



