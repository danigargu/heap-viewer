#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idc
import idaapi
import tempfile
import traceback

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from heap_viewer.tracer import HeapTracer
from heap_viewer.widgets.custom import CustomWidget, TTable
from heap_viewer.misc import *
from heap_viewer.ptmalloc import *
from heap_viewer import config
from heap_viewer import villoc

# -----------------------------------------------------------------------
class TracerWidget(CustomWidget):
    def __init__(self, parent=None):
        super(TracerWidget, self).__init__(parent)
        self.tracer = None
        self.free_chunks = {}
        self.allocated_chunks = {}
        self.row_info = {}
        self._create_gui()

    def _create_gui(self):
        self._create_table()
        self._create_menu()     

    def _create_table(self):
        self.tbl_traced_chunks = TTable(['#','User-address', 'Action', 'Arg 1', 'Arg 2', \
            'Thread', 'Caller', 'Info'])
        self.tbl_traced_chunks.setRowCount(0)
        self.tbl_traced_chunks.resize_columns([40, 155, 80, 80, 80, 80, 200, 200])
        self.tbl_traced_chunks.customContextMenuRequested.connect(self.context_menu)
        self.tbl_traced_chunks.itemSelectionChanged.connect(self.view_selected_chunk)
        self.tbl_traced_chunks.cellDoubleClicked.connect(self.traced_double_clicked)

    def _create_menu(self):
        cb_enable_trace = QtWidgets.QCheckBox()
        cb_enable_trace.stateChanged.connect(self.cb_tracing_changed)
        self.cb_stop_during_tracing = QtWidgets.QCheckBox()
        
        btn_dump_trace = QtWidgets.QPushButton("Dump trace")
        btn_dump_trace.clicked.connect(self.btn_dump_trace_on_click)

        btn_villoc_trace = QtWidgets.QPushButton("Villoc")
        btn_villoc_trace.clicked.connect(self.btn_villoc_on_click)

        btn_clear_trace = QtWidgets.QPushButton("Clear")
        btn_clear_trace.clicked.connect(self.btn_clear_on_click)
        
        hbox_enable_trace = QtWidgets.QHBoxLayout()
        hbox_enable_trace.addWidget(QtWidgets.QLabel("Enable tracing"))
        hbox_enable_trace.addWidget(cb_enable_trace)
        hbox_enable_trace.addWidget(QtWidgets.QLabel("Stop during tracing"))
        hbox_enable_trace.addWidget(self.cb_stop_during_tracing)
        hbox_enable_trace.addWidget(btn_dump_trace)
        hbox_enable_trace.addWidget(btn_villoc_trace)
        hbox_enable_trace.addWidget(btn_clear_trace)
        hbox_enable_trace.addStretch(1)

        hbox_trace = QtWidgets.QVBoxLayout()
        hbox_trace.addLayout(hbox_enable_trace)
        hbox_trace.addWidget(QtWidgets.QLabel("Traced chunks"))
        hbox_trace.addWidget(self.tbl_traced_chunks)

        self.cb_stop_during_tracing.setChecked(config.stop_during_tracing)
        cb_enable_trace.setChecked(config.start_tracing_at_startup)

        self.setLayout(hbox_trace)

    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()

        show_warn_info = None
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to chunk")
        jump_to_u = menu.addAction("Jump to user-data")
        goto_caller = menu.addAction("Jump to caller")

        current_row = self.sender().currentRow()
        if current_row in self.row_info:
            show_warn_info = menu.addAction("Show warning info")

        chunk_addr = int(sender.item(sender.currentRow(), 1).text(), 16)
        action = menu.exec_(sender.mapToGlobal(position))
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.jumpto(chunk_addr - (config.ptr_size*2))

        elif action == jump_to_u:
            idc.jumpto(chunk_addr)

        elif action == goto_caller:
            caller_str = str(sender.item(sender.currentRow(), 6).text())
            if caller_str:
                idc.jumpto(str2ea(caller_str))

        elif action == view_chunk:
            self.view_selected_chunk()

        elif show_warn_info and action == show_warn_info:
            self.traced_double_clicked()

    def enable_tracing(self):
        stop_during_tracing = not self.cb_stop_during_tracing.isChecked()
        self.tracer = HeapTracer(self.append_chunk, stop_during_tracing)
        self.tracer.hook()
        self.parent.tracer = self.tracer 
        self.free_chunks = {}
        self.allocated_chunks = {}
        log("Tracer enabled")
    
    def disable_tracing(self):
        if self.tracer:
            self.tracer.remove_bps()
            self.tracer.unhook()
            self.parent.tracer = None
        log("Trace disabled")

    def cb_tracing_changed(self, state):
        if state == QtCore.Qt.Checked:
            self.cb_stop_during_tracing.setEnabled(False)
            self.enable_tracing()
        else:
            self.cb_stop_during_tracing.setEnabled(True)
            self.disable_tracing()

    def get_value(self, row, name):
        cols = {
            'address': 1,
            'action': 2,
            'arg1': 3,
            'arg2': 4,
            'thread': 5,
            'caller': 6,
            'info': 7
        }
        return self.tbl_traced_chunks.item(row, cols[name]).text()

    def dump_table_for_villoc(self):
        result = ''
        for i in range(self.tbl_traced_chunks.rowCount()):
            action = self.get_value(i, "action")
            info = self.get_value(i, "info")

            if info != "N/A":
                result += "@villoc(%s) = <void>\n" % info

            if action == "malloc":
                arg1 = self.get_value(i, "arg1")
                ret = self.get_value(i, "address")
                result += "malloc(%d) = " % int(arg1, 16)
                result += ret if ret.startswith("0x") else '<error>'

            elif action == "free":
                address = self.get_value(i, "address")
                result += "free(%s) = <void>" % address

            elif action == "realloc":
                address = self.get_value(i, "address")
                arg1 = self.get_value(i, "arg1")
                arg2 = self.get_value(i, "arg2")
                result += "realloc(%s, %d) = %s" % (arg1, int(arg2, 16), address)

            elif action == "calloc":
                address = self.get_value(i, "address")
                arg1 = self.get_value(i, "arg1")
                arg2 = self.get_value(i, "arg2")
                result += "calloc(%d, %d) = %s" % (int(arg1, 16), int(arg2, 16), address)

            result += '\n'
        return result

    def btn_villoc_on_click(self):
        if self.tbl_traced_chunks.rowCount() == 0:
            idaapi.warning("Empty table")
            return

        try:
            villoc.Block.header = config.ptr_size*2
            villoc.Block.round  = self.parent.heap.malloc_alignment
            villoc.Block.minsz  = self.parent.heap.min_chunk_size

            result = self.dump_table_for_villoc()
            html = villoc.build_html(result)

            h, filename = tempfile.mkstemp(suffix='.html')

            with open(filename, 'wb') as f:
                f.write(html.encode("utf-8"))

            url = QtCore.QUrl.fromLocalFile(filename)
            QtGui.QDesktopServices.openUrl(url)

        except Exception as e:
            idaapi.warning(traceback.format_exc())

    def btn_dump_trace_on_click(self):
        if self.tbl_traced_chunks.rowCount() == 0:
            idaapi.warning("Empty table")
            return

        filename = AskFile(1, "*.csv", "Select the file to store tracing results")
        if not filename:
            return            
        try:
            result = self.tbl_traced_chunks.dump_table_as_csv()
            with open(filename, 'wb') as f:
                f.write(result)

        except Exception as e:
            idaapi.warning(traceback.format_exc())

    def btn_clear_on_click(self):
        self.tbl_traced_chunks.clear_table()

    def view_selected_chunk(self):
        items = self.tbl_traced_chunks.selectedItems()
        if len(items) > 0:
            chunk_addr = int(items[1].text(), 16)
            norm_address = "0x%x-0x%x" % (chunk_addr, config.ptr_size * 2)
            self.parent.show_chunk_info(norm_address)

    def traced_double_clicked(self):
        current_row = self.sender().currentRow()
        if current_row in self.row_info:
            idaapi.info(self.row_info[current_row])

    def update_allocated_chunks(self):
        for start, info in self.allocated_chunks.items():
            try:
                chunk = self.heap.get_chunk(start)
                if chunk.norm_size != info['size']:
                    info['size'] = chunk.norm_size
                    info['end']  = start+chunk.norm_size
            except:
                continue

    def malloc_consolidate(self):
        fastbins = self.heap.get_all_fastbins_chunks(self.cur_arena)
        if len(fastbins) == 0:
            return False

        self.free_chunks = {}
        for addr in fastbins:
            chunk = self.get_chunk(chunk)
            self.free_chunks[addr] = {
                'size': chunk.norm_size,
                'end': addr+chunk.norm_size
            }
        return True

    def append_chunk(self, addr, action, arg1, arg2, thread_id, caller, from_ret=True):
        warn_msg = None
        row_msg  = None
        row_color = None

        warn_types = {
            'overlap': ['Overlap detected', QtGui.QColor(255,204,0)],
            'double_free': ['Double free detected', QtGui.QColor(255,153,102)]
        }

        if addr == 0:
            return

        if action == "free" and from_ret:
            self.parent.reload_gui_info()
            return

        if config.detect_double_frees_and_overlaps:

            if action == "malloc":
                chunk_addr = self.heap.mem2chunk(addr)
                chunk_size = self.heap.get_chunk(chunk_addr).norm_size
                chunk_end  = chunk_addr+chunk_size

                chunk = {
                    'size': chunk_size,
                    'end':  chunk_end
                }
                overlap = check_overlap(chunk_addr, chunk_size, self.allocated_chunks)
                if overlap is not None:

                    overlap_size = self.allocated_chunks[overlap]['size']
                    row_msg = "<h3>Heap overlap detected</h3>"
                    row_msg += "<ul><li>malloc(<b>%d</b>) = <b>%#x</b> (<b>%#x</b>) of size %#x</li>\n" % \
                         (arg1, addr, chunk_addr, chunk_size)
                    row_msg += "<li><b>%#x</b> overlaps in-used chunk (<b>%#x</b>) " % (chunk_addr, overlap)
                    row_msg += "of size <b>%#x</b></li></ul>\n" % overlap_size

                    warn_msg, row_color = warn_types['overlap']
                    del self.allocated_chunks[overlap]

                self.allocated_chunks[chunk_addr] = chunk

                if chunk_addr in self.free_chunks:
                    free_chunk = self.free_chunks[chunk_addr]

                    del self.free_chunks[chunk_addr]

                    if chunk['size'] != free_chunk['size']:
                        split_addr = chunk_addr + chunk_size
                        split_size = free_chunk['size']-chunk['size']
                        split_end  = split_addr+split_size

                        self.free_chunks[split_addr] = {
                            'size': split_size,
                            'end': split_end
                        }

                if arg1 >= self.heap.min_large_size:
                    """ If this is a large request, consolidate fastbins """
                    self.malloc_consolidate()

            elif action == "free":

                chunk_addr = self.heap.mem2chunk(addr)
                chunk = self.heap.get_chunk(chunk_addr)
                chunk_size = chunk.norm_size
                prev_inuse = chunk.prev_inuse
                chunk_end  = chunk_addr+chunk_size

                overlap = check_overlap(chunk_addr, chunk_size, self.free_chunks)
                if overlap is not None:

                    row_msg = "<h3>Double free detected</h3>"
                    row_msg += "<ul><li>free (<b>%#x</b>) of size <b>%#x</b></li>" % \
                        (chunk_addr, chunk_size)
                    row_msg += "<li>Double free: <b>%#x</b> of size <b>%#x</b></li></ul>\n" % \
                         (overlap, self.free_chunks[overlap]['size'])

                    warn_msg, row_color = warn_types['double_free']
                    del self.free_chunks[overlap]


                in_tcache = False
                tc_idx = self.heap.csize2tidx(chunk_size)

                if self.heap.tcache_enabled and tc_idx < TCACHE_BINS:

                    tcache = self.heap.get_tcache_struct(self.cur_arena)
                    tc_idx = self.heap.csize2tidx(chunk_size)

                    if tcache.counts[tc_idx] < TCACHE_COUNT:
                        self.free_chunks[chunk_addr] = {
                            'size': chunk_size,
                            'end': chunk_end
                        }
                        in_tcache = True

                        if chunk_addr in self.allocated_chunks:
                            del self.allocated_chunks[chunk_addr]

                if not in_tcache:

                    # fastbins
                    if chunk_size <= config.ptr_size*16:

                        self.free_chunks[chunk_addr] = {
                            'size': chunk_size,
                            'end': chunk_end
                        }

                        if chunk_addr in self.allocated_chunks:
                            del self.allocated_chunks[chunk_addr]

                    # > global_max_fast
                    else:
                        if prev_inuse == 0:
                            prev_size = chunk.prev_size
                            prev_addr = chunk_addr-prev_size

                            if prev_addr in self.free_chunks:
                                prev_size += chunk_size
                                del self.free_chunks[prev_addr]

                        next_chunk = {}
                        av = self.heap.get_arena(self.cur_arena)
                        next_addr = chunk_addr + chunk_size

                        if next_addr == av.top:
                            if chunk_addr in self.allocated_chunks:
                                del self.allocated_chunks[chunk_addr]

                        else:
                            next_chunk = self.heap.get_chunk(next_addr)
                            next_size  = next_chunk.norm_size
                            next_inuse = self.heap.get_chunk(next_addr+next_size).prev_inuse

                            if next_inuse == 0:

                                if prev_inuse:
                                    if next_addr in self.free_chunks:
                                        chunk_size += next_size
                                        del self.free_chunks[next_addr]
                                else:
                                    if next_addr in self.free_chunks:
                                        prev_size += next_size
                                        del self.free_chunks[next_addr]

                            # prev freed
                            if prev_inuse == 0:
                                if chunk_addr in self.allocated_chunks:
                                    del self.allocated_chunks[chunk_addr]

                                chunk_addr = prev_addr
                                chunk_size = prev_size
                                chunk_end  = prev_addr+prev_size


                            self.free_chunks[chunk_addr] = {
                                'size': chunk_size,
                                'end': chunk_end
                            }
                            if chunk_addr in self.allocated_chunks:
                                del self.allocated_chunks[chunk_addr]

                            if chunk_size > 0x10000:
                                self.malloc_consolidate()


            elif action == "realloc":
                self.update_allocated_chunks()

        num_rows = self.tbl_traced_chunks.rowCount()
        if row_msg is not None:
            self.row_info[num_rows] = row_msg

        self.tbl_traced_chunks.setSortingEnabled(False)
        self.tbl_traced_chunks.insertRow(num_rows)

        caller_name = get_func_name_offset(caller) if caller else ''

        arg1 = "%#x" % arg1 if arg1 is not None else 'N/A'
        arg2 = "%#x" % arg2 if arg2 is not None else 'N/A'
        warn_msg_s = warn_msg if warn_msg else 'N/A'

        it_count  = QtWidgets.QTableWidgetItem("%d" % num_rows)
        it_chunk  = QtWidgets.QTableWidgetItem("%#x" % addr)
        it_action = QtWidgets.QTableWidgetItem(action)
        it_arg1   = QtWidgets.QTableWidgetItem(arg1)
        it_arg2   = QtWidgets.QTableWidgetItem(arg2)
        it_thread = QtWidgets.QTableWidgetItem("%d" % thread_id)
        it_caller = QtWidgets.QTableWidgetItem(caller_name)
        it_info   = QtWidgets.QTableWidgetItem(warn_msg_s)
        
        self.tbl_traced_chunks.setItem(num_rows, 0, it_count)
        self.tbl_traced_chunks.setItem(num_rows, 1, it_chunk)
        self.tbl_traced_chunks.setItem(num_rows, 2, it_action)
        self.tbl_traced_chunks.setItem(num_rows, 3, it_arg1)
        self.tbl_traced_chunks.setItem(num_rows, 4, it_arg2)
        self.tbl_traced_chunks.setItem(num_rows, 5, it_thread)
        self.tbl_traced_chunks.setItem(num_rows, 6, it_caller)
        self.tbl_traced_chunks.setItem(num_rows, 7, it_info)

        self.tbl_traced_chunks.resizeRowsToContents()
        self.tbl_traced_chunks.resizeColumnsToContents()
        self.tbl_traced_chunks.setSortingEnabled(True)

        if warn_msg:
            self.tbl_traced_chunks.set_row_color(num_rows, row_color)

        # only reload when the function returns
        if from_ret:
            self.parent.reload_gui_info()

# -----------------------------------------------------------------------

