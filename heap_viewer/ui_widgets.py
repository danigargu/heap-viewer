#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import json
import traceback
import tempfile

from idc import *
from idautils import *
from idaapi import *

from ctypes import *
from collections import OrderedDict
from cgi import escape as html_encode

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QWidget, QCheckBox, QLabel, QAction, QTextEdit
from PyQt5.QtWidgets import QSplitter, QListWidget, QVBoxLayout, QHBoxLayout
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QDialog

from heap_viewer.misc import *
from heap_viewer.ptmalloc import *
from heap_viewer.tracer import HeapTracer
from heap_viewer.bingraph import BinGraph
from heap_viewer.io_file import parse_io_file_structs

import heap_viewer.config as config
import heap_viewer.villoc as villoc


# -----------------------------------------------------------------------
class TTable(QTableWidget):
    def __init__(self, labels, parent=None):
        QTableWidget.__init__(self, parent)
        self.labels = labels
        self.setColumnCount(len(labels))
        self.setHorizontalHeaderLabels(labels)
        self.verticalHeader().hide()
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.horizontalHeader().model().setHeaderData(0, QtCore.Qt.Horizontal, 
            QtCore.Qt.AlignJustify, QtCore.Qt.TextAlignmentRole)    
        self.horizontalHeader().setStretchLastSection(1)
        self.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

    def copy_selected_value(self):
        item = self.currentItem()
        if item:
            QtWidgets.QApplication.clipboard().setText(item.text())

    def copy_selected_row(self):
        selection = self.selectionModel()
        indexes = selection.selectedRows()
        if len(indexes) < 1:
            return
        text = ''
        for idx in indexes:
            row = idx.row()
            for col in range(0, self.columnCount()):
                item = self.item(row, col)
                if item:
                    text += item.text()
                text += '\t'
            text += '\n'
        QtWidgets.QApplication.clipboard().setText(text)

    def dump_table_as_csv(self):
        result = ''
        result += ';'.join(self.labels) + "\n"
        for i in range(0, self.rowCount()):
            columns = []
            for j in range(0, self.columnCount()):
                item = self.item(i, j).text()
                columns.append(item)
            result += ';'.join(columns) + "\n"
        return result


    def resize_columns(self, widths):
        for i, val in enumerate(widths):
            self.setColumnWidth(i, val)

    def resize_to_contents(self):
        self.resizeRowsToContents()
        self.resizeColumnsToContents()

    def set_row_color(self, num_row, color):
        for i in range(self.columnCount()):
            self.item(num_row, i).setBackground(color)

    def clear_table(self):
        self.setRowCount(0)

# -----------------------------------------------------------------------
class CustomWidget(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self)
        self.parent = parent

    @property
    def heap(self):
        return self.parent.heap

    @property
    def cur_arena(self):
        return self.parent.cur_arena

    def _create_gui(self):
        raise NotImplementedError


# -----------------------------------------------------------------------
class InfoDialog(QDialog):
    def __init__(self, info, parent=None):
        QDialog.__init__(self)
        self.parent = parent
        self.info = info
        self._create_gui()
        self.setModal(False)

    def _create_gui(self):
        self.t_info = QtWidgets.QTextEdit()
        self.t_info.setReadOnly(True)
        self.t_info.setFixedHeight(300)
        self.t_info.setFixedWidth(600)
        self.t_info.insertHtml(self.info)

        hbox = QHBoxLayout()
        hbox.addWidget(self.t_info)
        self.setLayout(hbox)


# -----------------------------------------------------------------------
class ChunkEditor(QDialog):
    def __init__(self, addr, parent=None):
        QDialog.__init__(self)
        self.addr = addr
        self.parent = parent
        self.chunk = None
        self._create_gui()
        self._populate_gui()

    def _create_gui(self):
        lbl = QLabel("0x%X" % self.addr)
        lbl.setStyleSheet("font-weight: bold")

        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.t_prev_size = QtWidgets.QLineEdit()
        self.t_size = QtWidgets.QLineEdit()
        self.t_fd = QtWidgets.QLineEdit()
        self.t_bk = QtWidgets.QLineEdit()
        self.t_fd_nextsize = QtWidgets.QLineEdit()
        self.t_bk_nextsize = QtWidgets.QLineEdit()

        widgets = [
            self.t_prev_size,
            self.t_size,
            self.t_fd,
            self.t_bk,
            self.t_fd_nextsize,
            self.t_bk_nextsize
        ]
        for w in widgets:
            w.setFixedWidth(170)

        groupbox_flags = QtWidgets.QGroupBox()
        self.f_prev_inuse = QCheckBox("prev_inuse")
        self.f_is_mmaped = QCheckBox("is_mmapped")
        self.f_non_main_arena = QCheckBox("non_main_arena")

        vbox_flags = QVBoxLayout()
        vbox_flags.addWidget(self.f_prev_inuse)
        vbox_flags.addWidget(self.f_is_mmaped)
        vbox_flags.addWidget(self.f_non_main_arena)
        groupbox_flags.setLayout(vbox_flags)

        form.addRow(lbl)
        form.addRow(QLabel())
        form.addRow("prev_size", self.t_prev_size)
        form.addRow("size", self.t_size)
        form.addRow("fd", self.t_fd)
        form.addRow("bk", self.t_bk)
        form.addRow("fd_nextsize", self.t_fd_nextsize)
        form.addRow("bk_nextsize", self.t_bk_nextsize)
        form.addRow("flags", groupbox_flags)

        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.btn_cancel_on_click)
        self.btn_save = QtWidgets.QPushButton("Save")
        self.btn_save.clicked.connect(self.btn_save_on_click)

        form.addRow(QLabel())
        form.addRow(self.btn_cancel, self.btn_save)
        self.setLayout(form)

    def _populate_gui(self):
        chunk = self.parent.heap.get_chunk(self.addr)

        self.t_prev_size.setText("%#x" % chunk.prev_size)
        self.t_size.setText("%#x" % chunk.norm_size)
        self.t_fd.setText("%#x" % chunk.fd)
        self.t_bk.setText("%#x" % chunk.bk)
        self.t_fd_nextsize.setText("%#x" % chunk.fd_nextsize)
        self.t_bk_nextsize.setText("%#x" % chunk.bk_nextsize)

        self.f_prev_inuse.setChecked(chunk.prev_inuse)
        self.f_is_mmaped.setChecked(chunk.is_mmapped)
        self.f_non_main_arena.setChecked(chunk.non_main_arena)

        self.chunk = chunk

    def btn_cancel_on_click(self):
        self.done(0)

    def btn_save_on_click(self):
        flags = 0
        if self.f_prev_inuse.isChecked():
            flags |= PREV_INUSE
        if self.f_is_mmaped.isChecked():
            flags |= IS_MMAPPED
        if self.f_non_main_arena.isChecked():
            flags |= NON_MAIN_ARENA

        try:
            size = eval(self.t_size.text())
            size |= flags

            fd = eval(self.t_fd.text())
            bk = eval(self.t_fd.text())
            fd_nextsize = eval(self.t_fd_nextsize.text())
            bk_nextsize = eval(self.t_bk_nextsize.text())

            self.chunk.size = size
            self.chunk.fd = fd
            self.chunk.bk = bk
            self.chunk.fd_nextsize = fd_nextsize
            self.chunk.bk_nextsize = bk_nextsize

            patch_bytes(self.addr, self.chunk.data)
            info("Chunk saved!")
            self.done(1)

        except Exception as e:
            warning("ERROR: " + str(e))


# -----------------------------------------------------------------------
class TracerWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self.name = "Tracer"
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
        self.tbl_traced_chunks.itemSelectionChanged.connect(self.show_selected_chunk)
        self.tbl_traced_chunks.cellDoubleClicked.connect(self.traced_double_clicked)

    def _create_menu(self):
        cb_enable_trace = QCheckBox()
        cb_enable_trace.stateChanged.connect(self.cb_tracing_changed)
        self.cb_stop_during_tracing = QCheckBox()
        
        btn_dump_trace = QtWidgets.QPushButton("Dump trace")
        btn_dump_trace.clicked.connect(self.btn_dump_trace_on_click)

        btn_villoc_trace = QtWidgets.QPushButton("Villoc")
        btn_villoc_trace.clicked.connect(self.btn_villoc_on_click)

        btn_clear_trace = QtWidgets.QPushButton("Clear")
        btn_clear_trace.clicked.connect(self.btn_clear_on_click)
        
        hbox_enable_trace = QHBoxLayout()
        hbox_enable_trace.addWidget(QLabel("Enable tracing"))
        hbox_enable_trace.addWidget(cb_enable_trace)
        hbox_enable_trace.addWidget(QLabel("Stop during tracing"))
        hbox_enable_trace.addWidget(self.cb_stop_during_tracing)
        hbox_enable_trace.addWidget(btn_dump_trace)
        hbox_enable_trace.addWidget(btn_villoc_trace)
        hbox_enable_trace.addWidget(btn_clear_trace)
        hbox_enable_trace.addStretch(1)

        hbox_trace = QVBoxLayout()
        hbox_trace.addLayout(hbox_enable_trace)
        hbox_trace.addWidget(QLabel("Traced chunks"))
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
            idc.Jump(chunk_addr - (config.ptr_size*2))

        elif action == jump_to_u:
            idc.Jump(chunk_addr)

        elif action == goto_caller:
            caller_str = str(sender.item(sender.currentRow(), 6).text())
            if caller_str:
                idc.Jump(str2ea(caller_str))

        elif action == view_chunk:
            self.show_selected_chunk()

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
            warning("Empty table")
            return

        try:
            villoc.Block.header = config.ptr_size*2
            villoc.Block.round  = self.parent.heap.malloc_alignment
            villoc.Block.minsz  = self.parent.heap.min_chunk_size

            result = self.dump_table_for_villoc()
            html = villoc.build_html(result)

            h, filename = tempfile.mkstemp(suffix='.html')

            with open(filename, 'wb') as f:
                f.write(html)

            url = QtCore.QUrl.fromLocalFile(filename)
            QtGui.QDesktopServices.openUrl(url)

        except Exception as e:
            warning(traceback.format_exc())

    def btn_dump_trace_on_click(self):
        if self.tbl_traced_chunks.rowCount() == 0:
            warning("Empty table")
            return

        filename = AskFile(1, "*.csv", "Select the file to store tracing results")
        if not filename:
            return            
        try:
            result = self.tbl_traced_chunks.dump_table_as_csv()
            with open(filename, 'wb') as f:
                f.write(result)

        except Exception as e:
            warning(traceback.format_exc())

    def btn_clear_on_click(self):
        self.tbl_traced_chunks.clear_table()

    def show_selected_chunk(self):
        items = self.tbl_traced_chunks.selectedItems()
        if len(items)>0:
            chunk_addr = int(items[1].text(), 16)
            norm_address = "0x%x-0x%x" % (chunk_addr, config.ptr_size * 2)
            self.parent.show_chunk_info(norm_address)

    def traced_double_clicked(self):
        current_row = self.sender().currentRow()
        if current_row in self.row_info:
            info(self.row_info[current_row])

        """
        if current_row in self.row_info:
            i = InfoDialog(self.row_info[current_row])
            i.show()
        """

    def update_allocated_chunks(self):
        for start, info in self.allocated_chunks.iteritems():
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
                            else:
                                warning("prev chunk (freed) not in free_chunks list: %#x" % prev_addr)

                        next_chunk = {}
                        av = self.heap.get_arena(self.cur_arena)
                        next_addr = chunk_addr + chunk_size

                        if next_addr == av.top:
                            warning("next_addr = arena.top")
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
                                warning("Malloc consolidate. chunk_size = %d" % chunk_size)


            elif action == "realloc":
                self.update_allocated_chunks()

        num_rows = self.tbl_traced_chunks.rowCount()
        if row_msg is not None:
            self.row_info[num_rows] = row_msg

        self.tbl_traced_chunks.setSortingEnabled(False)
        self.tbl_traced_chunks.insertRow(num_rows)

        caller_name = ''
        if caller:
            caller_name = get_func_name_offset(caller)
            if caller_name is None:
                caller_name = '%#x' % caller

        arg1 = "%#x" % arg1 if arg1 is not None else 'N/A'
        arg2 = "%#x" % arg2 if arg2 is not None else 'N/A'
        warn_msg_s = warn_msg if warn_msg else 'N/A'

        it_count  = QTableWidgetItem("%d" % num_rows)
        it_chunk  = QTableWidgetItem("%#x" % addr)
        it_action = QTableWidgetItem(action)
        it_arg1 = QTableWidgetItem(arg1)
        it_arg2 = QTableWidgetItem(arg2)
        it_thread = QTableWidgetItem("%d" % thread_id)
        it_caller = QTableWidgetItem(caller_name)
        it_info = QTableWidgetItem(warn_msg_s)
        
        self.tbl_traced_chunks.setItem(num_rows, 0, it_count)
        self.tbl_traced_chunks.setItem(num_rows, 1, it_chunk)
        self.tbl_traced_chunks.setItem(num_rows, 2, it_action)
        self.tbl_traced_chunks.setItem(num_rows, 3, it_arg1)
        self.tbl_traced_chunks.setItem(num_rows, 4, it_arg2)
        self.tbl_traced_chunks.setItem(num_rows, 5, it_thread)
        self.tbl_traced_chunks.setItem(num_rows, 6, it_caller)
        self.tbl_traced_chunks.setItem(num_rows, 7, it_info)

        self.tbl_traced_chunks.resizeRowsToContents()
        self.tbl_traced_chunks.setSortingEnabled(True)

        if warn_msg:
            self.tbl_traced_chunks.set_row_color(num_rows, row_color)

        if from_ret:
            self.parent.reload_gui_info()

# -----------------------------------------------------------------------
class ChunkWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self.setMinimumWidth(400)
        self._create_gui()

    def _create_gui(self):        

        self.t_chunk_addr = QtWidgets.QLineEdit()
        self.t_chunk_addr.setFixedWidth(180)
        self.t_chunk_addr.returnPressed.connect(self.view_chunk_on_click)

        self.btn_view_chunk = QtWidgets.QPushButton("View")
        self.btn_view_chunk.clicked.connect(self.view_chunk_on_click)

        self.btn_jump_chunk = QtWidgets.QPushButton("Jump")
        self.btn_jump_chunk.clicked.connect(self.jump_on_click)

        self.btn_next_chunk = QtWidgets.QPushButton("Next")
        self.btn_next_chunk.clicked.connect(self.next_on_click)

        self.btn_prev_chunk = QtWidgets.QPushButton("Prev")
        self.btn_prev_chunk.clicked.connect(self.prev_on_click)

        self.btn_edit_chunk = QtWidgets.QPushButton("Edit")
        self.btn_edit_chunk.clicked.connect(self.edit_chunk_on_click)

        hbox_chunk_address = QHBoxLayout()
        hbox_chunk_address.addWidget(QLabel("Chunk address "))
        hbox_chunk_address.addWidget(self.t_chunk_addr)
        hbox_chunk_address.setContentsMargins(0, 0, 0, 0)
        hbox_chunk_address.setSpacing(0)
        hbox_chunk_address.addStretch(1)

        hbox_btns = QHBoxLayout()
        hbox_btns.addWidget(self.btn_view_chunk)
        hbox_btns.addWidget(self.btn_jump_chunk)
        hbox_btns.addWidget(self.btn_next_chunk)
        hbox_btns.addWidget(self.btn_prev_chunk)
        hbox_btns.addWidget(self.btn_edit_chunk)
        hbox_btns.addStretch(1)

        self.te_chunk_info = QtWidgets.QTextEdit()
        self.te_chunk_info.setReadOnly(True)

        hbox = QVBoxLayout()
        hbox.addLayout(hbox_chunk_address)
        hbox.addLayout(hbox_btns)
        hbox.addWidget(self.te_chunk_info)
        hbox.setSpacing(3)

        groupbox_arena_info = QtWidgets.QGroupBox('Chunk info')
        groupbox_arena_info.setLayout(hbox)

        hbox_actions = QVBoxLayout()
        hbox_actions.addWidget(groupbox_arena_info)
        hbox_actions.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hbox_actions)


    def html_chunk_table(self, chunk, in_use):
        chunk_table = '<table>'
        offset = 0
        for name, ctype in chunk._fields_:
            value = getattr(chunk, name)

            chunk_table += '''
                <tr>
                    <td>+%02d</td>
                    <td>%s</td>
                    <td>0x%x</td>
                </tr>
            ''' % (offset, name, value)

            offset += sizeof(ctype)

        chunk_table += '<tr><td></td><td>norm_size</td><td>0x%x</td></tr>' % (chunk.norm_size)

        for field in ['prev_inuse', 'is_mmapped', 'non_main_arena']:
            chunk_table += '''
                <tr>
                    <td></td>
                    <td>%s</td>
                    <td>%d</td>
                </tr>
            ''' % (field, getattr(chunk, field))


        if in_use is not None:
            chunk_table += '''
                <tr>
                    <td></td>
                    <td>next->prev_inuse</td>
                    <td>%d</td>
                </tr>
            ''' % (in_use)

        chunk_table += '</table>'
        return chunk_table

    def html_chunk_hexdump(self, data, splitted):
        hexdump = '<code>'
        line = ''
        data_len = len(data)
        spaces = len(str(data_len))
        fmt_offset = "+%-{0}d | ".format(spaces)
        hexdump += fmt_offset % 0

        #for i in range(len(chunk.data)):
        for i in range(len(data)):
            char = data[i]
            hexdump += "%02X " % ord(char)

            char = re.sub(r'[<>\'"]', '\x00', char)
            line += char if 0x20 <= ord(char) <= 0x7e else '.'

            if (i+1) % config.ptr_size == 0 and i != (len(data)-1):
                hexdump += ' | %s<br>' % line
                hexdump += fmt_offset % (i+1)
                line = ''
        hexdump += ' | %s<br>' % line

        if splitted:
            hexdump += "<br>[...]<br>"

        hexdump += "</code>"
        return hexdump


    def view_chunk_on_click(self):
        chunk_template = '''
        <style>
            td {
                padding-right: 30px;
            }
            table {
                font-size: 12px;
                white-space: nowrap;
                overflow: hidden;
            }
            body {
                width: 100%%;
            }
            #hexdump {
                font-family:Monaco;
                font-size:12px;
                white-space:pre;
            }
        </style>
        <p><b>[ 0x%x ]</b><br>
        <!-- Chunk fields -->
        %s
        <br>
        <p><b>[ hexdump ]</b></p>
        <p id="hexdump";>%s</p>
        '''

        chunk_addr = self.get_current_addr()

        if chunk_addr is None:
            warning("Invalid expression")
            return

        try:
            splitted = False
            in_use = None
            chunk_data = ""
            chunk_hexdump = ""
            chunk = self.heap.get_chunk(chunk_addr)
            chunk_bytes = chunk.norm_size
      
            if chunk_bytes > config.hexdump_limit: 
                chunk_bytes = config.hexdump_limit
                splitted = True

            if chunk_bytes > 0 and is_loaded(chunk_addr + chunk_bytes):
                chunk_data = get_bytes(chunk_addr, chunk_bytes)
            else:
                chunk_data = chunk.data

            if is_loaded(chunk_addr + chunk.norm_size):
                in_use = self.heap.next_chunk(chunk_addr).prev_inuse

            chunk_table = self.html_chunk_table(chunk, in_use)
            if chunk_data:
                chunk_hexdump = self.html_chunk_hexdump(chunk_data, splitted)

            self.te_chunk_info.clear()
            chunk_info = chunk_template % (chunk_addr, chunk_table, chunk_hexdump)
            self.te_chunk_info.insertHtml(chunk_info)

        except Exception as e:
            warning("ERROR: " + str(e))
            #warning(traceback.format_exc())

    def show_chunk(self, expr):
        if type(expr) == str:
            self.t_chunk_addr.setText(expr)
        elif type(expr) == int or type(expr) == long:
            self.t_chunk_addr.setText("0x%x" % expr)
        self.view_chunk_on_click()

    def get_current_addr(self):
        ea = None
        try:
            ea = int(eval(self.t_chunk_addr.text()))
        except:
            pass
        return ea

    def jump_on_click(self):
        try:
            chunk_addr = int(eval(self.t_chunk_addr.text()))
            idc.Jump(chunk_addr)
        except:
            warning("Invalid expression")

    def next_on_click(self):
        chunk_addr = self.get_current_addr()
        if chunk_addr is None:
            warning("Invalid expression")
            return
        try:
            chunk = self.heap.get_chunk(chunk_addr)
            chunk_size = chunk.norm_size
            next_addr = chunk_addr+chunk_size
            if is_loaded(next_addr):
                self.show_chunk("%#x" % next_addr)
            else:
                warning("%#x: next addr (%#x) is not loaded" % (chunk_addr, next_addr))
        except Exception as e:
            warning("ERROR: " + str(e))

    def prev_on_click(self):
        chunk_addr = self.get_current_addr()
        if chunk_addr is None:
            warning("Invalid expression")
            return
        try:
            chunk = self.heap.get_chunk(chunk_addr)
            if chunk.prev_inuse == 0:
                prev_addr = chunk_addr-chunk.prev_size
                self.show_chunk("%#x" % prev_addr)
            else:
                warning("%#x: prev_chunk in use" % chunk_addr)
        except Exception as e:
            warning("ERROR: " + str(e))

    def edit_chunk_on_click(self):
        chunk_addr = self.get_current_addr()
        if chunk_addr is not None:
            w = ChunkEditor(chunk_addr, self)
            if w.exec_() == 1:
                self.view_chunk_on_click()

# -----------------------------------------------------------------------
class ArenaWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self._create_table()
        self._create_menu()

    def _create_menu(self):
        self.t_top_addr = QtWidgets.QLineEdit()
        self.t_top_addr.setFixedWidth(150)
        self.t_top_addr.setReadOnly(True)

        self.t_last_remainder = QtWidgets.QLineEdit()
        self.t_last_remainder.setFixedWidth(150)
        self.t_last_remainder.setReadOnly(True)

        self.lbl_top_warning = QtWidgets.QLabel()
        self.lbl_top_warning.setStyleSheet('color: red')
        self.lbl_top_warning.setVisible(False)

        self.t_attached_threads = QtWidgets.QLineEdit()
        self.t_attached_threads.setFixedWidth(150)
        self.t_attached_threads.setReadOnly(True)

        hbox_arena_top = QHBoxLayout()
        hbox_arena_top.addWidget(QLabel('Top:'))
        hbox_arena_top.addWidget(self.t_top_addr)
        hbox_arena_top.addWidget(QLabel('Last remainder:'))
        hbox_arena_top.addWidget(self.t_last_remainder)
        hbox_arena_top.addWidget(QLabel('Attached threads:'))
        hbox_arena_top.addWidget(self.t_attached_threads)
        hbox_arena_top.addStretch(1)

        hbox_arena_others = QHBoxLayout()
        hbox_arena_others.addWidget(self.lbl_top_warning)

        self.bold_font = QFont()
        self.bold_font.setBold(True)

        grid_arenas = QtWidgets.QGridLayout()        
        grid_arenas.addLayout(hbox_arena_top, 0, 0)
        grid_arenas.addLayout(hbox_arena_others, 1, 0)
        grid_arenas.addWidget(self.tbl_parsed_heap, 2, 0)

        self.setLayout(grid_arenas)

    def _create_table(self):
        self.tbl_parsed_heap = TTable(['address','prev','size','status','fd','bk'])
        self.tbl_parsed_heap.resize_columns([155, 40, 100, 120, 155, 155])
        self.tbl_parsed_heap.customContextMenuRequested.connect(self.context_menu)
        self.tbl_parsed_heap.itemSelectionChanged.connect(self.show_selected_chunk)

    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to chunk")
        jump_to_u = menu.addAction("Jump to user-data")
        check_freaable = menu.addAction("Check freeable")

        chunk_addr = int(sender.item(sender.currentRow(), 0).text(), 16)
        action = menu.exec_(sender.mapToGlobal(position))
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(chunk_addr)

        elif action == jump_to_u:
            idc.Jump(chunk_addr + (config.ptr_size*2))

        elif action == view_chunk:
            self.show_selected_chunk()

        elif action == check_freaable:
            self.parent.check_freeable(chunk_addr)

    def show_selected_chunk(self):
        items = self.tbl_parsed_heap.selectedItems()
        if len(items) > 0:
            chunk_addr = int(items[0].text(), 16)
            self.parent.show_chunk_info(chunk_addr)

    def populate_table(self):
        cur_arena = self.cur_arena
        arena = self.heap.get_arena(cur_arena)
        self.t_top_addr.setText("0x%x" % arena.top)
        self.t_last_remainder.setText("0x%x" % arena.last_remainder)
        self.t_attached_threads.setText("%d" % arena.attached_threads)

        top_segname = SegName(arena.top)
        if not any(s in top_segname for s in ['heap','debug']):
            self.lbl_top_warning.setVisible(True)
            self.lbl_top_warning.setText("Top points to '%s' segment" % top_segname)
        else:
            self.lbl_top_warning.setVisible(False)

        self.tbl_parsed_heap.clearContents()
        self.tbl_parsed_heap.setRowCount(0)
        self.tbl_parsed_heap.setSortingEnabled(False)

        parsed_heap = self.heap.parse_heap(cur_arena)

        for idx, chunk in enumerate(parsed_heap):
            self.tbl_parsed_heap.insertRow(idx)

            it_address = QTableWidgetItem("0x%x" % chunk['address'])
            it_prev = QTableWidgetItem("0x%x" % chunk['prev'])
            it_size = QTableWidgetItem("0x%x" % chunk['size'])
            it_status = QTableWidgetItem("%s" % chunk['status'])
            it_fd = QTableWidgetItem("0x%x" % chunk['fd'])
            it_bk = QTableWidgetItem("0x%x" % chunk['bk'])

            if 'Freed' in chunk['status']:
                it_status.setForeground(QColor('red'))
            elif chunk['status'] == 'Corrupt':
                it_status.setForeground(QColor.fromRgb(213, 94, 0))
                it_status.setFont(self.bold_font)
            else:
                it_status.setForeground(QColor('blue'))

            self.tbl_parsed_heap.setItem(idx, 0, it_address)
            self.tbl_parsed_heap.setItem(idx, 1, it_prev)
            self.tbl_parsed_heap.setItem(idx, 2, it_size)
            self.tbl_parsed_heap.setItem(idx, 3, it_status)
            self.tbl_parsed_heap.setItem(idx, 4, it_fd)
            self.tbl_parsed_heap.setItem(idx, 5, it_bk)

        self.tbl_parsed_heap.resizeRowsToContents()
        self.tbl_parsed_heap.setSortingEnabled(True)
        self.tbl_parsed_heap.sortByColumn(0, QtCore.Qt.DescendingOrder)


# -----------------------------------------------------------------------
class BinsWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self.show_bases = False
        self._create_gui()

    def _create_gui(self):
        self._create_tables()
        vbox_fastbins = QVBoxLayout()
        vbox_fastbins.addWidget(QLabel("Fastbins"))
        vbox_fastbins.addWidget(self.tbl_fastbins)

        vbox_unsortedbin = QVBoxLayout()
        vbox_unsortedbin.addWidget(QLabel("Unsorted"))
        vbox_unsortedbin.addWidget(self.tbl_unsortedbin)

        vbox_smallbins = QVBoxLayout()
        vbox_smallbins.addWidget(QLabel("Small bins"))
        vbox_smallbins.addWidget(self.tbl_smallbins)

        vbox_largebins = QVBoxLayout()
        vbox_largebins.addWidget(QLabel("Large bins"))
        vbox_largebins.addWidget(self.tbl_largebins)

        self.te_chain_info = QtWidgets.QTextEdit()
        self.te_chain_info.setReadOnly(True)

        vbox_chain = QVBoxLayout()
        vbox_chain.addWidget(QLabel("Chain info"))
        vbox_chain.addWidget(self.te_chain_info)

        grid_bins = QtWidgets.QGridLayout()
        grid_bins.addLayout(vbox_fastbins, 0, 0)
        grid_bins.addLayout(vbox_unsortedbin, 0, 1)
        grid_bins.addLayout(vbox_smallbins, 1, 0)
        grid_bins.addLayout(vbox_largebins, 1, 1)
        grid_bins.addLayout(vbox_chain, 2, 0, 2, 2)

        self.setLayout(grid_bins)


    def _create_tables(self):

        # --- Fastbins table
        self.tbl_fastbins = TTable(['#','size','fd'])
        self.tbl_fastbins.resize_columns([50, 100, 155])
        self.tbl_fastbins.customContextMenuRequested.connect(self.context_menu)
        self.tbl_fastbins.cellDoubleClicked.connect(self.table_on_change)
        self.tbl_fastbins.itemSelectionChanged.connect(self.table_on_change)

        # --- Unsortedbin
        self.tbl_unsortedbin = TTable(['#','fd','bk','base'])
        self.tbl_unsortedbin.resize_columns([50, 155, 155, 155])
        self.tbl_unsortedbin.customContextMenuRequested.connect(self.context_menu)
        self.tbl_unsortedbin.cellDoubleClicked.connect(self.table_on_change)
        self.tbl_unsortedbin.itemSelectionChanged.connect(self.table_on_change)

        # --- Smallbins
        self.tbl_smallbins = TTable(['#','size','fd','bk','base'])
        self.tbl_smallbins.resize_columns([50, 100, 155, 155, 155])
        self.tbl_smallbins.customContextMenuRequested.connect(self.context_menu)
        self.tbl_smallbins.cellDoubleClicked.connect(self.table_on_change)
        self.tbl_smallbins.itemSelectionChanged.connect(self.table_on_change)

        # --- Largebins
        self.tbl_largebins = TTable(['#','size','fd','bk','base'])
        self.tbl_largebins.resize_columns([50, 100, 155, 155, 155])
        self.tbl_largebins.customContextMenuRequested.connect(self.context_menu)
        self.tbl_largebins.cellDoubleClicked.connect(self.table_on_change)
        self.tbl_largebins.itemSelectionChanged.connect(self.table_on_change)


        self.bin_tables = {
            self.tbl_fastbins: {
                'title': 'fastbins',
                'address': 2,
                'size': 1,
                'base': None
            },
            self.tbl_unsortedbin: {
                'title': 'unsortedbin',
                'address': 1,
                'size': None,
                'base': 3
            },
            self.tbl_smallbins: {
                'title': 'smallbins',
                'address': 2,
                'size': 1,
                'base': 4
            },
            self.tbl_largebins: {
                'title': 'largebins',
                'address': 2,
                'size': 1,
                'base': 4
            }
        }


    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to")
        graphview_action = menu.addAction("GraphView")
        self.show_uninit = menu.addAction("Show uninitialized bins (bases)")
        self.show_uninit.setCheckable(True)
        self.show_uninit.setChecked(self.show_bases)

        action = menu.exec_(sender.mapToGlobal(position))

        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            self.jmp_to_selected_chunk()

        elif action == view_chunk:
            self.show_selected_chunk()

        elif action == self.show_uninit:
            self.show_bases = self.show_uninit.isChecked()
            self.populate_tables()

        elif action == graphview_action:

            if sender is self.tbl_fastbins:
                idx   = int(sender.item(sender.currentRow(), 0).text())
                size  = int(sender.item(sender.currentRow(), 1).text(), 16)

                graph = BinGraph(self, info={
                    'type': 'fastbin',
                    'fastbin_id': idx,
                    'size': size
                })
                graph.Show()

            elif sender is self.tbl_unsortedbin:
                idx  = sender.item(sender.currentRow(), 0).text()
                base = int(sender.item(sender.currentRow(), 3).text(), 16)

                graph = BinGraph(self, info={
                    'type': 'unsortedbin',
                    'bin_id': idx,
                    'bin_base': base    
                })
                graph.Show()

            elif sender is self.tbl_smallbins:
                idx  = sender.item(sender.currentRow(), 0).text()
                size = int(sender.item(sender.currentRow(), 1).text(), 16)
                base = int(sender.item(sender.currentRow(), 4).text(), 16)

                graph = BinGraph(self, info={
                    'type': 'smallbin',
                    'bin_id': idx,
                    'size': size,
                    'bin_base': base    
                })
                graph.Show()

            elif sender is self.tbl_largebins:
                idx  = sender.item(sender.currentRow(), 0).text()
                size = int(sender.item(sender.currentRow(), 1).text(), 16)
                base = int(sender.item(sender.currentRow(), 4).text(), 16)

                graph = BinGraph(self, info={
                    'type': 'largebin',
                    'bin_id': idx,
                    'size': size,
                    'bin_base': base    
                })
                graph.Show()


    def show_bin_chain(self):
        sender = self.sender()
        stop = 0
        size = None

        row = sender.selectedItems()

        if not len(row):
            return

        bin_cols = self.bin_tables[sender]
        address = int(row[bin_cols['address']].text(), 16)

        if bin_cols['size']:
            size = int(row[bin_cols['size']].text(), 16)

        if bin_cols['base']:
            stop = int(row[bin_cols['base']].text(), 16)

        self.show_chain(bin_cols['title'], address, size, stop)


    def show_selected_chunk(self):
        chunk_addr = self.get_selected_chunk_addr()
        if chunk_addr:
            self.parent.show_chunk_info(chunk_addr)

    def jmp_to_selected_chunk(self):
        chunk_addr = self.get_selected_chunk_addr()
        if chunk_addr:
            idc.Jump(chunk_addr)

    def get_selected_chunk_addr(self):
        sender = self.sender()
        items = sender.selectedItems()
        if len(items):
            col_id = self.bin_tables[sender]['address']
            address = int(items[col_id].text(), 16)
            return address
        return None

    def table_on_change(self):
        self.show_selected_chunk()
        self.show_bin_chain()

    def show_chain(self, title, address, size, stop=0):
        if size:
            title = '%s[0x%02x]' % (title, size)

        if address != 0 and address != BADADDR:
            chain, b_error = self.heap.chunk_chain(address, stop)
            html_chain = make_html_chain(title, chain, b_error)
            self.te_chain_info.clear()
            self.te_chain_info.insertHtml(html_chain)

    def populate_tbl_fastbins(self): 
        self.tbl_fastbins.clearContents()
        self.tbl_fastbins.setRowCount(0)
        self.tbl_fastbins.setSortingEnabled(False)

        idx = 0
        fastbins = self.heap.get_fastbins(self.cur_arena)
        for id_fast, (size, fast_chunk) in enumerate(fastbins.iteritems()):

            if not self.show_bases and fast_chunk == 0:
                continue

            self.tbl_fastbins.insertRow(idx)

            it_bin_num  = QTableWidgetItem("%d" % id_fast)
            it_size = QTableWidgetItem("0x%x" % size)
            it_fastchunk = QTableWidgetItem("0x%x" % fast_chunk)

            self.tbl_fastbins.setItem(idx, 0, it_bin_num)
            self.tbl_fastbins.setItem(idx, 1, it_size)
            self.tbl_fastbins.setItem(idx, 2, it_fastchunk)

            idx += 1

        if idx:
            self.tbl_fastbins.resize_to_contents()
            self.tbl_fastbins.setSortingEnabled(True)


    def populate_tbl_unsortedbin(self):
        base, fd, bk = self.heap.get_unsortedbin(self.cur_arena)

        self.tbl_unsortedbin.clearContents()
        self.tbl_unsortedbin.setRowCount(0)

        # points to current base
        if not self.show_bases and fd == base:
            return

        self.tbl_unsortedbin.setSortingEnabled(False)
        self.tbl_unsortedbin.insertRow(0)

        it_bin_num  = QTableWidgetItem("1")
        it_fd = QTableWidgetItem("0x%x" % fd)
        it_bk = QTableWidgetItem("0x%x" % bk)
        it_base = QTableWidgetItem("0x%x" % base)

        self.tbl_unsortedbin.setItem(0, 0, it_bin_num)
        self.tbl_unsortedbin.setItem(0, 1, it_fd)
        self.tbl_unsortedbin.setItem(0, 2, it_bk)
        self.tbl_unsortedbin.setItem(0, 3, it_base)

        self.tbl_unsortedbin.resizeRowsToContents()
        self.tbl_unsortedbin.resizeColumnsToContents()
        self.tbl_unsortedbin.setSortingEnabled(True)


    def populate_tbl_smallbins(self):
        self.tbl_smallbins.clearContents()
        self.tbl_smallbins.setRowCount(0)
        self.tbl_smallbins.setSortingEnabled(False)

        smallbins = self.heap.get_smallbins(self.cur_arena)

        idx = 0
        for bin_id, smallbin in smallbins.iteritems():

            # point to himself
            if not self.show_bases and smallbin['base'] == smallbin['fd']:
                continue

            self.tbl_smallbins.insertRow(idx)
            it_bin_num  = QTableWidgetItem("%d" % bin_id)
            it_size = QTableWidgetItem("0x%x" % smallbin['size'])
            it_fd = QTableWidgetItem("0x%x" % smallbin['fd'])
            it_bk = QTableWidgetItem("0x%x" % smallbin['bk'])
            it_base = QTableWidgetItem("0x%x" % smallbin['base'])

            self.tbl_smallbins.setItem(idx, 0, it_bin_num)
            self.tbl_smallbins.setItem(idx, 1, it_size)
            self.tbl_smallbins.setItem(idx, 2, it_fd)
            self.tbl_smallbins.setItem(idx, 3, it_bk)
            self.tbl_smallbins.setItem(idx, 4, it_base)

            idx += 1

        self.tbl_smallbins.resizeRowsToContents()
        self.tbl_smallbins.resizeColumnsToContents()
        self.tbl_smallbins.setSortingEnabled(True)


    def populate_tbl_largebins(self):
        self.tbl_largebins.clearContents()
        self.tbl_largebins.setRowCount(0)
        self.tbl_largebins.setSortingEnabled(False)

        largebins = self.heap.get_largebins(self.cur_arena)

        idx = 0
        for bin_id, largebin in largebins.iteritems():

            # point to himself
            if not self.show_bases and largebin['base'] == largebin['fd']:
                continue
  
            self.tbl_largebins.insertRow(idx)
            it_bin_num  = QTableWidgetItem("%d" % bin_id)
            it_size = QTableWidgetItem("0x%x" % largebin['size'])
            it_fd = QTableWidgetItem("0x%x" % largebin['fd'])
            it_bk = QTableWidgetItem("0x%x" % largebin['bk'])
            it_base = QTableWidgetItem("0x%x" % largebin['base'])

            self.tbl_largebins.setItem(idx, 0, it_bin_num)
            self.tbl_largebins.setItem(idx, 1, it_size)
            self.tbl_largebins.setItem(idx, 2, it_fd)
            self.tbl_largebins.setItem(idx, 3, it_bk)
            self.tbl_largebins.setItem(idx, 4, it_base)

            idx += 1

        self.tbl_largebins.resizeRowsToContents()
        self.tbl_largebins.resizeColumnsToContents()
        self.tbl_largebins.setSortingEnabled(True)


    def populate_tables(self):
        self.populate_tbl_fastbins()
        self.populate_tbl_unsortedbin()
        self.populate_tbl_smallbins()
        self.populate_tbl_largebins()


# -----------------------------------------------------------------------
class TcacheWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self._create_table()   
      
        self.te_tcache_chain = QtWidgets.QTextEdit()
        self.te_tcache_chain.setFixedHeight(100)
        self.te_tcache_chain.setReadOnly(True)
        
        vbox_tcache_chain = QVBoxLayout()
        vbox_tcache_chain.addWidget(QLabel('Chain info'))
        vbox_tcache_chain.addWidget(self.te_tcache_chain)

        vbox_tcache = QtWidgets.QVBoxLayout()
        vbox_tcache.addWidget(QLabel('Tcache entries'))
        vbox_tcache.addWidget(self.tbl_tcache)
        vbox_tcache.addLayout(vbox_tcache_chain)
        vbox_tcache.addStretch(1)

        self.setLayout(vbox_tcache)

    def _create_table(self):

        # -----------------------------------------------------------------------
        # Tcache table

        self.tbl_tcache = TTable(['#','size','counts','next'])
        self.tbl_tcache.resize_columns([50, 100, 50, 155])
        self.tbl_tcache.customContextMenuRequested.connect(self.context_menu)
        self.tbl_tcache.cellDoubleClicked.connect(self.show_selected_chunk)
        self.tbl_tcache.itemSelectionChanged.connect(self.table_on_change_index)


    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to")
        graphview_action = menu.addAction("GraphView")

        action = menu.exec_(sender.mapToGlobal(position))
        fd_addr = int(sender.item(sender.currentRow(), 3).text(), 16)
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(fd_addr)

        elif action == view_chunk:
            self.show_selected_chunk()

        elif action == graphview_action:
            idx = int(sender.item(sender.currentRow(), 0).text())
            size = int(sender.item(sender.currentRow(), 1).text(), 16)
            fd = int(sender.item(sender.currentRow(), 3).text(), 16)

            graph = BinGraph(self, info={
                'type': 'tcache',
                'bin_id': idx,
                'size': size,
            })
            graph.Show()


    def populate_table(self):
        self.tbl_tcache.clearContents()
        self.tbl_tcache.setRowCount(0)
        self.tbl_tcache.setSortingEnabled(False)

        tcache = self.heap.get_tcache(self.cur_arena)

        if not tcache:
            return

        idx = 0
        for i, (size, entry) in enumerate(tcache.iteritems()):

            if entry['counts'] == 0 and entry['next'] == 0:
                continue

            self.tbl_tcache.insertRow(idx)

            it_entry_id  = QTableWidgetItem("%d" % i)
            it_size  = QTableWidgetItem("0x%x" % size)
            it_counts = QTableWidgetItem("%d" % entry['counts'])
            it_address = QTableWidgetItem("0x%x" % entry['next'])

            self.tbl_tcache.setItem(idx, 0, it_entry_id)
            self.tbl_tcache.setItem(idx, 1, it_size)
            self.tbl_tcache.setItem(idx, 2, it_counts)
            self.tbl_tcache.setItem(idx, 3, it_address)

            idx += 1

        self.tbl_tcache.resizeRowsToContents()
        self.tbl_tcache.resizeColumnsToContents()
        self.tbl_tcache.setSortingEnabled(True)


    def table_on_change_index(self):
        sender = self.sender()
        items = sender.selectedItems()

        if items and len(items):
            entry_addr = int(items[3].text(), 16)
            entry_size = int(items[1].text(), 16)
            self.show_chain(entry_addr, entry_size)
            

    def show_selected_chunk(self):
        items = self.sender().selectedItems()
        entry_addr = int(items[3].text(), 16)
        norm_address = "0x%x-0x%x" % (entry_addr, config.ptr_size * 2)
        self.parent.show_chunk_info(norm_address)


    def show_chain(self, address, size):
        title = 'Tcache[0x%02x]' % size
        chain, b_error = self.heap.tcache_chain(address)
        html_chain = make_html_chain(title, chain, b_error)
        self.te_tcache_chain.clear()
        self.te_tcache_chain.insertHtml(html_chain)


class UnlinkWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.t_unlink_addr = QtWidgets.QLineEdit()
        self.t_unlink_addr.setFixedWidth(150)
        self.t_unlink_info = QtWidgets.QTextEdit()
        self.t_unlink_info.setFixedHeight(400)
        self.t_unlink_info.setReadOnly(True)


        self.btn_check_unlink = QtWidgets.QPushButton("Check")
        self.btn_check_unlink.clicked.connect(self.check_unlink_on_click)

        hbox_unlink = QHBoxLayout()
        hbox_unlink.addWidget(QLabel('Chunk ptr unlink'))
        hbox_unlink.addWidget(self.t_unlink_addr)
        hbox_unlink.addWidget(self.btn_check_unlink)

        hbox_unlink.addStretch(1)

        vbox_unlink = QVBoxLayout()
        vbox_unlink.addLayout(hbox_unlink)
        vbox_unlink.addWidget(self.t_unlink_info)
        vbox_unlink.addStretch(1)
        vbox_unlink.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vbox_unlink)

    def check_unlink_on_click(self):
        info_template = '''
        <style>
            td {padding-right: 30px;}
            table {font-size: 12px;}
            body {width: 100%%;}
            #True {color: green}
            #False {color: red}
        </style>
        <table>
            <tr>
                <td>Unlinkable</td>
                <td><b id="%s">%s</b></td>
            </tr> 
            <tr>
                <td>P</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>chunk_size</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>next->prev_size</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>FD</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>BK</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>FD->bk</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>BK->fd</td>
                <td>0x%x</td>
            </tr>
        </table>

        <p><b>Result of unlink</b></p>\n
        <table>
            <tr>
                <td>FD->bk (*0x%x)</td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td>BK->fd (*0x%x)</td>
                <td><b>0x%x<b></td>
            </tr>
        </table>
        '''

        p = int(self.t_unlink_addr.text(), 16)

        chunk = self.heap.get_chunk(p)
        fd_chunk = self.heap.get_chunk(chunk.fd)
        bk_chunk = self.heap.get_chunk(chunk.bk)
        next_chunk = self.heap.next_chunk(p)

        fd_offset = self.heap.chunk_member_offset('fd')
        bk_offset = self.heap.chunk_member_offset('bk')

        """

        Unlink macro:
        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

        if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     
            malloc_printerr (check_action, "corrupted double-linked list", P);

        chunksize(P) != prev_size(next_chunk(P))

        https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30

        """

        unlinkable = (fd_chunk.bk == p and bk_chunk.fd == p) and \
            (chunk.norm_size == next_chunk.prev_size)

        unlinkable_s = str(unlinkable)

        unlink_info = info_template % (unlinkable_s, unlinkable_s, p, chunk.norm_size, next_chunk.prev_size, 
            chunk.bk, chunk.fd, fd_chunk.bk, bk_chunk.fd, chunk.fd+bk_offset, chunk.bk, 
            chunk.bk+fd_offset, chunk.fd)

        self.t_unlink_info.clear()
        self.t_unlink_info.insertHtml(unlink_info)
        


# -----------------------------------------------------------------------
class HouseOfForceWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.t_house_force_addr = QtWidgets.QLineEdit()
        self.t_house_force_addr.setFixedWidth(150)

        self.t_house_force_info = QtWidgets.QTextEdit()
        self.t_house_force_info.setReadOnly(True)

        self.btn_house_force = QtWidgets.QPushButton("Calc evil size")
        self.btn_house_force.clicked.connect(self.house_force_on_click)

        hbox_house_force = QHBoxLayout()
        hbox_house_force.addWidget(QLabel('Target address'))
        hbox_house_force.addWidget(self.t_house_force_addr)
        hbox_house_force.addWidget(self.btn_house_force)
        hbox_house_force.addStretch(1)

        vbox_house_force = QVBoxLayout()
        vbox_house_force.addLayout(hbox_house_force)
        vbox_house_force.addWidget(self.t_house_force_info)
        vbox_house_force.addStretch(1)

        vbox_house_force.setContentsMargins(0, 0, 0, 0)
        self.setLayout(vbox_house_force)


    def house_force_on_click(self):
        arena = self.heap.get_arena(self.cur_arena)
        target_addr = int(self.t_house_force_addr.text(), 16)

        ptr_size = config.ptr_size

        top_size_ptr = arena.top + ptr_size
        top_size_val = self.heap.get_ptr(top_size_ptr)
        evil_size = target_addr - (ptr_size * 2) - top_size_ptr

        # unsigned
        if ptr_size == 4:
            evil_size_u = evil_size & 0xffffffff
        else:
            evil_size_u = evil_size & 0xffffffffffffffff

        html_result = '''
        <style>
            td {padding-right: 30px;}
            table {font-size: 12px;}
            body {width: 100%%;}
        </style>

        <table>
            <tr>
                <td><b>&top</b></td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td><b>&top->size</b></td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td><b>top->size</b></td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td><b>Evil size unsigned</b></td>
                <td>0x%x</td>
            </tr>
            <tr>
                <td><b>Evil size signed</b></td>
                <td>%d</td>
            </tr>
            <tr>
                <td><b>Formula</b></td>
                <td>target_address - ptr_size * 2 - &top->size</td>
            </tr>
        </table>
        ''' % (arena.top, top_size_ptr, top_size_val, evil_size_u, evil_size)

        self.t_house_force_info.clear()
        self.t_house_force_info.insertHtml(html_result)


    
# -----------------------------------------------------------------------
class LibcOffsetsWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self.libc_base = None
        self._create_gui()
        self.populate_table()

    def _create_gui(self):
        self.tbl_offsets_vars = TTable(['name','offset'])
        self.tbl_offsets_vars.resize_columns([150, 100])
        self.tbl_offsets_vars.cellDoubleClicked.connect(self.tbl_offsets_double_clicked)
        self.tbl_offsets_vars.customContextMenuRequested.connect(self.context_menu)

        self.tbl_offsets_funcs = TTable(['name','offset'])
        self.tbl_offsets_funcs.resize_columns([150, 100])
        self.tbl_offsets_funcs.cellDoubleClicked.connect(self.tbl_offsets_double_clicked)
        self.tbl_offsets_funcs.customContextMenuRequested.connect(self.context_menu)

        vbox_offsets_vars = QVBoxLayout()
        vbox_offsets_vars.addWidget(QLabel('Variables'))
        vbox_offsets_vars.addWidget(self.tbl_offsets_vars)

        vbox_offsets_funcs = QVBoxLayout()
        vbox_offsets_funcs.addWidget(QLabel('Functions'))
        vbox_offsets_funcs.addWidget(self.tbl_offsets_funcs)

        hbox_libc_offsets = QHBoxLayout()
        hbox_libc_offsets.addLayout(vbox_offsets_vars)
        hbox_libc_offsets.addLayout(vbox_offsets_funcs)
        hbox_libc_offsets.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hbox_libc_offsets)

    def context_menu(self, position):
        sender = self.sender()

        menu = QtWidgets.QMenu()
        action_copy = menu.addAction("Copy value")
        action_copy_row = menu.addAction("Copy row")
        action_jump_to = menu.addAction("Jump to address")

        action = menu.exec_(sender.mapToGlobal(position))

        if action == action_copy:
            sender.copy_selected_value()

        elif action == action_copy_row:
            sender.copy_selected_row()

        elif action == action_jump_to:

            offset = int(sender.item(sender.currentRow(), 1).text(), 16)

            address = self.libc_base + offset
            idc.Jump(address)

    def tbl_offsets_double_clicked(self):
        sender = self.sender()
        offset = int(sender.item(sender.currentRow(), 1).text(), 16)
        address = self.libc_base + offset
        idc.Jump(address)

    def populate_table(self):
        self.tbl_offsets_vars.clearContents()
        self.tbl_offsets_funcs.clearContents()

        self.tbl_offsets_vars.setRowCount(0)
        self.tbl_offsets_funcs.setRowCount(0)               

        self.tbl_offsets_vars.setSortingEnabled(False)
        self.tbl_offsets_funcs.setSortingEnabled(False)

        offsets = self.get_libc_offsets()

        variables = offsets['variables']
        functions = offsets['functions']

        for idx, (name, offset) in enumerate(variables.iteritems()):
            self.tbl_offsets_vars.insertRow(idx)
            self.tbl_offsets_vars.setItem(idx, 0, QTableWidgetItem(name))
            self.tbl_offsets_vars.setItem(idx, 1, QTableWidgetItem("0x%x" % offset))

        for idx, (name, offset) in enumerate(functions.iteritems()):
            self.tbl_offsets_funcs.insertRow(idx)
            self.tbl_offsets_funcs.setItem(idx, 0, QTableWidgetItem(name))
            self.tbl_offsets_funcs.setItem(idx, 1, QTableWidgetItem("0x%x" % offset))
        
        self.tbl_offsets_vars.resizeRowsToContents()
        self.tbl_offsets_funcs.resizeRowsToContents()

        self.tbl_offsets_vars.setSortingEnabled(True)
        self.tbl_offsets_funcs.setSortingEnabled(True)  


    def get_libc_offsets(self):        
        libc_symbols = {
            'variables': [
                '__environ',
                '__free_hook',
                '__malloc_hook',
                '__realloc_hook',
                '_IO_list_all',
                '_IO_2_1_stdin_',
                '_IO_2_1_stdout_',
                '_IO_2_1_stderr_',
            ],
            'functions': [                
                'system',
                'execve',
                'open',
                'read',
                'write',
                '_IO_gets',
                'setcontext+0x35',
            ]
        }
        result = {
            'variables': OrderedDict(),
            'functions': OrderedDict(),

        }
        
        self.libc_base = get_libc_base()
        if not self.libc_base:
            return result

        libc_names = get_libc_names()
        if not libc_names:
            warning("Unable to get glibc symbols.")
            return result

        for s_type, symbols in libc_symbols.iteritems():
            for sym in symbols:

                name_expr = parse_name_expr(sym)
                if not name_expr:
                    continue

                name, offset = name_expr
                addr = libc_names.get(name)

                if addr:
                    addr += offset
                    offset = addr - self.libc_base
                    result[s_type][sym] = offset
                    
        return result
        
# -----------------------------------------------------------------------

class FakefastWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.t_fakefast_addr = QtWidgets.QLineEdit()
        self.t_fakefast_addr.setFixedWidth(150)

        self.tbl_fakefast = TTable(['fast_id', 'fast_size', 'bytes to target', 'chunk address'])
        self.tbl_fakefast.customContextMenuRequested.connect(self.context_menu)

        self.t_fakefast_info = QtWidgets.QTextEdit()
        self.t_fakefast_info.setReadOnly(True)

        self.btn_find_fakefast = QtWidgets.QPushButton("Find")
        self.btn_find_fakefast.clicked.connect(self.find_fakefast_on_click)

        hbox_fakefast = QHBoxLayout()
        hbox_fakefast.addWidget(QLabel('Target address'))
        hbox_fakefast.addWidget(self.t_fakefast_addr)
        hbox_fakefast.addWidget(self.btn_find_fakefast)
        hbox_fakefast.addStretch(1)

        vbox_fakefast = QVBoxLayout()
        vbox_fakefast.addLayout(hbox_fakefast)
        vbox_fakefast.addWidget(self.tbl_fakefast)
        vbox_fakefast.addStretch(1)
        vbox_fakefast.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vbox_fakefast)

    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to chunk")

        chunk_addr = int(sender.item(sender.currentRow(), 3).text(), 16)
        action = menu.exec_(sender.mapToGlobal(position))
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(chunk_addr)

        elif action == view_chunk:
            self.parent.parent.show_chunk_info(chunk_addr)

    def find_fakefast_on_click(self):
        start_addr = int(self.t_fakefast_addr.text(), 16)
        fake_chunks = self.heap.find_fakefast(start_addr)

        if len(fake_chunks) == 0:
            info("Fakefast: No results")
            return

        self.tbl_fakefast.clearContents()
        self.tbl_fakefast.setRowCount(0)
        self.tbl_fakefast.setSortingEnabled(False)

        for idx, chunk in enumerate(fake_chunks):
            self.tbl_fakefast.insertRow(idx)
            self.tbl_fakefast.setItem(idx, 0, QTableWidgetItem("%d" % chunk['fast_id']))
            self.tbl_fakefast.setItem(idx, 1, QTableWidgetItem("0x%x" % chunk['size']))
            self.tbl_fakefast.setItem(idx, 2, QTableWidgetItem("%d" % chunk['bytes_to']))
            self.tbl_fakefast.setItem(idx, 3, QTableWidgetItem("0x%x" % chunk['address']))    

        self.tbl_fakefast.resizeRowsToContents()
        self.tbl_fakefast.resizeColumnsToContents()
        self.tbl_fakefast.setSortingEnabled(True)


# -----------------------------------------------------------------------
class MagicWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.cb_magic = QtWidgets.QComboBox()
        self.cb_magic.setFixedWidth(200)
        self.cb_magic.addItem('Unlink merge info', 0)
        self.cb_magic.addItem('Find fake fast', 0)
        self.cb_magic.addItem('House of force helper', 0)
        self.cb_magic.addItem('Useful libc offsets')
        self.cb_magic.addItem('Calc chunk size')
        self.cb_magic.addItem('IO_FILE structs')
        self.cb_magic.addItem('Freeable chunk')
        self.cb_magic.currentIndexChanged[int].connect(self.cb_magic_changed)

        self.stacked_magic = QtWidgets.QStackedWidget()

        self.unlink_widget = UnlinkWidget(self)
        self.fakefast_widget = FakefastWidget(self)
        self.house_of_force_widget = HouseOfForceWidget(self)
        self.libc_offsets_widget = LibcOffsetsWidget(self)
        self.req2size_widget = Req2sizeWidget(self)
        self.io_file_widget = IOFileWidget(self)
        self.freeable_widget = FreeableWidget(self)

        self.stacked_magic.addWidget(self.unlink_widget)
        self.stacked_magic.addWidget(self.fakefast_widget)
        self.stacked_magic.addWidget(self.house_of_force_widget)
        self.stacked_magic.addWidget(self.libc_offsets_widget)
        self.stacked_magic.addWidget(self.req2size_widget)
        self.stacked_magic.addWidget(self.io_file_widget)
        self.stacked_magic.addWidget(self.freeable_widget)

        hbox_magic = QHBoxLayout()
        hbox_magic.addWidget(QLabel('Select util'))
        hbox_magic.addWidget(self.cb_magic)
        hbox_magic.addStretch(1)

        self.vbox_magic = QVBoxLayout()
        self.vbox_magic.addLayout(hbox_magic)
        self.vbox_magic.addWidget(self.stacked_magic)
        #self.vbox_magic.addStretch(1)

        self.setLayout(self.vbox_magic)

    def populate_libc_offsets(self):
        self.libc_offsets_widget.populate_table()

    def cb_magic_changed(self, idx):
        self.stacked_magic.setCurrentIndex(idx)


# -----------------------------------------------------------------------
class ConfigWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        
        self.t_config = QtWidgets.QTextEdit()
        self.t_config.setFixedHeight(440)

        self.btn_update_config = QtWidgets.QPushButton("Update")
        self.btn_dump_config = QtWidgets.QPushButton("Dump json")

        self.btn_update_config.clicked.connect(self.update_config)
        self.btn_dump_config.clicked.connect(self.dump_config)

        hbox_update_config = QHBoxLayout()        
        hbox_update_config.addWidget(QLabel("Config file (config.json)"))
        hbox_update_config.addWidget(self.btn_update_config)
        hbox_update_config.addWidget(self.btn_dump_config)
        hbox_update_config.addStretch(1)

        groupbox_tracer = QtWidgets.QGroupBox("Tracer options")
        self.opt1 = QCheckBox("Start tracing at startup")
        self.opt2 = QCheckBox("Stop during tracing")
        self.opt3 = QCheckBox("Detect double frees and chunk overlaps")

        vbox_tracer = QVBoxLayout()
        vbox_tracer.addWidget(self.opt1)
        vbox_tracer.addWidget(self.opt2)
        vbox_tracer.addWidget(self.opt3)
        groupbox_tracer.setLayout(vbox_tracer)

        vbox_options = QVBoxLayout()
        vbox_options.addWidget(QtWidgets.QTextEdit("Hexdump limit"))

        hbox_hex_limit = QHBoxLayout()
        self.t_hexdump_limit = QtWidgets.QLineEdit()
        self.t_hexdump_limit.setFixedWidth(180)
        hbox_hex_limit.addWidget(QLabel("Hexdump limit (bytes)"))
        hbox_hex_limit.addWidget(self.t_hexdump_limit)
        hbox_hex_limit.addStretch(1)

        vbox_offsets = QVBoxLayout()

        form_offsets = QtWidgets.QFormLayout()
        form_offsets.setSpacing(5)
        form_offsets.setLabelAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)

        self.t_main_arena = QtWidgets.QLineEdit()
        self.t_malloc_par = QtWidgets.QLineEdit()
        self.t_global_max_fast = QtWidgets.QLineEdit()

        self.offset_widgets = {
            'main_arena': self.t_main_arena,
            'malloc_par': self.t_malloc_par,
            'global_max_fast': self.t_global_max_fast
        }

        form_offsets.addRow("main_arena", self.t_main_arena)
        form_offsets.addRow("mp_ (malloc_par)", self.t_malloc_par)
        form_offsets.addRow("global_max_fast", self.t_global_max_fast)


        groupbox_offsets = QtWidgets.QGroupBox("glibc offsets (optional)")
        groupbox_offsets.setLayout(form_offsets)

        hbox_groupboxs = QHBoxLayout()
        hbox_groupboxs.addWidget(groupbox_tracer)
        hbox_groupboxs.addWidget(groupbox_offsets)
        hbox_groupboxs.addStretch(1)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox_update_config)
        vbox.addLayout(hbox_groupboxs)
        vbox.addLayout(hbox_hex_limit)
        vbox.addStretch(1)
        self.setLayout(vbox)

    def get_offsets(self):
        offsets = {}
        for name, widget in self.offset_widgets.iteritems():
            try:
                value = int(widget.text())
                offsets[name] = value
            except:
                pass
        return offsets

    def load_config(self):
        self.opt1.setChecked(config.start_tracing_at_startup)
        self.opt2.setChecked(config.stop_during_tracing)
        self.opt3.setChecked(config.detect_double_frees_and_overlaps)
        self.t_hexdump_limit.setText("%d" % config.hexdump_limit)

        if type(config.libc_offsets) is dict:
            for name, widget in self.offset_widgets.iteritems():
                value = config.libc_offsets.get(name)
                if value is not None:
                    widget.setText("%d" % value)

    def update_config(self):
        try:
            config.start_tracing_at_startup = self.opt1.isChecked()
            config.stop_during_tracing = self.opt2.isChecked()
            config.detect_double_frees_and_overlaps = self.opt3.isChecked()
            config.hexdump_limit = int(self.t_hexdump_limit.text())
            config.libc_offsets = self.get_offsets()

            config.save()
            info("Config updated!")

            self.parent.init_heap(from_update=True)
            self.parent.reload_gui_info()

        except Exception as e:
            warning("ERROR: " + str(e))

    def dump_config(self):
        info(config.dump())


# -----------------------------------------------------------------------
class Req2sizeWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.t_req2size = QtWidgets.QLineEdit()
        self.t_req2size.setFixedWidth(150)

        self.t_req2size_info = QtWidgets.QTextEdit()
        self.t_req2size_info.setReadOnly(True)

        self.btn_req2size = QtWidgets.QPushButton("Calc chunk size")
        self.btn_req2size.clicked.connect(self.btn_req2size_on_click)

        hbox_req2size = QHBoxLayout()
        hbox_req2size.addWidget(QLabel('Request size'))
        hbox_req2size.addWidget(self.t_req2size)
        hbox_req2size.addWidget(self.btn_req2size)
        hbox_req2size.addStretch(1)

        vbox_req2size = QVBoxLayout()
        vbox_req2size.addLayout(hbox_req2size)
        vbox_req2size.addWidget(self.t_req2size_info)
        vbox_req2size.addStretch(1)

        vbox_req2size.setContentsMargins(0, 0, 0, 0)
        self.setLayout(vbox_req2size)

    def btn_req2size_on_click(self):
        req_size = eval(self.t_req2size.text())

        min_chunk_size = self.heap.min_chunk_size
        malloc_alignment = self.heap.malloc_alignment
        size = self.heap.request2size(req_size)

        html_result = '''
        <style>
            td {padding-right: 20px;}
            body {width: 100%%;}
        </style>

        <table>
            <tr>
                <td><b>Min chunk size</b></td>
                <td>0x%x (%d)</td>
            </tr>
            <tr>
                <td><b>Malloc alignment</b></td>
                <td>0x%x (%d)</td>
            </tr>
            <tr>
                <td><b>Chunk size</b></td>
                <td>0x%x (%d)</td>
            </tr>
        </table>
        ''' % (min_chunk_size,min_chunk_size, malloc_alignment, 
            malloc_alignment, size, size)

        self.t_req2size_info.clear()
        self.t_req2size_info.insertHtml(html_result)

# -----------------------------------------------------------------------
class IOFileWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()
        self.cb_struct_changed(0)

    def _create_gui(self):
        self.t_io_file = QtWidgets.QTextEdit()
        self.t_io_jump_t = QtWidgets.QTextEdit()
        self.t_io_file.setReadOnly(True)
        self.t_io_jump_t.setReadOnly(True)

        self.cb_struct = QtWidgets.QComboBox()
        self.cb_struct.setFixedWidth(200)

        io_structs = [
            '_IO_2_1_stdin_',
            '_IO_2_1_stdout_',
            '_IO_2_1_stderr_'
        ]
        for i, name in enumerate(io_structs):
            self.cb_struct.addItem(name, i)

        self.cb_struct.currentIndexChanged[int].connect(self.cb_struct_changed)

        self.t_struct_addr = QtWidgets.QLineEdit()
        self.t_struct_addr.setFixedWidth(150)
        self.btn_parse_struct = QtWidgets.QPushButton('Show')
        self.btn_parse_struct.clicked.connect(self.show_struct_on_click)

        hbox_io_struct = QHBoxLayout()
        hbox_io_struct.addWidget(QLabel('Struct:'))
        hbox_io_struct.addWidget(self.cb_struct)
        hbox_io_struct.addWidget(QLabel('Address:'))
        hbox_io_struct.addWidget(self.t_struct_addr)
        hbox_io_struct.addWidget(self.btn_parse_struct)
        hbox_io_struct.addStretch(1)

        hbox_result = QtWidgets.QGridLayout()
        hbox_result = QHBoxLayout()
        hbox_result.addWidget(self.t_io_file)
        hbox_result.addWidget(self.t_io_jump_t)

        vbox_req2size = QVBoxLayout()
        vbox_req2size.addLayout(hbox_io_struct)
        vbox_req2size.addLayout(hbox_result)

        vbox_req2size.setContentsMargins(0, 0, 0, 0)
        self.setLayout(vbox_req2size)
        
    def cb_struct_changed(self, idx):
        struct_name = str(self.cb_struct.currentText())
        address = LocByName(struct_name)
        if address != BADADDR:
            self.t_struct_addr.setText("0x%x" % address)
            self.show_struct(address, struct_name)

    def show_struct_on_click(self):
        try:
            address = int(self.t_struct_addr.text(), 16)
            self.show_struct(address, "_IO_FILE")
        except:
            warning("ERROR: Invalid address")

    def html_struct_table(self, struct):        
        offsets = get_struct_offsets(type(struct))
        struct_table = '<table>'

        for name, ctype in struct._fields_:
            value = getattr(struct, name)

            if ctype in [c_uint32, c_uint64]:
                value = "0x%x" % value
            if ctype is c_char:
                value = "0x%x" % ord(value)

            struct_table += '''
                <tr>
                    <td>+%02X</td>
                    <td>%s</td>
                    <td>%s</td>
                </tr>
            ''' % (offsets[name], name, str(value))

        struct_table += '</table>'
        return struct_table

    def html_template(self, name, address):
        template = '''

        <style>
            td {
                padding-right: 30px;
            }
            table {
                font-size: 12px;
                white-space: nowrap;
                overflow: hidden;
            }
            body {
                width: 100%%;
            }
            #hexdump {
                font-family:Monaco;
                font-size:12px;
            }
        </style>
        <p><b>%s</b> (0x%x)<br>
        ''' % (name, address)

        return template


    def show_struct(self, address, struct_name):
        io_file_struct = parse_io_file_structs(address)
        if io_file_struct is None:
            return

        self.t_io_file.clear()
        self.t_io_jump_t.clear()

        io_jump_t_addr = io_file_struct.file.vtable
        html_table =  self.html_template(struct_name, address)
        html_table += self.html_struct_table(io_file_struct.file)
        self.t_io_file.insertHtml(html_table)

        html_table =  self.html_template("%s->vtable" % struct_name, io_jump_t_addr)
        html_table += self.html_struct_table(io_file_struct.vtable)
        self.t_io_jump_t.insertHtml(html_table)

        for obj in [self.t_io_file, self.t_io_jump_t]:
            cursor = obj.textCursor()
            cursor.setPosition(0)
            obj.setTextCursor(cursor)

# -----------------------------------------------------------------------
class FreeableWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):
        self.t_chunk_addr = QtWidgets.QLineEdit()
        self.t_chunk_addr.setFixedWidth(150)

        self.t_freeable_info = QtWidgets.QTextEdit()
        self.t_freeable_info.setFixedHeight(400)
        self.t_freeable_info.setReadOnly(True)

        self.btn_freeable = QtWidgets.QPushButton("Check")
        self.btn_freeable.clicked.connect(self.check_freeable)

        hbox_freeable = QHBoxLayout()
        hbox_freeable.addWidget(QLabel('Chunk address'))
        hbox_freeable.addWidget(self.t_chunk_addr)
        hbox_freeable.addWidget(self.btn_freeable)
        hbox_freeable.addStretch(1)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox_freeable)
        vbox.addWidget(self.t_freeable_info)
        vbox.addStretch(1)
        vbox.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vbox)

    def check_freeable(self):
        cur_arena = self.cur_arena
        chunk_addr = eval(self.t_chunk_addr.text())

        if self.heap is None:
            warning("Heap not initialized")
            return

        freeable, errors = self.heap.is_freeable(chunk_addr, cur_arena)
        freeable_str = str(freeable)
        html_result = '''
        <style>
            td {padding-right: 20px;}
            body {width: 100%%;}
            #True {color: green}
            #False {color: red}
        </style>
        <h3>Freaable</h3>
        <ul>
            <li><span>0x%x: <b id="%s">%s</b></span></li>
        </ul>
        ''' % (chunk_addr, freeable_str, freeable_str)

        if len(errors) > 0:
            html_result += '<h3>Messages / Errors:</h3>'
            html_result += '<ul>'
            for err in errors:
                html_result += '<li>%s</li>' % html_encode(err)
            html_result += '</ul>'

        merge_info = self.heap.merge_info(chunk_addr, cur_arena)
        if merge_info is not None:
            html_result += '''
            <h3>Merge info</h3>
            <ul>
            '''
            if type(merge_info) == list:
                for info in merge_info:
                    html_result += '<li>%s</li>' % html_encode(info)
            elif type(merge_info) == str:
                html_result += '<li>%s</li>' % merge_info
            html_result += '</ul>'


        self.t_freeable_info.clear()
        self.t_freeable_info.insertHtml(html_result)

# -----------------------------------------------------------------------

