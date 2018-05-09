#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import json
import traceback

from idc import *
from idautils import *
from idaapi import *

from collections import OrderedDict

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QWidget, QCheckBox, QLabel, QAction, QTextEdit
from PyQt5.QtWidgets import QSplitter, QListWidget, QVBoxLayout, QHBoxLayout
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

from misc import *
from tracer import HeapTracer
from bingraph import BinGraph

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
        value = self.currentItem().text()
        QtWidgets.QApplication.clipboard().setText(value)

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
class TracerWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self.name = "Tracer"
        self.tracer = None
        self._create_gui()

    def _create_gui(self):
        self._create_table()
        self._create_menu()     

    def _create_table(self):
        self.tbl_traced_chunks = TTable(['#','User-address', 'Action', 'Req. size', 'Caller', 'Caller address'])
        self.tbl_traced_chunks.setRowCount(0)
        self.tbl_traced_chunks.resize_columns([40, 155, 80, 80, 200, 200])
        self.tbl_traced_chunks.customContextMenuRequested.connect(self.context_menu)
        self.tbl_traced_chunks.itemSelectionChanged.connect(self.show_selected_chunk)

    def _create_menu(self):
        cb_enable_trace = QCheckBox()
        cb_enable_trace.stateChanged.connect(self.cb_tracing_changed)
        btn_dump_trace = QtWidgets.QPushButton("Dump trace")
        btn_dump_trace.clicked.connect(self.btn_dump_trace_on_click)
        
        hbox_enable_trace = QHBoxLayout()
        hbox_enable_trace.addWidget(QLabel("Enable trace"))
        hbox_enable_trace.addWidget(cb_enable_trace)
        hbox_enable_trace.addWidget(btn_dump_trace)
        hbox_enable_trace.addStretch(1)

        hbox_trace = QVBoxLayout()
        hbox_trace.addLayout(hbox_enable_trace)
        hbox_trace.addWidget(QLabel("Traced chunks"))
        hbox_trace.addWidget(self.tbl_traced_chunks)

        self.setLayout(hbox_trace)

    def context_menu(self, position):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        
        copy_action = menu.addAction("Copy value")
        copy_row = menu.addAction("Copy row")
        view_chunk = menu.addAction("View chunk")
        jump_to = menu.addAction("Jump to chunk")
        jump_to_u = menu.addAction("Jump to user-data")
        goto_caller = menu.addAction("Jump to caller")

        chunk_addr = int(sender.item(sender.currentRow(), 1).text(), 16)
        action = menu.exec_(sender.mapToGlobal(position))
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(chunk_addr - (self.heap.ptr_size*2))

        elif action == jump_to_u:
            idc.Jump(chunk_addr)

        elif action == goto_caller:
            caller_addr = sender.item(sender.currentRow(), 5).text()
            if caller_addr:
                idc.Jump(int(caller_addr, 16))

        elif action == view_chunk:
            self.show_selected_chunk()

    def enable_tracing(self):
        self.tracer = HeapTracer(self)
        self.tracer.hook()
        self.parent.tracer = self.tracer 
        log("Tracer enabled")

    def disable_tracing(self):
        if self.tracer:
            self.tracer.remove_bps()
            self.tracer.unhook()
            self.parent.tracer = None
        log("Trace disabled")

    def cb_tracing_changed(self, state):
        if state == QtCore.Qt.Checked:
            self.enable_tracing()
        else:
            self.disable_tracing()

    def btn_dump_trace_on_click(self):
        filename = AskFile(1, "*.csv", "Select the file to store tracing results")
        if not filename:
            return            
        try:
            result = self.tbl_traced_chunks.dump_table_as_csv()
            with open(filename, 'wb') as f:
                f.write(result)
        except Excetion as e:
            warning(e.message)

    def show_selected_chunk(self):
        items = self.tbl_traced_chunks.selectedItems()
        chunk_addr = int(items[1].text(), 16)
        norm_address = "0x%x-0x%x" % (chunk_addr, self.heap.ptr_size * 2)
        self.parent.show_chunk_info(norm_address)

    def append_traced_chunk(self, addr, action, reqsize, caller):
        num_rows = self.tbl_traced_chunks.rowCount()

        self.tbl_traced_chunks.setSortingEnabled(False)
        self.tbl_traced_chunks.insertRow(num_rows)

        caller_name_offset = get_func_name_offset(caller)
        reqsize = "0x%x" % reqsize if reqsize else 'N/A'

        it_count  = QTableWidgetItem("%d" % num_rows)
        it_chunk  = QTableWidgetItem("0x%x" % addr)
        it_action = QTableWidgetItem("%s" % action)
        it_reqsize = QTableWidgetItem(reqsize)
        it_caller = QTableWidgetItem("%s" % caller_name_offset)
        it_caller_a = QTableWidgetItem("0x%x" % caller)
        
        self.tbl_traced_chunks.setItem(num_rows, 0, it_count)
        self.tbl_traced_chunks.setItem(num_rows, 1, it_chunk)
        self.tbl_traced_chunks.setItem(num_rows, 2, it_action)
        self.tbl_traced_chunks.setItem(num_rows, 3, it_reqsize)
        self.tbl_traced_chunks.setItem(num_rows, 4, it_caller)
        self.tbl_traced_chunks.setItem(num_rows, 5, it_caller_a)
        
        self.tbl_traced_chunks.resizeRowsToContents()
        self.tbl_traced_chunks.setSortingEnabled(True)
        self.parent.reload_gui_info()


# -----------------------------------------------------------------------
class ChunkWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
        self._create_gui()

    def _create_gui(self):        

        self.t_chunk_addr = QtWidgets.QLineEdit()
        self.t_chunk_addr.setFixedWidth(180)
        self.t_chunk_addr.returnPressed.connect(self.view_chunk_on_click)

        self.btn_view_chunk = QtWidgets.QPushButton("View")
        self.btn_view_chunk.clicked.connect(self.view_chunk_on_click)

        self.btn_jump_chunk = QtWidgets.QPushButton("Jump")
        self.btn_jump_chunk.clicked.connect(self.jump_on_click)

        hbox_chunk_address = QHBoxLayout()
        hbox_chunk_address.addWidget(QLabel("Chunk address:"))
        hbox_chunk_address.addWidget(self.t_chunk_addr)
        hbox_chunk_address.addWidget(self.btn_view_chunk)
        hbox_chunk_address.addWidget(self.btn_jump_chunk)
        hbox_chunk_address.addStretch(1)


        self.te_chunk_info = QtWidgets.QTextEdit()
        self.te_chunk_info.setReadOnly(True)

        hbox_arena = QVBoxLayout()        
        hbox_arena.addLayout(hbox_chunk_address)
        hbox_arena.addWidget(self.te_chunk_info)

        groupbox_arena_info = QtWidgets.QGroupBox('Chunk info')
        groupbox_arena_info.setLayout(hbox_arena)

        hbox_actions = QVBoxLayout()
        hbox_actions.addWidget(groupbox_arena_info)
        hbox_actions.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hbox_actions)


    def html_chunk_table(self, chunk):
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

        chunk_table += '</table>'
        return chunk_table

    def html_chunk_hexdump(self, chunk):
        hexdump = '<p>'
        hexdump = '+%02d | ' % 0
        line = ''

        for i in range(len(chunk.data)):
            char = chunk.data[i]
            hexdump += "%02X " % ord(char)

            # Fix
            char = re.sub(r'[<>\'"]', '\x00', char)
            line += char if 0x20 <= ord(char) <= 0x7e else '.'

            if (i+1) % self.heap.ptr_size == 0 and i != (len(chunk.data)-1):
                hexdump += ' | %s<br>' % line
                hexdump += '+%02d | ' % (i+1)
                line = ''
        hexdump += ' | %s</p>' % line

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
            }
        </style>
        <p><b>[ chunk @ 0x%x ]</b><br>
        <!-- Chunk fields -->
        %s
        <br>
        <p><b>[ hexdump ]</b></p>
        <p id="hexdump";>%s</p>
        '''        

        try:
            chunk_addr = int(eval(self.t_chunk_addr.text()))
        except:
            warning("Invalid expression")
            return

        chunk = self.heap.get_chunk(chunk_addr)
        chunk_table = self.html_chunk_table(chunk)
        chunk_hexdump = self.html_chunk_hexdump(chunk)
        
        self.te_chunk_info.clear()
        chunk_info = chunk_template % (chunk_addr, chunk_table, chunk_hexdump)
        self.te_chunk_info.insertHtml(chunk_info)

    def show_chunk(self, expr):
        if type(expr) == str:
            self.t_chunk_addr.setText(expr)
        elif type(expr) == int or type(expr) == long:
            self.t_chunk_addr.setText("0x%x" % expr)
        self.view_chunk_on_click()

    def jump_on_click(self):
        try:
            chunk_addr = int(eval(self.t_chunk_addr.text()))
            idc.Jump(chunk_addr)
        except:
            warning("Invalid expression")
            return

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

        hbox_arena_top = QHBoxLayout()
        hbox_arena_top.addWidget(QLabel('Top:'))
        hbox_arena_top.addWidget(self.t_top_addr)
        hbox_arena_top.addWidget(QLabel('Last remainder:'))
        hbox_arena_top.addWidget(self.t_last_remainder)
        hbox_arena_top.addWidget(self.lbl_top_warning)
        hbox_arena_top.addStretch(1)

        self.bold_font = QFont()
        self.bold_font.setBold(True)

        grid_arenas = QtWidgets.QGridLayout()        
        grid_arenas.addLayout(hbox_arena_top, 0, 0)
        grid_arenas.addWidget(self.tbl_parsed_heap, 1, 0)

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

        chunk_addr = int(sender.item(sender.currentRow(), 0).text(), 16)
        action = menu.exec_(sender.mapToGlobal(position))
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(chunk_addr)

        elif action == jump_to_u:
            idc.Jump(chunk_addr + (self.heap.ptr_size*2))

        elif action == view_chunk:
            self.show_selected_chunk()

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


# -----------------------------------------------------------------------
class BinsWidget(CustomWidget):
    def __init__(self, parent=None):
        CustomWidget.__init__(self, parent)
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

        action = menu.exec_(sender.mapToGlobal(position))

        addr_field = self.bin_tables[sender]['address']
        chunk_addr = int(sender.item(sender.currentRow(), addr_field).text(), 16)
       
        if action == copy_action:
            sender.copy_selected_value()

        if action == copy_row:
            sender.copy_selected_row()

        elif action == jump_to:
            idc.Jump(chunk_addr)

        elif action == view_chunk:
            self.show_selected_chunk()

        elif action == graphview_action:

            if sender is self.tbl_fastbins:
                idx   = int(sender.item(sender.currentRow(), 0).text())
                size  = int(sender.item(sender.currentRow(), 1).text(), 16)

                graph = BinGraph(self.heap, info={
                    'type': 'fastbin',
                    'fastbin_id': idx,
                    'size': size
                })
                graph.Show()

            elif sender is self.tbl_unsortedbin:
                idx  = sender.item(sender.currentRow(), 0).text()
                base = int(sender.item(sender.currentRow(), 3).text(), 16)

                graph = BinGraph(self.heap, info={
                    'type': 'unsortedbin',
                    'bin_id': idx,
                    'bin_base': base    
                })
                graph.Show()


            elif sender is self.tbl_smallbins:
                idx  = sender.item(sender.currentRow(), 0).text()
                size = int(sender.item(sender.currentRow(), 1).text(), 16)
                base = int(sender.item(sender.currentRow(), 4).text(), 16)

                graph = BinGraph(self.heap, info={
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

                graph = BinGraph(self.heap, info={
                    'type': 'largebin',
                    'bin_id': idx,
                    'size': size,
                    'bin_base': base    
                })
                graph.Show()


            elif sender is self.tbl_tcache:
                idx = int(sender.item(sender.currentRow(), 0).text())
                size = int(sender.item(sender.currentRow(), 1).text(), 16)
                fd = int(sender.item(sender.currentRow(), 3).text(), 16)

                graph = BinGraph(self.heap, info={
                    'type': 'tcache',
                    'bin_id': idx,
                    'size': size,
                })
                graph.Show()


    def show_bin_chain(self):
        sender = self.sender()
        stop = 0
        size = None

        row = sender.selectedItems()
        bin_cols = self.bin_tables[sender]
        address = int(row[bin_cols['address']].text(), 16)

        if bin_cols['size']:
            size = int(row[bin_cols['size']].text(), 16)

        if bin_cols['base']:
            stop = int(row[bin_cols['base']].text(), 16)

        self.show_chain(bin_cols['title'], address, size, stop)


    def show_selected_chunk(self):
        sender = self.sender()
        items = sender.selectedItems()
        col_id = self.bin_tables[sender]['address']
        address = int(items[col_id].text(), 16)
        self.parent.show_chunk_info(address)
      

    def table_on_change(self):
        self.show_selected_chunk()
        self.show_bin_chain()

    def show_chain(self, title, address, size, stop=0):
        if size:
            title = '%s[0x%02x]' % (title, size)

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

            if not fast_chunk:
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
        if fd == base:
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
            if smallbin['base'] == smallbin['fd']:
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
            if largebin['base'] == largebin['fd']:
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

            graph = BinGraph(self.heap, info={
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
            if entry['counts'] == 0:
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

        entry_addr = int(items[3].text(), 16)
        entry_size = int(items[1].text(), 16)
        self.show_chain(entry_addr, entry_size)


    def show_selected_chunk(self):
        items = self.sender().selectedItems()
        entry_addr = int(items[3].text(), 16)
        norm_address = "0x%x-0x%x" % (entry_addr, self.heap.ptr_size * 2)
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
            (chunk.size == next_chunk.prev_size)

        unlinkable_s = str(unlinkable)

        unlink_info = info_template % (unlinkable_s, unlinkable_s, p, chunk.size, next_chunk.prev_size, 
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

        top_size_ptr = arena.top + self.ptr_size
        top_size_val = self.heap.get_ptr(top_size_ptr)
        evil_size = target_addr - (self.ptr_size * 2) - top_size_ptr

        # unsigned
        if self.ptr_size == 4:
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
            # TODO: Refactor
            libc_base = get_libc_base()
            offset = int(sender.item(sender.currentRow(), 1).text(), 16)

            address = libc_base + offset
            idc.Jump(address)

    def tbl_offsets_double_clicked(self):
        sender = self.sender()

        # TODO: Refactor
        libc_base = get_libc_base()
        offset = int(sender.item(sender.currentRow(), 1).text(), 16)
        address = libc_base + offset
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
                'environ',
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
                'gets',
                'setcontext+0x35',
            ]
        }
        result = {
            'variables': OrderedDict(),
            'functions': OrderedDict(),

        }
        libc_base = get_libc_base()
        for s_type, symbols in libc_symbols.iteritems():
            for sym in symbols:
                addr = addr_by_name_expr(sym)
                if addr:
                    offset = addr - libc_base
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
        self.cb_magic.currentIndexChanged[int].connect(self.cb_magic_changed)

        self.stacked_magic = QtWidgets.QStackedWidget()

        self.unlink_widget = UnlinkWidget(self)
        self.fakefast_widget = FakefastWidget(self)
        self.house_of_force_widget = HouseOfForceWidget(self)
        self.libc_offsets_widget = LibcOffsetsWidget(self)

        self.stacked_magic.addWidget(self.unlink_widget)
        self.stacked_magic.addWidget(self.fakefast_widget)
        self.stacked_magic.addWidget(self.house_of_force_widget)
        self.stacked_magic.addWidget(self.libc_offsets_widget)

        hbox_magic = QHBoxLayout()
        hbox_magic.addWidget(QLabel('Select util'))
        hbox_magic.addWidget(self.cb_magic)
        hbox_magic.addStretch(1)

        self.vbox_magic = QVBoxLayout()
        self.vbox_magic.addLayout(hbox_magic)
        self.vbox_magic.addWidget(self.stacked_magic)
        self.vbox_magic.addStretch(1)

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
        hbox_update_config = QHBoxLayout()
        self.t_config = QtWidgets.QTextEdit()
        self.btn_update_config = QtWidgets.QPushButton("Update")
        self.btn_update_config.clicked.connect(self.update_config_on_click)
        self.t_config.setFixedHeight(400)

        hbox_update_config.addWidget(QLabel('Libc config (config.json)'))
        hbox_update_config.addWidget(self.btn_update_config)
        hbox_update_config.addStretch(1)

        vbox_config = QVBoxLayout()
        vbox_config.addLayout(hbox_update_config)
        vbox_config.addWidget(self.t_config)
        vbox_config.addStretch(1)

        self.setLayout(vbox_config)

    def load_config(self):
        try:
            self.t_config.setText(self.parent.config.dump_config())
        except:
            self.t_config.setText('')


    def update_config_on_click(self):
        try:
            config = json.loads(self.t_config.toPlainText())
            with open(self.parent.config_path, 'wb') as f:
                f.write(json.dumps(config, indent=4))
            info("Config updated.\nPlease, restart the plugin to apply the changes.")

        except Exception as e:
            warning("Error: %s" % traceback.format_exc())

# -----------------------------------------------------------------------


