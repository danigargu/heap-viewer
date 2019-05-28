#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from collections import OrderedDict
from cgi import escape as html_encode

from heap_viewer.misc import *
from heap_viewer.widgets.custom import CustomWidget, TTable
from heap_viewer import io_file
from heap_viewer import config

# -----------------------------------------------------------------------
class MagicWidget(CustomWidget):
    def __init__(self, parent=None):
        super(MagicWidget, self).__init__(parent)
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

        hbox_magic = QtWidgets.QHBoxLayout()
        hbox_magic.addWidget(QtWidgets.QLabel('Select util'))
        hbox_magic.addWidget(self.cb_magic)
        hbox_magic.addStretch(1)

        self.vbox_magic = QtWidgets.QVBoxLayout()
        self.vbox_magic.addLayout(hbox_magic)
        self.vbox_magic.addWidget(self.stacked_magic)
        self.setLayout(self.vbox_magic)

    def populate_libc_offsets(self):
        self.libc_offsets_widget.populate_table()

    def cb_magic_changed(self, idx):
        self.stacked_magic.setCurrentIndex(idx)


# -----------------------------------------------------------------------
class UnlinkWidget(CustomWidget):
    def __init__(self, parent=None):
        super(UnlinkWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self.t_unlink_addr = QtWidgets.QLineEdit()
        self.t_unlink_addr.setFixedWidth(150)
        self.t_unlink_info = QtWidgets.QTextEdit()
        self.t_unlink_info.setFixedHeight(400)
        self.t_unlink_info.setReadOnly(True)

        self.btn_check_unlink = QtWidgets.QPushButton("Check")
        self.btn_check_unlink.clicked.connect(self.check_unlink_on_click)

        hbox_unlink = QtWidgets.QHBoxLayout()
        hbox_unlink.addWidget(QtWidgets.QLabel('Chunk ptr unlink'))
        hbox_unlink.addWidget(self.t_unlink_addr)
        hbox_unlink.addWidget(self.btn_check_unlink)
        hbox_unlink.addStretch(1)

        vbox_unlink = QtWidgets.QVBoxLayout()
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

        try:
            p = int(self.t_unlink_addr.text(), 16)

            chunk = self.heap.get_chunk(p)
            fd_chunk = self.heap.get_chunk(chunk.fd)
            bk_chunk = self.heap.get_chunk(chunk.bk)
            next_chunk = self.heap.next_chunk(p)

            fd_offset = self.heap.chunk_member_offset('fd')
            bk_offset = self.heap.chunk_member_offset('bk')

            """
            Unlink

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

        except Exception as e:
            idaapi.warning("ERROR: " + str(e))


# -----------------------------------------------------------------------
class HouseOfForceWidget(CustomWidget):
    def __init__(self, parent=None):
        super(HouseOfForceWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self.t_house_force_addr = QtWidgets.QLineEdit()
        self.t_house_force_addr.setFixedWidth(150)

        self.t_house_force_info = QtWidgets.QTextEdit()
        self.t_house_force_info.setReadOnly(True)

        self.btn_house_force = QtWidgets.QPushButton("Calc evil size")
        self.btn_house_force.clicked.connect(self.house_force_on_click)

        hbox_house_force = QtWidgets.QHBoxLayout()
        hbox_house_force.addWidget(QtWidgets.QLabel("Target address"))
        hbox_house_force.addWidget(self.t_house_force_addr)
        hbox_house_force.addWidget(self.btn_house_force)
        hbox_house_force.addStretch(1)

        vbox_house_force = QtWidgets.QVBoxLayout()
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
        evil_size_u = evil_size & config.ptr_mask

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
        super(LibcOffsetsWidget, self).__init__(parent)
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

        vbox_offsets_vars = QtWidgets.QVBoxLayout()
        vbox_offsets_vars.addWidget(QtWidgets.QLabel('Variables'))
        vbox_offsets_vars.addWidget(self.tbl_offsets_vars)

        vbox_offsets_funcs = QtWidgets.QVBoxLayout()
        vbox_offsets_funcs.addWidget(QtWidgets.QLabel('Functions'))
        vbox_offsets_funcs.addWidget(self.tbl_offsets_funcs)

        hbox_libc_offsets = QtWidgets.QHBoxLayout()
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
            self.tbl_offsets_vars.setItem(idx, 0, QtWidgets.QTableWidgetItem(name))
            self.tbl_offsets_vars.setItem(idx, 1, QtWidgets.QTableWidgetItem("0x%x" % offset))

        for idx, (name, offset) in enumerate(functions.iteritems()):
            self.tbl_offsets_funcs.insertRow(idx)
            self.tbl_offsets_funcs.setItem(idx, 0, QtWidgets.QTableWidgetItem(name))
            self.tbl_offsets_funcs.setItem(idx, 1, QtWidgets.QTableWidgetItem("0x%x" % offset))
        
        self.tbl_offsets_vars.resizeRowsToContents()
        self.tbl_offsets_funcs.resizeRowsToContents()

        self.tbl_offsets_vars.setSortingEnabled(True)
        self.tbl_offsets_funcs.setSortingEnabled(True)  


    def get_libc_offsets(self):        
        libc_symbols = {
            'variables': [
                'environ',
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
                '__libc_system',
                'execve',
                'open',
                '__open64',
                'read',
                'write',
                '__write',
                '_IO_gets',
                'gets',
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
            idaapi.warning("Unable to get glibc symbols")
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
        super(FakefastWidget, self).__init__(parent)
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

        hbox_fakefast = QtWidgets.QHBoxLayout()
        hbox_fakefast.addWidget(QtWidgets.QLabel('Target address'))
        hbox_fakefast.addWidget(self.t_fakefast_addr)
        hbox_fakefast.addWidget(self.btn_find_fakefast)
        hbox_fakefast.addStretch(1)

        vbox_fakefast = QtWidgets.QVBoxLayout()
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
            idaapi.info("Fakefast: 0 results")
            return

        self.tbl_fakefast.clearContents()
        self.tbl_fakefast.setRowCount(0)
        self.tbl_fakefast.setSortingEnabled(False)

        for idx, chunk in enumerate(fake_chunks):
            self.tbl_fakefast.insertRow(idx)
            self.tbl_fakefast.setItem(idx, 0, QtWidgets.QTableWidgetItem("%d" % chunk['fast_id']))
            self.tbl_fakefast.setItem(idx, 1, QtWidgets.QTableWidgetItem("0x%x" % chunk['size']))
            self.tbl_fakefast.setItem(idx, 2, QtWidgets.QTableWidgetItem("%d" % chunk['bytes_to']))
            self.tbl_fakefast.setItem(idx, 3, QtWidgets.QTableWidgetItem("0x%x" % chunk['address']))    

        self.tbl_fakefast.resizeRowsToContents()
        self.tbl_fakefast.resizeColumnsToContents()
        self.tbl_fakefast.setSortingEnabled(True)


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

        hbox_req2size = QtWidgets.QHBoxLayout()
        hbox_req2size.addWidget(QtWidgets.QLabel("Request size"))
        hbox_req2size.addWidget(self.t_req2size)
        hbox_req2size.addWidget(self.btn_req2size)
        hbox_req2size.addStretch(1)

        vbox_req2size = QtWidgets.QVBoxLayout()
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
        super(IOFileWidget, self).__init__(parent)
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

        hbox_io_struct = QtWidgets.QHBoxLayout()
        hbox_io_struct.addWidget(QtWidgets.QLabel('Struct:'))
        hbox_io_struct.addWidget(self.cb_struct)
        hbox_io_struct.addWidget(QtWidgets.QLabel('Address:'))
        hbox_io_struct.addWidget(self.t_struct_addr)
        hbox_io_struct.addWidget(self.btn_parse_struct)
        hbox_io_struct.addStretch(1)

        hbox_result = QtWidgets.QGridLayout()
        hbox_result = QtWidgets.QHBoxLayout()
        hbox_result.addWidget(self.t_io_file)
        hbox_result.addWidget(self.t_io_jump_t)

        vbox_req2size = QtWidgets.QVBoxLayout()
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
            idaapi.warning("ERROR: Invalid address")

    def html_struct_table(self, struct):
        offsets = get_struct_offsets(struct)
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
        io_file_struct = io_file.parse_structs(address)
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
        super(FreeableWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self.t_chunk_addr = QtWidgets.QLineEdit()
        self.t_chunk_addr.setFixedWidth(150)

        self.t_freeable_info = QtWidgets.QTextEdit()
        self.t_freeable_info.setFixedHeight(400)
        self.t_freeable_info.setReadOnly(True)

        self.btn_freeable = QtWidgets.QPushButton("Check")
        self.btn_freeable.clicked.connect(self.check_freeable)

        hbox_freeable = QtWidgets.QHBoxLayout()
        hbox_freeable.addWidget(QtWidgets.QLabel("Chunk address"))
        hbox_freeable.addWidget(self.t_chunk_addr)
        hbox_freeable.addWidget(self.btn_freeable)
        hbox_freeable.addStretch(1)

        vbox = QtWidgets.QVBoxLayout()
        vbox.addLayout(hbox_freeable)
        vbox.addWidget(self.t_freeable_info)
        vbox.addStretch(1)
        vbox.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vbox)

    def check_freeable(self):
        cur_arena = self.cur_arena
        chunk_addr = eval(self.t_chunk_addr.text())

        if self.heap is None:
            idaapi.warning("Heap not initialized")
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
                <li>
                    <span>0x%x: <b id="%s">%s</b></span><
                /li>
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
