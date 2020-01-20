#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import re
import traceback

import idc
import idaapi

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from ctypes import *

from heap_viewer.widgets.custom import CustomWidget
from heap_viewer.ptmalloc import *
from heap_viewer import config

# -----------------------------------------------------------------------
class ChunkEditor(QtWidgets.QDialog):
    def __init__(self, addr, parent=None):
        super(ChunkEditor, self).__init__(parent)
        self.addr = addr
        self.parent = parent
        self.chunk = None
        self._create_gui()
        self._populate_gui()

    def _create_gui(self):
        self.setWindowTitle("Chunk editor")
        lbl = QtWidgets.QLabel("0x%X" % self.addr)
        lbl.setStyleSheet("font-weight: bold")

        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft|Qt.AlignVCenter)
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
        self.f_prev_inuse = QtWidgets.QCheckBox("prev_inuse")
        self.f_is_mmaped = QtWidgets.QCheckBox("is_mmapped")
        self.f_non_main_arena = QtWidgets.QCheckBox("non_main_arena")

        vbox_flags = QtWidgets.QVBoxLayout()
        vbox_flags.addWidget(self.f_prev_inuse)
        vbox_flags.addWidget(self.f_is_mmaped)
        vbox_flags.addWidget(self.f_non_main_arena)
        groupbox_flags.setLayout(vbox_flags)

        form.addRow("address", lbl)
        form.addRow(QtWidgets.QLabel())
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
        self.btn_save.setDefault(True)

        form.addRow(QtWidgets.QLabel())
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
            bk = eval(self.t_bk.text())
            fd_nextsize = eval(self.t_fd_nextsize.text())
            bk_nextsize = eval(self.t_bk_nextsize.text())

            self.chunk.size = size
            self.chunk.fd = fd
            self.chunk.bk = bk
            self.chunk.fd_nextsize = fd_nextsize
            self.chunk.bk_nextsize = bk_nextsize

            idaapi.patch_bytes(self.addr, self.chunk.data)
            idaapi.info("Chunk saved")
            self.done(1)

        except Exception as e:
            idaapi.warning("ERROR: " + str(e))


# -----------------------------------------------------------------------
class ChunkWidget(CustomWidget):
    def __init__(self, parent=None):
        super(ChunkWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self.setMinimumWidth(415)
        self.t_chunk_addr = QtWidgets.QLineEdit()
        self.t_chunk_addr.setFixedWidth(180)
        self.t_chunk_addr.returnPressed.connect(self.view_chunk_info)

        self.btn_view_chunk = QtWidgets.QPushButton("View")
        self.btn_view_chunk.clicked.connect(self.view_chunk_info)

        self.btn_jump_chunk = QtWidgets.QPushButton("Jump")
        self.btn_jump_chunk.clicked.connect(self.jump_on_click)

        self.btn_next_chunk = QtWidgets.QPushButton("Next")
        self.btn_next_chunk.clicked.connect(self.next_on_click)

        self.btn_prev_chunk = QtWidgets.QPushButton("Prev")
        self.btn_prev_chunk.clicked.connect(self.prev_on_click)

        self.btn_edit_chunk = QtWidgets.QPushButton("Edit")
        self.btn_edit_chunk.clicked.connect(self.edit_chunk_on_click)

        hbox_chunk_address = QtWidgets.QHBoxLayout()
        hbox_chunk_address.addWidget(QtWidgets.QLabel("Chunk address "))
        hbox_chunk_address.addWidget(self.t_chunk_addr)
        hbox_chunk_address.setContentsMargins(0, 0, 0, 0)
        hbox_chunk_address.setSpacing(0)
        hbox_chunk_address.addStretch(1)

        hbox_btns = QtWidgets.QHBoxLayout()
        hbox_btns.addWidget(self.btn_view_chunk)
        hbox_btns.addWidget(self.btn_jump_chunk)
        hbox_btns.addWidget(self.btn_next_chunk)
        hbox_btns.addWidget(self.btn_prev_chunk)
        hbox_btns.addWidget(self.btn_edit_chunk)
        hbox_btns.addStretch(1)

        self.te_chunk_info = QtWidgets.QTextEdit()
        self.te_chunk_info.setReadOnly(True)

        hbox = QtWidgets.QVBoxLayout()
        hbox.addLayout(hbox_chunk_address)
        hbox.addLayout(hbox_btns)
        hbox.addWidget(self.te_chunk_info)
        hbox.setSpacing(3)

        groupbox_arena_info = QtWidgets.QGroupBox("Chunk info")
        groupbox_arena_info.setLayout(hbox)

        hbox_actions = QtWidgets.QVBoxLayout()
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
                    <td>%#x</td>
                </tr>
            ''' % (offset, name, value)
            offset += sizeof(ctype)

        chunk_table += '<tr><td></td><td>norm_size</td><td>%#x</td></tr>' % (chunk.norm_size)

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
        line = ''
        data = bytearray(data)
        data_len = len(data)
        spaces = len(str(data_len))

        fmt_offset = "+%-{0}d | ".format(spaces)
        hexdump = '<code>'
        hexdump += fmt_offset % 0

        for i in range(len(data)):
            char = data[i]
            hexdump += "%02X " % char
            char = re.sub(r'[<>\'"]', '\x00', chr(char))
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


    def view_chunk_info(self):
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
            <p><b>[ %#x ]</b><br>
            <!-- Chunk fields -->
            %s
            <br>
            <p><b>[ hexdump ]</b></p>
            <p id="hexdump";>%s</p>
        '''

        chunk_addr = self.get_chunk_address()
        if chunk_addr is None:
            idaapi.warning("Invalid address / expression")
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

            if chunk_bytes > 0 and idaapi.is_loaded(chunk_addr + chunk_bytes):
                chunk_data = idaapi.get_bytes(chunk_addr, chunk_bytes)
            else:
                chunk_data = chunk.data

            if idaapi.is_loaded(chunk_addr + chunk.norm_size):
                in_use = self.heap.next_chunk(chunk_addr).prev_inuse

            chunk_table = self.html_chunk_table(chunk, in_use)
            if chunk_data:
                chunk_hexdump = self.html_chunk_hexdump(chunk_data, splitted)

            self.te_chunk_info.clear()
            chunk_info = chunk_template % (chunk_addr, chunk_table, chunk_hexdump)
            self.te_chunk_info.insertHtml(chunk_info)

        except Exception as e:
            idaapi.warning("ERROR: " + str(e))


    def show_chunk(self, expr):
        if type(expr) == str:
            self.t_chunk_addr.setText(expr)
        elif type(expr) == int or type(expr) == long:
            self.t_chunk_addr.setText("%#x" % expr)
        self.view_chunk_info()

    def get_chunk_address(self):
        addr_str = self.t_chunk_addr.text()
        if sys.version_info < (3, 0):
            addr_str = addr_str.encode("utf-8")
        addr = idaapi.str2ea(addr_str)

        if addr == idc.BADADDR:
            return None
        return addr

    def jump_on_click(self):
        chunk_addr = self.get_chunk_address()
        if chunk_addr is None:
            idaapi.warning("Invalid address / expression")
            return
        idc.jumpto(chunk_addr)

    def next_on_click(self):
        chunk_addr = self.get_chunk_address()
        if chunk_addr is None:
            idaapi.warning("Invalid address / expression")
            return
        try:
            chunk = self.heap.get_chunk(chunk_addr)
            chunk_size = chunk.norm_size
            next_addr = chunk_addr+chunk_size
            if idaapi.is_loaded(next_addr):
                self.show_chunk("%#x" % next_addr)
            else:
                idaapi.warning("%#x: next chunk (%#x) is not loaded" % \
                    (chunk_addr, next_addr))

        except Exception as e:
            idaapi.warning("ERROR: " + str(e))

    def prev_on_click(self):
        chunk_addr = self.get_chunk_address()
        if chunk_addr is None:
            idaapi.warning("Invalid address / expression")
            return
        try:
            chunk = self.heap.get_chunk(chunk_addr)
            if chunk.prev_inuse == 0:
                prev_addr = chunk_addr-chunk.prev_size
                self.show_chunk("%#x" % prev_addr)
            else:
                idaapi.warning("%#x: prev_chunk in use" % chunk_addr)
        except Exception as e:
            idaapi.warning("ERROR: " + str(e))

    def edit_chunk_on_click(self):
        chunk_addr = self.get_chunk_address()
        if chunk_addr is None:
            idaapi.warning("Invalid address / expression")
            return

        w = ChunkEditor(chunk_addr, self)
        if w.exec_() == 1:
            self.view_chunk_info()

# -----------------------------------------------------------------------