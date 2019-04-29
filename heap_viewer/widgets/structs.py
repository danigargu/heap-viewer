#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idc

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from heap_viewer.widgets.custom import CustomWidget
from heap_viewer.misc import *
from heap_viewer import config
from heap_viewer import ptmalloc

# -----------------------------------------------------------------------
class StructView(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(StructView, self).__init__(parent)
        self.parent = parent
        self.address = None
        self.expand_arrays = False
        self._create_gui()

    def _create_gui(self):
        columns = ['offset','name','size','value']
        self.tree = QtWidgets.QTreeWidget()

        self.tree.setAttribute(Qt.WA_MacShowFocusRect, 0)
        self.tree.setColumnCount(len(columns))
        self.tree.setHeaderLabels(columns)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.context_menu)

        hbox = QtWidgets.QHBoxLayout()
        lbl_address = QtWidgets.QLabel("Address:")
        lbl_address.setStyleSheet("font-weight: bold;")
        hbox.addWidget(lbl_address)
        self.lbl_hex_addr = QtWidgets.QLabel()
        hbox.addWidget(self.lbl_hex_addr)
        hbox.addStretch(1)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(hbox)
        layout.addWidget(self.tree)

        #layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def load_struct(self, struct):        
        offsets = get_struct_offsets(struct)

        self.address = struct._addr
        self.lbl_hex_addr.setText("0x%X" % self.address)
        self.tree.clear()

        for name, ctype in struct._fields_:
            offset = offsets[name]
            value = getattr(struct, name)
            is_array = hasattr(value, "_length_")
            self.add_row(offset, name, sizeof(ctype), value, is_array)

        for i,width in enumerate([90, 130, 80, 120]):
            self.tree.setColumnWidth(i, width)
            #self.tree.resizeColumnToContents(i)

    def add_row(self, offset, name, size, value, is_array):
        parent = QtWidgets.QTreeWidgetItem(self.tree)
        parent.setText(0, "%d" % offset)
        parent.setText(1, "%s" % name)
        parent.setText(2, "%d" % size)

        if is_array:
            parent.setExpanded(self.expand_arrays)
            parent.setText(3, "Array [%d]" % len(value))
            size = sizeof(value._type_)
            for idx, val in enumerate(value):
                child = QtWidgets.QTreeWidgetItem(parent)
                child.setText(0, "%d" % (offset+(size*idx)))
                child.setText(1, "%s[%d]" % (name, idx))
                child.setText(2, "%d" % size)
                child.setText(3, "%#x" % val)
        else:
            parent.setText(3, "%#x" % value)

    def get_selected_item(self):
        items = self.tree.selectedItems()
        if len(items) > 0:
            return items[0]
        return None

    def context_menu(self, position):
        menu = QtWidgets.QMenu()
        jmp_offset = menu.addAction("Jump to offset")
        jmp_value = menu.addAction("Jump to value")
        action = menu.exec_(self.tree.mapToGlobal(position))

        if action == jmp_offset:
            self.jump_to_offset()
        elif action == jmp_value:
            self.jump_to_value()

    def jump_to_offset(self):
        item = self.get_selected_item()
        if item is not None:
            try:
                offset = int(item.text(0))
                address = self.address + offset
                idaapi.jumpto(address)
            except:
                pass

    def jump_to_value(self):
        item = self.get_selected_item()
        if item is not None:
            try:
                value = int(item.text(3), 16)
                if idaapi.is_loaded(value):
                    idaapi.jumpto(value)
            except:
                pass


# -----------------------------------------------------------------------
class StructsWidget(CustomWidget):
    def __init__(self, parent=None):
        super(StructsWidget, self).__init__(parent)
        self.parent = parent
        self._create_gui()

    def _create_gui(self):
        self.cb_struct = QtWidgets.QComboBox()
        self.cb_struct.setFixedWidth(150)
        self.cb_struct.addItem('malloc_state')
        self.cb_struct.addItem('malloc_par')
        self.cb_struct.addItem('tcache_perthread')
        self.cb_struct.currentIndexChanged[int].connect(self.cb_struct_changed)

        self.widgets = {
            'malloc_state': StructView(self),
            'malloc_par': StructView(self),
            'tcache_perthread': StructView(self)
        }

        self.stacked = QtWidgets.QStackedWidget()
        self.stacked.addWidget(self.widgets['malloc_state'])
        self.stacked.addWidget(self.widgets['malloc_par'])
        self.stacked.addWidget(self.widgets['tcache_perthread'])

        self.btn_load = QtWidgets.QPushButton("Load")
        self.btn_load.clicked.connect(self.btn_load_on_click)

        hbox_struct = QtWidgets.QHBoxLayout()
        hbox_struct.addWidget(QtWidgets.QLabel("Struct"))
        hbox_struct.addWidget(self.cb_struct)
        hbox_struct.addWidget(self.btn_load)
        hbox_struct.addStretch(1)
        
        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(hbox_struct)
        layout.addWidget(self.stacked)
        self.setLayout(layout)

    def load_malloc_state(self):
        widget = self.widgets['malloc_state']
        arena_struct = self.heap.get_arena(self.cur_arena)
        if arena_struct is not None:
            widget.load_struct(arena_struct)

    def load_malloc_par(self):
        widget = self.widgets['malloc_par']
        mp_ = ptmalloc.get_malloc_par_addr()
        if mp_ is None:
            idaapi.warning("Unable to resolve 'mp_' address.\nTry again when the heap is initialized")
        else:
            malloc_par_struct = ptmalloc.parse_malloc_par(mp_)
            widget.load_struct(malloc_par_struct)

    def load_tcache_perthread(self):
        widget = self.widgets['tcache_perthread']
        tcache_struct = self.heap.get_tcache_struct(self.cur_arena)

        if tcache_struct is None:
            idaapi.warning("Unable to resolve tcache address")
        else:
            widget.load_struct(tcache_struct)
            
    def btn_load_on_click(self):
        value = self.cb_struct.currentText()

        if value == 'malloc_state':
            self.load_malloc_state()
        elif value == 'malloc_par':
            self.load_malloc_par()
        elif value == 'tcache_perthread':
            self.load_tcache_perthread()

    def populate(self):
        self.load_malloc_state()

    def show_malloc_state(self):
        self.load_malloc_state()
        self.stacked.setCurrentIndex(0)

    def cb_struct_changed(self, idx):
        self.stacked.setCurrentIndex(idx)

# -----------------------------------------------------------------------

   