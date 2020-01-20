#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idc

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from heap_viewer.widgets.custom import CustomWidget, TTable, InfoDialog
from heap_viewer.misc import *
from heap_viewer import config
from heap_viewer import ptmalloc

# -----------------------------------------------------------------------
class ArenaWidget(CustomWidget):
    def __init__(self, parent=None):
        super(ArenaWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self._create_table()
        self._create_menu()

    def _create_menu(self):
        self.t_top_addr = QtWidgets.QLineEdit()
        self.t_top_addr.setFixedWidth(130)
        self.t_top_addr.setReadOnly(True)

        self.t_last_remainder = QtWidgets.QLineEdit()
        self.t_last_remainder.setFixedWidth(150)
        self.t_last_remainder.setReadOnly(True)

        self.lbl_top_warning = QtWidgets.QLabel()
        self.lbl_top_warning.setStyleSheet('color: red')
        self.lbl_top_warning.setVisible(False)

        self.t_attached_threads = QtWidgets.QLineEdit()
        self.t_attached_threads.setFixedWidth(130)
        self.t_attached_threads.setReadOnly(True)

        hbox_arena_top = QtWidgets.QHBoxLayout()
        hbox_arena_top.addWidget(QtWidgets.QLabel('Top:'))
        hbox_arena_top.addWidget(self.t_top_addr)
        hbox_arena_top.addWidget(QtWidgets.QLabel('Last remainder:'))
        hbox_arena_top.addWidget(self.t_last_remainder)

        btn_malloc_par = QtWidgets.QPushButton("Struct")
        btn_malloc_par.clicked.connect(self.btn_struct_on_click)
        hbox_arena_top.addWidget(btn_malloc_par)

        hbox_arena_top.addStretch(1)

        hbox_arena_others = QtWidgets.QHBoxLayout()
        hbox_arena_others.addWidget(self.lbl_top_warning)

        self.bold_font = QtGui.QFont()
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
        self.tbl_parsed_heap.itemSelectionChanged.connect(self.view_selected_chunk)

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
            idc.jumpto(chunk_addr)

        elif action == jump_to_u:
            idc.jumpto(chunk_addr + (config.ptr_size*2))

        elif action == view_chunk:
            self.view_selected_chunk()

        elif action == check_freaable:
            self.parent.check_freeable(chunk_addr)

    def view_selected_chunk(self):
        items = self.tbl_parsed_heap.selectedItems()
        if len(items) > 0:
            chunk_addr = int(items[0].text(), 16)
            self.parent.show_chunk_info(chunk_addr)

    def populate_table(self):
        cur_arena = self.cur_arena
        arena = self.heap.get_arena(cur_arena)
        self.t_top_addr.setText("%#x" % arena.top)
        self.t_last_remainder.setText("%#x" % arena.last_remainder)
        self.t_attached_threads.setText("%d" % arena.attached_threads)

        top_segname = idc.get_segm_name(arena.top)
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

            it_address = QtWidgets.QTableWidgetItem("%#x" % chunk['address'])
            it_prev = QtWidgets.QTableWidgetItem("%#x" % chunk['prev'])
            it_size = QtWidgets.QTableWidgetItem("%#x" % chunk['size'])
            it_status = QtWidgets.QTableWidgetItem("%s" % chunk['status'])
            it_fd = QtWidgets.QTableWidgetItem("%#x" % chunk['fd'])
            it_bk = QtWidgets.QTableWidgetItem("%#x" % chunk['bk'])

            if 'Freed' in chunk['status']:
                it_status.setForeground(QtGui.QColor('red'))
            elif chunk['status'] == 'Corrupt':
                it_status.setForeground(QtGui.QColor.fromRgb(213, 94, 0))
                it_status.setFont(self.bold_font)
            else:
                it_status.setForeground(QtGui.QColor('blue'))

            self.tbl_parsed_heap.setItem(idx, 0, it_address)
            self.tbl_parsed_heap.setItem(idx, 1, it_prev)
            self.tbl_parsed_heap.setItem(idx, 2, it_size)
            self.tbl_parsed_heap.setItem(idx, 3, it_status)
            self.tbl_parsed_heap.setItem(idx, 4, it_fd)
            self.tbl_parsed_heap.setItem(idx, 5, it_bk)

        self.tbl_parsed_heap.resizeRowsToContents()
        self.tbl_parsed_heap.resizeColumnsToContents()
        self.tbl_parsed_heap.setSortingEnabled(True)
        self.tbl_parsed_heap.sortByColumn(0, QtCore.Qt.DescendingOrder)

    def btn_struct_on_click(self):
        self.parent.show_malloc_state()


# -----------------------------------------------------------------------

