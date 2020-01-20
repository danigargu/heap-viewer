#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import sys
import idc

from PyQt5 import QtGui, QtCore, QtWidgets

from heap_viewer.widgets.custom import CustomWidget, TTable
from heap_viewer.bingraph import BinGraph
from heap_viewer import config

# -----------------------------------------------------------------------
class BinsWidget(CustomWidget):
    def __init__(self, parent=None):
        super(BinsWidget, self).__init__(parent)
        self.show_bases = False
        self._create_gui()

    def _create_gui(self):
        self._create_tables()
        vbox_fastbins = QtWidgets.QVBoxLayout()
        vbox_fastbins.addWidget(QtWidgets.QLabel("Fastbins"))
        vbox_fastbins.addWidget(self.tbl_fastbins)

        vbox_unsortedbin = QtWidgets.QVBoxLayout()
        vbox_unsortedbin.addWidget(QtWidgets.QLabel("Unsorted"))
        vbox_unsortedbin.addWidget(self.tbl_unsortedbin)

        vbox_smallbins = QtWidgets.QVBoxLayout()
        vbox_smallbins.addWidget(QtWidgets.QLabel("Small bins"))
        vbox_smallbins.addWidget(self.tbl_smallbins)

        vbox_largebins = QtWidgets.QVBoxLayout()
        vbox_largebins.addWidget(QtWidgets.QLabel("Large bins"))
        vbox_largebins.addWidget(self.tbl_largebins)

        self.te_chain_info = QtWidgets.QTextEdit()
        self.te_chain_info.setReadOnly(True)

        vbox_chain = QtWidgets.QVBoxLayout()
        vbox_chain.addWidget(QtWidgets.QLabel("Chain info"))
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
        self.tbl_unsortedbin.itemClicked.connect(self.table_on_change)

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
            idc.jumpto(chunk_addr)

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

        if address != 0 and address != idc.BADADDR:
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
        for id_fast, (size, fast_chunk) in enumerate(fastbins.items()):

            if not self.show_bases and fast_chunk == 0:
                continue

            self.tbl_fastbins.insertRow(idx)

            it_bin_num  = QtWidgets.QTableWidgetItem("%d" % id_fast)
            it_size = QtWidgets.QTableWidgetItem("%#x" % size)
            it_fastchunk = QtWidgets.QTableWidgetItem("%#x" % fast_chunk)

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

        it_bin_num  = QtWidgets.QTableWidgetItem("1")
        it_fd = QtWidgets.QTableWidgetItem("%#x" % fd)
        it_bk = QtWidgets.QTableWidgetItem("%#x" % bk)
        it_base = QtWidgets.QTableWidgetItem("%#x" % base)

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
        for bin_id, smallbin in smallbins.items():

            # point to himself
            if not self.show_bases and smallbin['base'] == smallbin['fd']:
                continue

            self.tbl_smallbins.insertRow(idx)
            it_bin_num  = QtWidgets.QTableWidgetItem("%d" % bin_id)
            it_size = QtWidgets.QTableWidgetItem("%#x" % smallbin['size'])
            it_fd = QtWidgets.QTableWidgetItem("%#x" % smallbin['fd'])
            it_bk = QtWidgets.QTableWidgetItem("%#x" % smallbin['bk'])
            it_base = QtWidgets.QTableWidgetItem("%#x" % smallbin['base'])

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
        for bin_id, largebin in largebins.items():

            # point to himself
            if not self.show_bases and largebin['base'] == largebin['fd']:
                continue
  
            self.tbl_largebins.insertRow(idx)
            it_bin_num  = QtWidgets.QTableWidgetItem("%d" % bin_id)
            it_size = QtWidgets.QTableWidgetItem("%#x" % largebin['size'])
            it_fd = QtWidgets.QTableWidgetItem("%#x" % largebin['fd'])
            it_bk = QtWidgets.QTableWidgetItem("%#x" % largebin['bk'])
            it_base = QtWidgets.QTableWidgetItem("%#x" % largebin['base'])

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
        super(TcacheWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):
        self._create_table()   
      
        self.te_tcache_chain = QtWidgets.QTextEdit()
        self.te_tcache_chain.setFixedHeight(100)
        self.te_tcache_chain.setReadOnly(True)
        
        vbox_tcache_chain = QtWidgets.QVBoxLayout()
        vbox_tcache_chain.addWidget(QtWidgets.QLabel('Chain info'))
        vbox_tcache_chain.addWidget(self.te_tcache_chain)

        vbox_tcache = QtWidgets.QVBoxLayout()
        vbox_tcache.addWidget(QtWidgets.QLabel('Tcache entries'))
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
            idc.jumpto(fd_addr)

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
        for i, (size, entry) in enumerate(tcache.items()):

            if entry['counts'] == 0 and entry['next'] == 0:
                continue

            self.tbl_tcache.insertRow(idx)

            it_entry_id  = QtWidgets.QTableWidgetItem("%d" % i)
            it_size  = QtWidgets.QTableWidgetItem("%#x" % size)
            it_counts = QtWidgets.QTableWidgetItem("%d" % entry['counts'])
            it_address = QtWidgets.QTableWidgetItem("%#x" % entry['next'])

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


# -----------------------------------------------------------------------
def make_html_chain(name, chain, b_error):
    empty_bin = '<span style="color: red; font-weight: bold">Empty</span>'
    res_html = '<style>p{font-family:Consoles;font-size:13px}</style>'
    res_html += '<p><b>%s</b>: ' % name

    chain_len = len(chain)
    if chain_len == 0:
        res_html += empty_bin
        return res_html

    arrow_left = ''
    arrow_right = ''

    if sys.version_info >= (3, 0):
        arrow_left  = ' ← '
        arrow_right = ' → '
    else:
        arrow_left  = ' ← '.decode("utf-8")
        arrow_right = ' → '.decode("utf-8")

    for i in range(chain_len):
        res_html += "%#x" % chain[i]
        if i != chain_len-1:
            if i == chain_len-2:
                res_html += arrow_left
            else:
                res_html += arrow_right
    res_html += '</p>'

    return res_html

# -----------------------------------------------------------------------

