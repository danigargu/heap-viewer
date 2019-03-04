#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import traceback

from idc import *
from idautils import *
from idaapi import *

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtWidgets import QWidget, QSplitter, QTabWidget, QPushButton, QComboBox
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel

from heap_viewer.misc import *
from heap_viewer.ui_widgets import *
from heap_viewer.ptmalloc import Heap
from heap_viewer import CONFIG_PATH, ICONS_DIR, PLUGNAME

# -----------------------------------------------------------------------
class HeapPluginForm(PluginForm):
    def __init__(self):
        super(HeapPluginForm, self).__init__()
        self.parent      = None
        self.config_path = None
        self.config      = None
        self.tracer      = None
        self.heap        = None
        self.cur_arena   = None # default: main_arena
        self.ptr_size    = get_arch_ptrsize()

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)     
        self.setup_gui()
        self.init_heap()
        self.populate_gui()

    def setup_gui(self):
        self.chunk_widget = ChunkWidget(self)
        self.tracer_tab = TracerWidget(self)
        self.arena_widget = ArenaWidget(self)
        self.bins_widget = BinsWidget(self)
        self.tcache_widget = TcacheWidget(self)
        self.magic_widget = MagicWidget(self)
        self.config_widget = ConfigWidget(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.tracer_tab, "Tracer")
        self.tabs.addTab(self.arena_widget, "Arena")
        self.tabs.addTab(self.bins_widget, "Bins")
        self.tabs.addTab(self.tcache_widget, "Tcache")
        self.tabs.addTab(self.magic_widget, "Magic")
        self.tabs.addTab(self.config_widget, "Config")

        self.btn_reload = QPushButton("Reload info")
        icon = QtGui.QIcon(os.path.normpath(ICONS_DIR + '/refresh.png'))
        self.btn_reload.setIcon(icon)
        self.btn_reload.setFixedWidth(120)
        self.btn_reload.setEnabled(False)
        self.btn_reload.clicked.connect(self.reload_gui_info)

        self.cb_arenas = QComboBox()
        self.cb_arenas.setFixedWidth(150)
        self.cb_arenas.currentIndexChanged[int].connect(self.cb_arenas_changed)

        hbox_arenas = QHBoxLayout()        
        hbox_arenas.addWidget(QLabel('Switch arena: '))
        hbox_arenas.addWidget(self.cb_arenas)
        hbox_arenas.setContentsMargins(0, 0, 0, 0)

        self.arenas_widget = QWidget()
        self.arenas_widget.setLayout(hbox_arenas)
        self.arenas_widget.setVisible(False)

        self.txt_warning = QLabel()
        self.txt_warning.setStyleSheet("font-weight: bold; color: red")
        self.txt_warning.setVisible(False)

        hbox_top = QHBoxLayout()
        hbox_top.addWidget(self.btn_reload)
        hbox_top.addWidget(self.arenas_widget)
        hbox_top.addWidget(self.txt_warning)
        hbox_top.setContentsMargins(0, 0, 0, 0)
        hbox_top.addStretch(1)

        vbox_left_panel = QVBoxLayout()        
        vbox_left_panel.addLayout(hbox_top)
        vbox_left_panel.addWidget(self.tabs)
        vbox_left_panel.setContentsMargins(0, 0, 0, 0)

        left_panel = QWidget()
        left_panel.setLayout(vbox_left_panel)

        self.splitter = QSplitter(QtCore.Qt.Horizontal)
        self.splitter.addWidget(left_panel)
        self.splitter.addWidget(self.chunk_widget)
        self.splitter.setStretchFactor(0, 1)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.splitter)
        self.parent.setLayout(main_layout)

    def populate_gui(self):
        self.magic_widget.populate_libc_offsets()
        self.reload_gui_info()

    def reload_gui_info(self, from_arena_cb=False):
        if self.heap is None:
            return

        if not is_process_suspended():
            answer = askyn_c(
                ASKBTN_YES, 
                "HIDECANCEL\nThe process must be suspended to reload the info.\n\
                Do you want to suspend it?")

            if answer == ASKBTN_NO:
                return

            if not suspend_process():
                warning("Unable to suspend the process")
                return
        try:
            RefreshDebuggerMemory()
            if not self.heap.get_heap_base():
                self.show_warning("Heap not initialized")
                return

            if not get_libc_base():
                self.show_warning("Unable to resolve glibc base address.")
                return

            self.hide_warning()
            self.arenas_widget.setVisible(True)

            if not from_arena_cb:
                self.populate_arenas()

            self.arena_widget.populate_table()
            self.tcache_widget.populate_table()
            self.bins_widget.populate_tables()

        except Exception as e:
            self.show_warning(e.message)
            warning(traceback.format_exc())

    def init_heap(self):
        try:            
            self.config_path = CONFIG_PATH
            self.config = HeapConfig(self.config_path)
            self.config_widget.load_config()

        except Exception as e:
            self.config = None
            self.show_warning('Please, update the config file')
            warning(str(e))
            return

        if not self.config.offsets:
            arch_bits = self.ptr_size * 8
            self.show_warning('Config: Libc offsets for %d bits not found.' % arch_bits)
            return

        try:
            current_libc_version = get_libc_version()
            if self.config.libc_version == current_libc_version or current_libc_version == None:
                self.heap = Heap(self.config)
                self.btn_reload.setEnabled(True)
                self.tabs.setTabEnabled(3, self.heap.tcache_enabled)
            else:
                self.show_warning('Config: glibc version mismatched: %s != %s' % \
                    (str(self.config.libc_version), str(current_libc_version)))

        except AttributeError as e:
            warning(str(e))
            self.show_warning('Invalid config file content')
         

    def populate_arenas(self):
        old_arena = self.cur_arena
        self.cb_arenas.blockSignals(True)
        self.cb_arenas.clear()

        for addr, arena in self.heap.arenas():
            if addr == self.heap.main_arena_addr:
                self.cb_arenas.addItem("main_arena", None)
                self.cb_arenas.addItem("main_arena2", 1)
            else:
                self.cb_arenas.addItem("0x%x" % addr, addr)

        idx = self.cb_arenas.findData(old_arena)
        if idx != -1:
            self.cb_arenas.setCurrentIndex(idx)
        self.cb_arenas.blockSignals(False)

    def show_warning(self, txt):
        self.txt_warning.setText(txt)
        self.txt_warning.setVisible(True)

    def hide_warning(self):
        self.txt_warning.setVisible(False)

    def cb_arenas_changed(self, idx):
        self.cur_arena = self.cb_arenas.itemData(idx)
        self.reload_gui_info(True)

    def show_chunk_info(self, address):
        self.chunk_widget.show_chunk(address)

    def Show(self):
        return PluginForm.Show(self, PLUGNAME, options = (
            PluginForm.FORM_TAB | PluginForm.FORM_CLOSE_LATER
        ))
    
    def OnClose(self, form):
        if self.tracer:
            self.tracer.unhook()
            log("Tracer disabled")
        log("Form closed")

# --------------------------------------------------------------------------

