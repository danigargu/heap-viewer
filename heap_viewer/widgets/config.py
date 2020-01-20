#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

from heap_viewer.widgets.custom import CustomWidget, TTable
from heap_viewer import config
from heap_viewer import misc

# -----------------------------------------------------------------------
class ConfigWidget(CustomWidget):
    def __init__(self, parent=None):
        super(ConfigWidget, self).__init__(parent)
        self._create_gui()

    def _create_gui(self):        
        self.t_config = QtWidgets.QTextEdit()
        self.t_config.setFixedHeight(440)

        self.btn_update_config = QtWidgets.QPushButton("Update")
        self.btn_dump_config = QtWidgets.QPushButton("Dump json")

        self.btn_update_config.clicked.connect(self.update_config)
        self.btn_dump_config.clicked.connect(self.dump_config)

        hbox_update_config = QtWidgets.QHBoxLayout()        
        hbox_update_config.addWidget(QtWidgets.QLabel("Config file (config.json)"))
        hbox_update_config.addWidget(self.btn_update_config)
        hbox_update_config.addWidget(self.btn_dump_config)
        hbox_update_config.addStretch(1)

        groupbox_tracer = QtWidgets.QGroupBox("Tracer options")
        self.opt1 = QtWidgets.QCheckBox("Start tracing at startup")
        self.opt2 = QtWidgets.QCheckBox("Stop during tracing")
        self.opt3 = QtWidgets.QCheckBox("Detect double frees and chunk overlaps")
        self.opt4 = QtWidgets.QCheckBox("Filter library calls")

        vbox_tracer = QtWidgets.QVBoxLayout()
        vbox_tracer.addWidget(self.opt1)
        vbox_tracer.addWidget(self.opt2)
        vbox_tracer.addWidget(self.opt3)
        vbox_tracer.addWidget(self.opt4)
        groupbox_tracer.setLayout(vbox_tracer)

        vbox_options = QtWidgets.QVBoxLayout()
        vbox_options.addWidget(QtWidgets.QTextEdit("Hexdump limit"))

        hbox_hex_limit = QtWidgets.QHBoxLayout()
        self.t_hexdump_limit = QtWidgets.QLineEdit()
        self.t_hexdump_limit.setFixedWidth(180)
        hbox_hex_limit.addWidget(QtWidgets.QLabel("Hexdump limit (bytes)"))
        hbox_hex_limit.addWidget(self.t_hexdump_limit)
        hbox_hex_limit.addStretch(1)

        form_offsets = QtWidgets.QFormLayout()
        form_offsets.setSpacing(5)
        form_offsets.setLabelAlignment(Qt.AlignLeft|Qt.AlignVCenter)

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

        hbox_groupboxs = QtWidgets.QHBoxLayout()
        hbox_groupboxs.addWidget(groupbox_tracer)
        hbox_groupboxs.addWidget(groupbox_offsets)
        hbox_groupboxs.addStretch(1)

        vbox = QtWidgets.QVBoxLayout()
        vbox.addLayout(hbox_update_config)
        vbox.addLayout(hbox_groupboxs)
        vbox.addLayout(hbox_hex_limit)
        vbox.addStretch(1)
        self.setLayout(vbox)

    def get_offsets(self):
        offsets = {}
        for name, widget in self.offset_widgets.items():
            try:
                offset_str = widget.text()
                if offset_str.startswith("0x"):
                    value = int(offset_str, 16)
                else:
                    value = int(offset_str)
                offsets[name] = value
            except:
                pass
        print("Offsets: "+str(offsets))
        return offsets

    def load_config(self):
        self.opt1.setChecked(config.start_tracing_at_startup)
        self.opt2.setChecked(config.stop_during_tracing)
        self.opt3.setChecked(config.detect_double_frees_and_overlaps)
        self.opt4.setChecked(config.filter_library_calls)
        self.t_hexdump_limit.setText("%d" % config.hexdump_limit)

        if type(config.libc_offsets) is dict:
            for name, widget in self.offset_widgets.items():
                value = config.libc_offsets.get(name)
                if value is not None:
                    widget.setText("%d" % value)

    def update_config(self):
        try:
            config.start_tracing_at_startup = self.opt1.isChecked()
            config.stop_during_tracing = self.opt2.isChecked()
            config.detect_double_frees_and_overlaps = self.opt3.isChecked()
            config.filter_library_calls = self.opt4.isChecked()
            config.hexdump_limit = int(self.t_hexdump_limit.text())
            config.libc_offsets = self.get_offsets()

            config.save()
            idaapi.info("Config updated")

            self.parent.init_heap()
            self.parent.reload_gui_info()

        except Exception as e:
            idaapi.warning("ERROR: " + str(e))

    def dump_config(self):
        idaapi.info(config.dump())

# -----------------------------------------------------------------------
