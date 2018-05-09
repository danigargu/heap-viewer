#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi
import os
import sys

PLUGIN_DIR = idaapi.idadir(os.path.join("plugins", "heap_viewer"))
sys.path.append(PLUGIN_DIR)

# ----- Only for develop / reload modules -------------------------------

idaapi.require('ptmalloc')
idaapi.require('plugin_gui')
idaapi.require('tracer')
idaapi.require('misc')
idaapi.require('bingraph')

#------------------------------------------------------------------------

from plugin_gui import HeapPluginForm, PLUGNAME

# -----------------------------------------------------------------------
class HeapViewPlugin(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = PLUGNAME
    wanted_hotkey = "Ctrl-H"

    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        try:
            if "ELF" not in idaapi.get_file_type_name():
                raise Exception("Executable must be ELF fomat")

            if not idaapi.is_debugger_on() or not idaapi.dbg_can_query():
                raise Exception("The debugger must be active and suspended before using this plugin")

            f = HeapPluginForm()
            f.Show()

        except Exception as e:
            idaapi.warning("[%s] %s" % (PLUGNAME, e.message))

    def term(self):
        idaapi.msg("[%s] terminated" % (PLUGNAME))

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return HeapViewPlugin()


